"""CA operations: root lifecycle + certificate issue/revoke.

Uses `openssl` under the hood for key generation and signing, and keeps the
PKI state (private keys encrypted on disk, metadata in index.json).
"""
from __future__ import annotations

import os
import secrets
import subprocess
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .cfssl_client import Storage, storage
from .config import settings


def _run(args: list[str], stdin: str | None = None) -> str:
    p = subprocess.run(
        ["openssl", *args],
        input=stdin.encode() if stdin else None,
        capture_output=True,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode() or "openssl failed")
    return p.stdout.decode()


def _root_dir(root_id: str) -> str:
    d = os.path.join(settings.ca_data_dir, "roots", root_id)
    os.makedirs(d, exist_ok=True)
    return d


def _passfile() -> str:
    fd, path = tempfile.mkstemp()
    with os.fdopen(fd, "w") as f:
        f.write(settings.ca_key_passphrase)
    return path


# --- Root lifecycle -------------------------------------------------------

def create_root(name: str, org: str, days: int = 3650,
                key_type: str = "rsa", key_size: int = 4096,
                created_by: str = "") -> dict[str, Any]:
    root_id = uuid.uuid4().hex[:12]
    d = _root_dir(root_id)
    key_path = os.path.join(d, "ca-key.pem")
    cert_path = os.path.join(d, "ca.pem")
    passfile = _passfile()

    alg = ["genrsa", "-aes256", "-passout", f"file:{passfile}", "-out", key_path,
           str(key_size)] if key_type == "rsa" else \
          ["ecparam", "-genkey", "-name", "prime256v1", "-out", key_path]

    _run(alg)

    subj = f"/CN={name}/O={org}"
    _run(["req", "-new", "-x509", "-key", key_path,
          "-passin", f"file:{passfile}",
          "-out", cert_path, "-days", str(days), "-sha384",
          "-subj", subj,
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    os.unlink(passfile)

    serial = _serial_of(cert_path)
    root = {
        "id": root_id,
        "name": name,
        "org": org,
        "serial": serial,
        "not_after": _not_after(cert_path),
        "status": "active",
        "key_type": key_type,
        "key_size": key_size,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    storage.add_root(root)
    storage.log_audit({"action": "root_created", "root_id": root_id, "name": name,
                       "by": created_by})
    return root


def list_roots() -> list[dict[str, Any]]:
    return storage.list_roots()


def root_cert(root_id: str) -> str:
    path = os.path.join(_root_dir(root_id), "ca.pem")
    with open(path) as f:
        return f.read()


def renew_root(root_id: str, days: int = 3650) -> dict[str, Any]:
    """Rotate: issue a new self-signed cert for the existing root key."""
    d = _root_dir(root_id)
    cert_path = os.path.join(d, "ca.pem")
    roots = storage.list_roots()
    current = next(r for r in roots if r["id"] == root_id)
    passfile = _passfile()
    _run(["req", "-new", "-x509", "-key", os.path.join(d, "ca-key.pem"),
          "-passin", f"file:{passfile}",
          "-out", cert_path, "-days", str(days), "-sha384",
          "-subj", f"/CN={current['name']}/O={current['org']}",
          "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    os.unlink(passfile)
    storage.update_root(root_id, {"not_after": _not_after(cert_path)})
    storage.log_audit({"action": "root_renewed", "root_id": root_id})
    return current


def revoke_root(root_id: str, reason: str = "unspecified") -> dict[str, Any]:
    storage.update_root(root_id, {"status": "revoked", "revoked_reason": reason})
    storage.log_audit({"action": "root_revoked", "root_id": root_id, "reason": reason})
    return {"status": "revoked"}


# --- Certificate issue / revoke ------------------------------------------

def issue_cert(root_id: str, cn: str, sans: list[str], cert_type: str = "server",
               days: int = 365, created_by: str = "") -> dict[str, Any]:
    """Issue a server or client certificate signed by the given root."""
    d = _root_dir(root_id)
    serial_hex = secrets.token_hex(16)
    cert_dir = os.path.join(settings.ca_data_dir, "certs", serial_hex)
    os.makedirs(cert_dir, exist_ok=True)

    key_path = os.path.join(cert_dir, "key.pem")
    csr_path = os.path.join(cert_dir, "req.csr")
    cert_path = os.path.join(cert_dir, "cert.pem")

    _run(["genrsa", "-out", key_path, "2048"])

    san_entries = ",".join(
        [f"DNS:{s}" if not _is_ip(s) else f"IP:{s}" for s in sans]
    )
    ext = ["basicConstraints=critical,CA:FALSE"]
    if cert_type == "server":
        ext += ["keyUsage=critical,digitalSignature,keyEncipherment",
                f"extendedKeyUsage=serverAuth",
                f"subjectAltName={san_entries}"]
    else:
        ext += ["keyUsage=critical,digitalSignature",
                "extendedKeyUsage=clientAuth"]
        if sans:
            ext += [f"subjectAltName={san_entries}"]

    _run(["req", "-new", "-key", key_path, "-out", csr_path, "-subj", f"/CN={cn}"])

    extfile = os.path.join(cert_dir, "ext.cnf")
    with open(extfile, "w") as f:
        f.write("\n".join(ext) + "\n")

    passfile = _passfile()
    _run(["x509", "-req", "-in", csr_path,
          "-CA", os.path.join(d, "ca.pem"),
          "-CAkey", os.path.join(d, "ca-key.pem"),
          "-passin", f"file:{passfile}",
          "-out", cert_path, "-days", str(days), "-sha384",
          "-CAcreateserial", "-extfile", extfile])
    os.unlink(passfile)

    rec = {
        "serial": serial_hex,
        "cn": cn,
        "sans": sans,
        "cert_type": cert_type,
        "root_id": root_id,
        "not_before": _not_before(cert_path),
        "not_after": _not_after(cert_path),
        "status": "active",
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    storage.add_cert(rec)
    storage.log_audit({"action": "cert_issued", "cn": cn, "cert_type": cert_type,
                       "serial": serial_hex, "root_id": root_id, "by": created_by})
    return rec


def revoke_cert(serial: str, reason: str = "unspecified") -> dict[str, Any]:
    storage.update_cert(serial, {
        "status": "revoked",
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "revoked_reason": reason,
    })
    storage.log_audit({"action": "cert_revoked", "serial": serial, "reason": reason})
    return {"status": "revoked"}


def list_certs() -> list[dict[str, Any]]:
    return storage.list_certs()


def get_cert_pem(serial: str) -> str:
    path = os.path.join(settings.ca_data_dir, "certs", serial, "cert.pem")
    with open(path) as f:
        return f.read()


def get_cert_key_pem(serial: str) -> str:
    path = os.path.join(settings.ca_data_dir, "certs", serial, "key.pem")
    with open(path) as f:
        return f.read()


def get_pkcs12(serial: str, cn: str) -> bytes:
    """Build PKCS#12 bundle (encrypted with the CA key passphrase)."""
    d = os.path.join(settings.ca_data_dir, "certs", serial)
    passfile = _passfile()
    p12_path = os.path.join(d, "bundle.p12")
    _run(["pkcs12", "-export",
          "-in", os.path.join(d, "cert.pem"),
          "-inkey", os.path.join(d, "key.pem"),
          "-out", p12_path,
          "-name", cn,
          "-passout", f"file:{passfile}"])
    os.unlink(passfile)
    with open(p12_path, "rb") as f:
        return f.read()


# --- helpers --------------------------------------------------------------

def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _serial_of(cert_path: str) -> str:
    out = _run(["x509", "-in", cert_path, "-noout", "-serial"])
    return out.strip().split("=")[1]


def _not_after(cert_path: str) -> str:
    out = _run(["x509", "-in", cert_path, "-noout", "-enddate"])
    return out.strip().split("=", 1)[1]


def _not_before(cert_path: str) -> str:
    out = _run(["x509", "-in", cert_path, "-noout", "-startdate"])
    return out.strip().split("=", 1)[1]
