"""SSH-CA: sign OpenSSH user/host certificates.

Uses ``ssh-keygen`` under the hood. This is a *separate* PKI from the X.509
roots in ``ca_ops.py`` — OpenSSH uses its own certificate format, not X.509.
"""
from __future__ import annotations

import os
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Any

from .cfssl_client import storage
from .config import settings


def _run(args: list[str], stdin: str | None = None) -> str:
    p = subprocess.run(
        ["ssh-keygen", *args],
        input=stdin.encode() if stdin else None,
        capture_output=True,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode() or "ssh-keygen failed")
    return p.stdout.decode()


def _ssh_root_dir(root_id: str) -> str:
    d = os.path.join(settings.ca_data_dir, "ssh-ca", root_id)
    os.makedirs(d, exist_ok=True)
    return d


def _ssh_cert_dir(serial: str) -> str:
    d = os.path.join(settings.ca_data_dir, "ssh-certs", serial)
    os.makedirs(d, exist_ok=True)
    return d


# --- SSH-CA root lifecycle ------------------------------------------------

def create_ssh_root(name: str, key_type: str = "ed25519",
                    validity: str = "+3650d", created_by: str = "") -> dict[str, Any]:
    """Create a new SSH CA (signing key). Supports ed25519 / rsa / ecdsa."""
    root_id = uuid.uuid4().hex[:12]
    d = _ssh_root_dir(root_id)
    ca_key = os.path.join(d, "ca_key")
    ca_pub = ca_key + ".pub"

    if key_type == "ed25519":
        _run(["-t", "ed25519", "-f", ca_key, "-N", "", "-C", f"ssh-ca:{name}"])
    elif key_type == "ecdsa":
        _run(["-t", "ecdsa", "-b", "256", "-f", ca_key, "-N", "", "-C", f"ssh-ca:{name}"])
    else:  # rsa
        _run(["-t", "rsa", "-b", "4096", "-f", ca_key, "-N", "", "-C", f"ssh-ca:{name}"])

    with open(ca_pub) as f:
        pub = f.read().strip()

    rec = {
        "id": root_id,
        "name": name,
        "key_type": key_type,
        "public_key": pub,
        "validity": validity,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }
    data = storage._load()
    data.setdefault("ssh_ca", []).append(rec)
    storage._save(data)
    storage.log_audit({"action": "ssh_ca_created", "root_id": root_id,
                       "name": name, "by": created_by})
    return rec


def list_ssh_roots() -> list[dict[str, Any]]:
    return storage._load().get("ssh_ca", [])


def ssh_ca_public(root_id: str) -> str:
    path = os.path.join(_ssh_root_dir(root_id), "ca_key.pub")
    with open(path) as f:
        return f.read()


# --- Sign user / host keys ------------------------------------------------

def sign_ssh_cert(root_id: str, public_key: str, principals: list[str],
                  cert_type: str = "user", validity: str = "+8h",
                  serial: str = "", created_by: str = "") -> dict[str, Any]:
    """Sign a public key as an OpenSSH user or host certificate.

    ``public_key`` must be a single OpenSSH-format public key line
    (e.g. contents of id_ed25519.pub).
    """
    if not serial:
        serial = uuid.uuid4().hex[:16]

    ca_key = os.path.join(_ssh_root_dir(root_id), "ca_key")
    key_file = os.path.join(_ssh_cert_dir(serial), "key.pub")
    with open(key_file, "w") as f:
        f.write(public_key.strip() + "\n")

    args = ["-s", ca_key, "-I", serial, "-n", ",".join(principals),
            "-V", validity, "-z", "0"]
    if cert_type == "host":
        args.append("-h")
    args.append(key_file)

    _run(args)

    cert_file = key_file.replace(".pub", "-cert.pub")
    with open(cert_file) as f:
        signed = f.read()

    rec = {
        "serial": serial,
        "root_id": root_id,
        "cert_type": cert_type,  # "user" | "host"
        "principals": principals,
        "validity": validity,
        "public_key": public_key.strip(),
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }
    data = storage._load()
    data.setdefault("ssh_certs", []).append(rec)
    storage._save(data)
    storage.log_audit({"action": "ssh_cert_signed", "serial": serial,
                       "root_id": root_id, "cert_type": cert_type,
                       "principals": principals, "by": created_by})
    return rec


def list_ssh_certs() -> list[dict[str, Any]]:
    return storage._load().get("ssh_certs", [])


def ssh_cert_public(serial: str) -> str:
    path = os.path.join(_ssh_cert_dir(serial), "key-cert.pub")
    with open(path) as f:
        return f.read()


def revoke_ssh_cert(serial: str, reason: str = "unspecified") -> dict[str, Any]:
    data = storage._load()
    for c in data.get("ssh_certs", []):
        if c["serial"] == serial:
            c["status"] = "revoked"
            c["revoked_reason"] = reason
            c["revoked_at"] = datetime.now(timezone.utc).isoformat()
    storage._save(data)
    storage.log_audit({"action": "ssh_cert_revoked", "serial": serial, "reason": reason})
    return {"status": "revoked"}
