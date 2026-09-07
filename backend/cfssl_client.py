"""CFSSL multirootca client wrapper.

Wraps the CFSSL HTTP API (certinfo / newcert / revoke) and adds a thin
local metadata layer on top of the on-disk PKI state.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from .config import settings


@dataclass
class CertRecord:
    serial: str
    cn: str
    sans: list[str] = field(default_factory=list)
    cert_type: str = "server"  # "server" | "client"
    root_id: str = ""
    not_before: str = ""
    not_after: str = ""
    status: str = "active"  # active | revoked | expired
    revoked_at: Optional[str] = None
    revoked_reason: str = ""


class CFSSLClient:
    """Talks to the CFSSL `serve` HTTP endpoint."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def info(self, cert_pem: str) -> dict[str, Any]:
        """Return parsed info for a certificate (certinfo endpoint)."""
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(f"{self.base_url}/api/v1/cfssl/info",
                                  json={"certificate": cert_pem})
            r.raise_for_status()
            return r.json()["result"]

    @staticmethod
    def _openssl(args: list[str], data: Optional[str] = None) -> str:
        p = subprocess.run(
            ["openssl", *args],
            input=data.encode() if data else None,
            capture_output=True,
            check=False,
        )
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode() or "openssl failed")
        return p.stdout.decode()

    def parse_cert(self, cert_pem: str) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(cert_pem)
            path = f.name
        try:
            out = self._openssl([
                "x509", "-in", path, "-noout",
                "-serial", "-subject", "-ext", "subjectAltName",
                "-startdate", "-enddate", "-text",
            ])
            return {"text": out}
        finally:
            os.unlink(path)


class Storage:
    """Local metadata index on the PKI volume."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.index_path = os.path.join(data_dir, "index.json")
        os.makedirs(data_dir, exist_ok=True)

    def _load(self) -> dict[str, Any]:
        if not os.path.exists(self.index_path):
            return {"roots": [], "certs": []}
        with open(self.index_path) as f:
            return json.load(f)

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.index_path)

    def list_roots(self) -> list[dict[str, Any]]:
        return self._load()["roots"]

    def add_root(self, root: dict[str, Any]) -> None:
        data = self._load()
        data["roots"].append(root)
        self._save(data)

    def update_root(self, root_id: str, patch: dict[str, Any]) -> None:
        data = self._load()
        for r in data["roots"]:
            if r["id"] == root_id:
                r.update(patch)
        self._save(data)

    def list_certs(self) -> list[dict[str, Any]]:
        return self._load()["certs"]

    def add_cert(self, cert: dict[str, Any]) -> None:
        data = self._load()
        data["certs"].append(cert)
        self._save(data)

    def update_cert(self, serial: str, patch: dict[str, Any]) -> None:
        data = self._load()
        for c in data["certs"]:
            if c["serial"] == serial:
                c.update(patch)
        self._save(data)

    def log_audit(self, entry: dict[str, Any]) -> None:
        path = os.path.join(self.data_dir, "audit.log")
        line = json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            **entry,
        })
        with open(path, "a") as f:
            f.write(line + "\n")


storage = Storage(settings.ca_data_dir)
cfssl = CFSSLClient(settings.cfssl_url)
