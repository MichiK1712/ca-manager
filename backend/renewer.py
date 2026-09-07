"""Renewal scheduler: warn before expiry and optionally auto-renew."""
from __future__ import annotations

import time
from datetime import datetime, timedelta

from .ca_ops import list_certs, revoke_cert, issue_cert
from .config import settings
from .mailer import expiry_warning


def _days_left(not_after: str) -> int:
    try:
        # openssl format: "Sep  7 10:00:00 2026 GMT"
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return 9999
    return (dt - datetime.now()).days


def run_once() -> None:
    warned = set()
    for cert in list_certs():
        if cert["status"] != "active":
            continue
        dl = _days_left(cert["not_after"])
        if dl <= settings.renew_days_before:
            key = cert["serial"]
            if key in warned:
                continue
            expiry_warning(cert["cn"], max(dl, 0), cert["serial"])
            warned.add(key)

            if settings.renew_enabled and dl <= 7:
                # auto-renew: same identity, new certificate
                try:
                    issue_cert(
                        root_id=cert["root_id"],
                        cn=cert["cn"],
                        sans=cert["sans"],
                        cert_type=cert["cert_type"],
                        days=365,
                    )
                    revoke_cert(cert["serial"], "superseded")
                except Exception:
                    pass


def main() -> None:
    interval = 60 * 60  # 1 hour
    while True:
        try:
            run_once()
        except Exception:
            pass
        time.sleep(interval)


if __name__ == "__main__":
    main()
