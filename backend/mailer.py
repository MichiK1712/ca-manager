"""E-Mail notification via external SMTP."""
from __future__ import annotations

import smtplib
import ssl
from email.mime.text import MIMEText

from .config import settings


def send_email(subject: str, body: str, to: str | None = None) -> bool:
    """Send a plain-text email through the configured external SMTP server."""
    if not settings.smtp_host or not settings.smtp_from:
        return False

    recipient = to or settings.smtp_to
    if not recipient:
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = recipient

    context = None
    if settings.smtp_tls in {"starttls", "ssl"}:
        context = ssl.create_default_context()

    try:
        if settings.smtp_tls == "ssl":
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port)
            if settings.smtp_tls == "starttls":
                server.starttls(context=context)

        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)

        server.sendmail(settings.smtp_from, [recipient], msg.as_string())
        server.quit()
        return True
    except Exception:
        return False


def expiry_warning(cn: str, days_left: int, serial: str) -> bool:
    level = "GELB" if days_left > 7 else "ROT"
    subject = f"[CA] {level}: Zertifikat '{cn}' läuft in {days_left} Tagen ab"
    body = (
        f"Zertifikat: {cn}\n"
        f"Serien-Nr.: {serial}\n"
        f"Läuft ab in: {days_left} Tagen\n\n"
        f"Bitte rechtzeitig erneuern.\n"
        f"(CA-Manager — ca.kubalek.local)"
    )
    return send_email(subject, body)
