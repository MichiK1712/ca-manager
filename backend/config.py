"""Application configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # OIDC
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    oidc_scope: str

    # CA
    cfssl_url: str
    ca_data_dir: str
    ca_key_passphrase: str

    # SMTP
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    smtp_to: str
    smtp_tls: str

    # Renewal
    renew_enabled: bool
    renew_days_before: int

    # Security
    secret_key: str


def _bool(v: str) -> bool:
    return v.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    return Settings(
        oidc_issuer=os.getenv("OIDC_ISSUER", "https://idp.mkubalek.eu/application/o/ca-manager/"),
        oidc_client_id=os.getenv("OIDC_CLIENT_ID", ""),
        oidc_client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
        oidc_redirect_uri=os.getenv("OIDC_REDIRECT_URI", "https://ca.kubalek.local/oidc/callback"),
        oidc_scope=os.getenv("OIDC_SCOPE", "openid profile email"),

        cfssl_url=os.getenv("CFSSL_URL", "http://cfssl:8888"),
        ca_data_dir=os.getenv("CA_DATA_DIR", "/var/lib/ca"),
        ca_key_passphrase=os.getenv("CA_KEY_PASSPHRASE", ""),

        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_from=os.getenv("SMTP_FROM", "ca@kubalek.local"),
        smtp_to=os.getenv("SMTP_TO", ""),
        smtp_tls=os.getenv("SMTP_TLS", "starttls"),

        renew_enabled=_bool(os.getenv("RENEW_ENABLED", "true")),
        renew_days_before=int(os.getenv("RENEW_DAYS_BEFORE", "30")),

        secret_key=os.getenv("SECRET_KEY", ""),
    )


settings = load_settings()
