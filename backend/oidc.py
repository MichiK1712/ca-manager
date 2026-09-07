"""OIDC authentication via Authentik.

OIDC Authorization Code flow with PKCE (S256). Token validation uses PyJWT's
PyJWKClient against the provider's JWKS endpoint, which handles the `kid`
lookup and signature verification correctly.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, Request

from .config import settings


class OIDC:
    def __init__(self):
        self._config: dict[str, Any] = {}
        self._jwks_client: PyJWKClient | None = None

    async def _discovery(self) -> dict[str, Any]:
        if self._config:
            return self._config
        base = settings.oidc_issuer.rstrip("/")
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{base}/.well-known/openid-configuration")
            r.raise_for_status()
            self._config = r.json()
        return self._config

    def _get_jwks_client(self) -> PyJWKClient:
        if self._jwks_client is None:
            self._jwks_client = PyJWKClient(
                settings.oidc_issuer.rstrip("/") + "/jwks/",
                cache_keys=True,
            )
        return self._jwks_client

    async def authorization_url(self, state: str, pkce: str) -> str:
        cfg = await self._discovery()
        challenge = hashlib.sha256(pkce.encode()).digest()
        challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
        params = {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": settings.oidc_scope,
            "state": state,
            "code_challenge": challenge_b64,
            "code_challenge_method": "S256",
        }
        qs = "&".join(f"{k}={httpx.QueryParams({'x': v})['x']}" for k, v in params.items())
        return f"{cfg['authorization_endpoint']}?{qs}"

    async def exchange_code(self, code: str, pkce: str) -> dict[str, Any]:
        cfg = await self._discovery()
        # Authentik supports client_secret_post. Send code_verifier for PKCE.
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "client_secret": settings.oidc_client_secret,
            "code_verifier": pkce,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(cfg["token_endpoint"], data=data)
            if r.status_code != 200:
                # Surface the provider's error description (no secrets) for diagnosis.
                try:
                    body = r.json()
                    detail = body.get("error_description") or body.get("error") or str(r.status_code)
                except Exception:
                    detail = f"{r.status_code}: {r.text[:200]}"
                raise HTTPException(status_code=401, detail=f"Token exchange failed: {detail}")
            return r.json()

    async def validate_id_token(self, id_token: str) -> dict[str, Any]:
        cfg = await self._discovery()
        jwks_client = self._get_jwks_client()
        alg = jwt.get_unverified_header(id_token).get("alg", "RS256")
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        payload = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=[alg],
            audience=settings.oidc_client_id,
            options={"verify_exp": True},
        )
        iss = (payload.get("iss") or "").rstrip("/")
        if iss != settings.oidc_issuer.rstrip("/"):
            raise HTTPException(status_code=401, detail="Issuer mismatch")
        return payload


oidc = OIDC()


async def require_user(request: Request) -> dict[str, Any]:
    """Dependency: return authenticated user claims or raise 401."""
    token = request.session.get("id_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return await oidc.validate_id_token(token)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def new_state() -> tuple[str, str]:
    state = secrets.token_urlsafe(16)
    pkce = secrets.token_urlsafe(64)
    return state, pkce
