"""OIDC authentication via Authentik.

Minimal OIDC Authorization Code flow with PKCE, validated against the
provider's JWKS endpoint. Exposes a FastAPI dependency for protected routes.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any, Optional

import httpx
import jwt
from fastapi import HTTPException, Request

from .config import settings


class OIDC:
    def __init__(self):
        self._config: dict[str, Any] = {}
        self._jwks: dict[str, Any] = {}

    async def _discovery(self) -> dict[str, Any]:
        if self._config:
            return self._config
        # Authentik issuer pattern:
        #   https://idp.mkubalek.eu/application/o/<slug>/
        # Discovery endpoints hang off that issuer base.
        base = settings.oidc_issuer.rstrip("/")
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{base}/.well-known/openid-configuration")
            r.raise_for_status()
            self._config = r.json()
        return self._config

    async def _jwks_data(self) -> dict[str, Any]:
        if self._jwks:
            return self._jwks
        cfg = await self._discovery()
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(cfg["jwks_uri"])
            r.raise_for_status()
            self._jwks = r.json()
        return self._jwks

    async def authorization_url(self, state: str, pkce: str) -> str:
        cfg = await self._discovery()
        challenge = hashlib.sha256(pkce.encode()).digest()
        challenge_b64 = (
            __import__("base64").urlsafe_b64encode(challenge).rstrip(b"=").decode()
        )
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
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                cfg["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.oidc_redirect_uri,
                    "client_id": settings.oidc_client_id,
                    "client_secret": settings.oidc_client_secret,
                    "code_verifier": pkce,
                },
            )
            r.raise_for_status()
            return r.json()

    async def validate_id_token(self, id_token: str) -> dict[str, Any]:
        cfg = await self._discovery()
        jwks = await self._jwks_data()
        # JWT header not decoded for alg; trust the key from JWKS by kid.
        unverified = jwt.get_unverified_header(id_token)
        kid = unverified.get("kid")
        key = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                from jwt.algorithms import RSAAlgorithm
                key = RSAAlgorithm.from_jwk(jwk)
                break
        if key is None:
            raise HTTPException(status_code=401, detail="Unknown signing key")
        payload = jwt.decode(
            id_token,
            key,
            algorithms=[cfg.get("id_token_signing_alg_values_supported", ["RS256"])[0]],
            audience=settings.oidc_client_id,
        )
        # Tolerate trailing-slash variance on the issuer claim.
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
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def new_state() -> tuple[str, str]:
    state = secrets.token_urlsafe(16)
    pkce = secrets.token_urlsafe(64)
    return state, pkce
