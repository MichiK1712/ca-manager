"""CA-Manager FastAPI application."""
from __future__ import annotations

import os
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import ca_ops, oidc
from .config import settings
from .oidc import require_user
from . import mailer


async def parse_body(request: Request) -> dict:
    """Parse request body as JSON or form-encoded (HTMX sends form-encoded)."""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        return await request.json()
    # form-encoded
    form = await request.form()
    return {k: v for k, v in form.items()}


def user_label(user: dict) -> str:
    """Human identifier for the authenticated user (for audit / created_by)."""
    return (
        user.get("preferred_username")
        or user.get("email")
        or user.get("name")
        or user.get("sub", "")
    )

BASE = os.path.dirname(__file__)
STATIC = os.path.join(BASE, "static")
TEMPLATES = os.path.join(BASE, "templates")

app = FastAPI(title="CA-Manager", version="1.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key or "dev-secret-change-me",
    same_site="lax",
    https_only=True,
)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
tpl = Jinja2Templates(directory=TEMPLATES)


def _render_dashboard(request: Request, user: dict) -> HTMLResponse:
    """Render the full dashboard body (used on load + after mutations)."""
    return tpl.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "roots": ca_ops.list_roots(),
        "certs": sorted(ca_ops.list_certs(), key=lambda c: c["not_after"], reverse=True),
    })


def _render_root_form(request: Request, user: dict) -> HTMLResponse:
    return tpl.TemplateResponse(request, "root_form.html", {"user": user})


# --- Auth routes ----------------------------------------------------------

@app.get("/")
async def index(request: Request):
    token = request.session.get("id_token")
    if not token:
        return RedirectResponse("/login")
    return RedirectResponse("/dashboard")


@app.get("/login")
async def login(request: Request):
    state, pkce = oidc.new_state()
    request.session["oauth_state"] = state
    request.session["pkce"] = pkce
    url = await oidc.oidc.authorization_url(state, pkce)
    return RedirectResponse(url)


@app.get("/oidc/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if state != request.session.get("oauth_state"):
        raise HTTPException(401, "State mismatch")
    tokens = await oidc.oidc.exchange_code(code, request.session["pkce"])
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(401, "No id_token returned")
    # validate before storing
    await oidc.oidc.validate_id_token(id_token)
    request.session["id_token"] = id_token
    return RedirectResponse("/dashboard")


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


# --- API routes -----------------------------------------------------------

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/me")
async def me(user=Depends(require_user)):
    return {"preferred_username": user.get("preferred_username"),
            "name": user.get("name"),
            "email": user.get("email")}

@app.post("/api/test-email")
async def api_test_email(user=Depends(require_user)):
    """Send a test email through the configured SMTP relay."""
    ok, detail = mailer.send_email_detailed(
        "[CA] Test-E-Mail",
        "Dies ist eine Test-E-Mail des CA-Managers.\n"
        "SMTP-Versand funktioniert.\n\n(ca.kubalek.local)",
    )
    if not ok:
        raise HTTPException(502, f"SMTP-Versand fehlgeschlagen: {detail}")
    return {"status": "sent"}


@app.get("/api/roots")
async def api_roots(user=Depends(require_user)):
    return ca_ops.list_roots()


@app.post("/api/roots")
async def api_create_root(request: Request, user=Depends(require_user)):
    body = await parse_body(request)
    try:
        root = ca_ops.create_root(
            name=body["name"],
            org=body.get("org", "MK"),
            days=int(body.get("days", 3650)),
            key_type=body.get("key_type", "rsa"),
            key_size=int(body.get("key_size", 4096)),
            created_by=user_label(user),
        )
    except Exception as e:
        raise HTTPException(400, str(e))
    if request.headers.get("HX-Request"):
        return _render_dashboard(request, user)
    return JSONResponse(root)


@app.get("/api/roots/{root_id}/cert")
async def api_root_cert(root_id: str, user=Depends(require_user)):
    pem = ca_ops.root_cert(root_id)
    return Response(content=pem, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={root_id}_ca.crt"})


@app.post("/api/roots/{root_id}/renew")
async def api_renew_root(request: Request, root_id: str, user=Depends(require_user)):
    result = ca_ops.renew_root(root_id)
    if request.headers.get("HX-Request"):
        return _render_dashboard(request, user)
    return JSONResponse(result)


@app.post("/api/roots/{root_id}/revoke")
async def api_revoke_root(request: Request, root_id: str, user=Depends(require_user)):
    body = await parse_body(request)
    result = ca_ops.revoke_root(root_id, body.get("reason", "unspecified"))
    if request.headers.get("HX-Request"):
        return _render_dashboard(request, user)
    return JSONResponse(result)


@app.get("/api/certs")
async def api_certs(user=Depends(require_user)):
    return ca_ops.list_certs()


@app.post("/api/certs")
async def api_issue(request: Request, user=Depends(require_user)):
    body = await parse_body(request)
    sans_raw = body.get("sans", "")
    sans = [s.strip() for s in str(sans_raw).split(",") if s.strip()]
    try:
        rec = ca_ops.issue_cert(
            root_id=body["root_id"],
            cn=body["cn"],
            sans=sans,
            cert_type=body.get("cert_type", "server"),
            days=int(body.get("days", 365)),
            created_by=user_label(user),
        )
    except Exception as e:
        raise HTTPException(400, str(e))
    if request.headers.get("HX-Request"):
        return _render_dashboard(request, user)
    return JSONResponse(rec)


@app.get("/api/certs/{serial}/pem")
async def api_cert_pem(serial: str, user=Depends(require_user)):
    cert = ca_ops.get_cert_pem(serial)
    key = ca_ops.get_cert_key_pem(serial)
    body = cert + key
    return Response(content=body, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={serial}.pem"})


@app.get("/api/certs/{serial}/crt")
async def api_cert_crt(serial: str, user=Depends(require_user)):
    rec = next((c for c in ca_ops.list_certs() if c["serial"] == serial), None)
    cert = ca_ops.get_cert_pem(serial)
    name = rec["cn"] if rec else serial
    return Response(content=cert, media_type="application/x-x509-ca-cert",
                    headers={"Content-Disposition": f"attachment; filename={name}.crt"})


@app.get("/api/certs/{serial}/key")
async def api_cert_key(serial: str, user=Depends(require_user)):
    rec = next((c for c in ca_ops.list_certs() if c["serial"] == serial), None)
    key = ca_ops.get_cert_key_pem(serial)
    name = rec["cn"] if rec else serial
    return Response(content=key, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={name}.key"})


@app.get("/api/certs/{serial}/chain")
async def api_cert_chain(serial: str, user=Depends(require_user)):
    """fullchain = cert + issuing root CA cert (for nginx fullchain.pem)."""
    rec = next((c for c in ca_ops.list_certs() if c["serial"] == serial), None)
    cert = ca_ops.get_cert_pem(serial)
    chain = cert
    if rec and rec.get("root_id"):
        chain += ca_ops.root_cert(rec["root_id"])
    name = rec["cn"] if rec else serial
    return Response(content=chain, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={name}-fullchain.pem"})


@app.get("/api/certs/{serial}/p12")
async def api_cert_p12(serial: str, user=Depends(require_user)):
    rec = next(c for c in ca_ops.list_certs() if c["serial"] == serial)
    data = ca_ops.get_pkcs12(serial, rec["cn"])
    return Response(content=data, media_type="application/x-pkcs12",
                    headers={"Content-Disposition": f"attachment; filename={rec['cn']}.p12"})


@app.post("/api/certs/{serial}/revoke")
async def api_revoke_cert(request: Request, serial: str, user=Depends(require_user)):
    body = await parse_body(request)
    result = ca_ops.revoke_cert(serial, body.get("reason", "unspecified"))
    if request.headers.get("HX-Request"):
        return _render_dashboard(request, user)
    return JSONResponse(result)


# --- UI (HTMX-rendered) ----------------------------------------------------

@app.get("/ui/root-form", response_class=HTMLResponse)
async def root_form(request: Request, user=Depends(require_user)):
    return _render_root_form(request, user)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user=Depends(require_user)):
    return _render_dashboard(request, user)
