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
from .config import settings
from .oidc import require_user


async def parse_body(request: Request) -> dict:
    """Parse request body as JSON or form-encoded (HTMX sends form-encoded)."""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        return await request.json()
    # form-encoded
    form = await request.form()
    return {k: v for k, v in form.items()}

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
        )
        return root
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/roots/{root_id}/cert")
async def api_root_cert(root_id: str, user=Depends(require_user)):
    pem = ca_ops.root_cert(root_id)
    return Response(content=pem, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={root_id}_ca.crt"})


@app.post("/api/roots/{root_id}/renew")
async def api_renew_root(root_id: str, user=Depends(require_user)):
    return ca_ops.renew_root(root_id)


@app.post("/api/roots/{root_id}/revoke")
async def api_revoke_root(request: Request, root_id: str, user=Depends(require_user)):
    body = await parse_body(request)
    return ca_ops.revoke_root(root_id, body.get("reason", "unspecified"))


@app.get("/api/certs")
async def api_certs(user=Depends(require_user)):
    return ca_ops.list_certs()


@app.post("/api/certs")
async def api_issue(request: Request, user=Depends(require_user)):
    body = await parse_body(request)
    sans_raw = body.get("sans", "")
    sans = [s.strip() for s in str(sans_raw).split(",") if s.strip()]
    try:
        return ca_ops.issue_cert(
            root_id=body["root_id"],
            cn=body["cn"],
            sans=sans,
            cert_type=body.get("cert_type", "server"),
            days=int(body.get("days", 365)),
        )
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/certs/{serial}/pem")
async def api_cert_pem(serial: str, user=Depends(require_user)):
    cert = ca_ops.get_cert_pem(serial)
    key = ca_ops.get_cert_key_pem(serial)
    body = cert + key
    return Response(content=body, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={serial}.pem"})


@app.get("/api/certs/{serial}/p12")
async def api_cert_p12(serial: str, user=Depends(require_user)):
    rec = next(c for c in ca_ops.list_certs() if c["serial"] == serial)
    data = ca_ops.get_pkcs12(serial, rec["cn"])
    return Response(content=data, media_type="application/x-pkcs12",
                    headers={"Content-Disposition": f"attachment; filename={rec['cn']}.p12"})


@app.post("/api/certs/{serial}/revoke")
async def api_revoke_cert(request: Request, serial: str, user=Depends(require_user)):
    body = await request.json()
    return ca_ops.revoke_cert(serial, body.get("reason", "unspecified"))


# --- UI (HTMX-rendered) ----------------------------------------------------

@app.get("/ui/root-form", response_class=HTMLResponse)
async def root_form(request: Request, user=Depends(require_user)):
    return tpl.TemplateResponse(request, "root_form.html", {"user": user})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user=Depends(require_user)):
    return tpl.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "roots": ca_ops.list_roots(),
        "certs": sorted(ca_ops.list_certs(), key=lambda c: c["not_after"], reverse=True),
    })
