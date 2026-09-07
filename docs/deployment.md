# Deployment via NPM + Portainer

## Nginx Proxy Manager (NPM)

1. **Proxy Host** anlegen:
   - Domain: `ca.kubalek.local`
   - Scheme: `http`
   - Forward Hostname: `<Docker-Host-IP>`
   - Forward Port: `8080` (oder dein `UI_PORT`, siehe unten)
   - Block Common Exploits: aktiv
   - (optional) SSL mit deinem eigenen CA-Cert oder Let's Encrypt

2. Der interne DNS-Eintrag `ca.kubalek.local` muss auf den NPM-Host zeigen
   (interner DNS / Pi-hole / Router).

## Portainer Stack (Image-Ziehen, kein Build)

Das UI-Image wird **automatisch per GitHub Actions** gebaut und nach GHCR
gepusht. Portainer zieht nur das fertige Image — kein BuildKit/Build-Schritt
auf dem Host, damit entfällt der „Build-Worker/HTTP2"-Fehler.

1. **Stacks → Add stack → Repository**
   - Name: `ca-manager`
   - Repository URL: `https://github.com/MichiK1712/ca-manager.git`
   - Repository reference: `refs/heads/main`
   - Compose path: `docker-compose.yml`
   - Authentication: GitHub-Token (private repo) aktivieren

2. **Environment variables** setzen (aus `.env.example`).
   - Secrets (SMTP-Passwort, OIDC-Client-Secret, `SECRET_KEY`, `CA_KEY_PASSPHRASE`)
     als **Portainer Secrets** oder Env-Vars — nie im Klartext.

3. **Deploy** → Container `ca-ui`, `ca-renewer` starten.

### Wichtige Env-Vars

| Variable | Bedeutung | Beispiel |
|----------|-----------|----------|
| `UI_PORT` | Host-Port des UI (ändern, falls 8080 belegt) | `8443` |
| `OIDC_CLIENT_ID` / `SECRET` | aus Authentik | — |
| `SMTP_*` | externer Mailserver | — |
| `SECRET_KEY` | `openssl rand -hex 32` | — |
| `CA_KEY_PASSPHRASE` | verschlüsselt die CA-Keys | — |

## Image-Registry (GHCR)

- Image: `ghcr.io/michik1712/ca-manager-ui:latest`
- Wird bei jedem Push auf `main` neu gebaut (siehe `.github/workflows/build-image.yml`).
- Portainer zieht `:latest` → einfacher Update über „Re-pull image" + Redeploy.

## Volumes

- `ca_data` — persistiert Roots, Zertifikate, Index, Audit-Log, CRLs.
  Regelmäßig backuppen (enthält die verschlüsselten Private Keys + Index-DB).

## Healthchecks

- `ca-ui` → `/healthz`
- Nach dem Deploy prüfen, ob alle Container `healthy` sind.
