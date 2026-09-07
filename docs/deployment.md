# Deployment via NPM + Portainer

## Nginx Proxy Manager (NPM)

1. **Proxy Host** anlegen:
   - Domain: `ca.kubalek.local`
   - Scheme: `http`
   - Forward Hostname: `<Docker-Host-IP>`
   - Forward Port: `8080`
   - Block Common Exploits: aktiv
   - (optional) SSL mit deinem eigenen CA-Cert oder Let's Encrypt

2. Der interne DNS-Eintrag `ca.kubalek.local` muss auf den NPM-Host zeigen
   (interner DNS / Pi-hole / Router).

## Portainer Stack

1. **Stacks → Add stack → Web editor**
2. Inhalt von `docker-compose.yml` einfügen.
3. **Environment variables** setzen (aus `.env.example`).
   - Secrets (SMTP-Passwort, OIDC-Client-Secret, `SECRET_KEY`, `CA_KEY_PASSPHRASE`)
     als **Portainer Secrets** oder Env-Vars setzen — nie im Klartext im Stack-File.
4. **Deploy** → Container `ca-cfssl`, `ca-ui`, `ca-renewer` starten.

## Volumes

- `ca_data` — persistiert Roots, Zertifikate, Index, Audit-Log, CRLs.
  Regelmäßig backuppen (enthält die verschlüsselten Private Keys + Index-DB).

## Healthchecks

- `ca-ui` → `/healthz`
- `ca-cfssl` → `cfssl info`
- Nach dem Deploy in Portainer prüfen, ob alle Container `healthy` sind.
