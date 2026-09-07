# CA-Manager

Private Multi-Root PKI mit Web-UI. Ein Root-Zertifikat auf einem Rechner
vertrauen → alle von dieser Root ausgestellten Zertifikate sind automatisch
gültig.

Siehe **[PROTOCOL.md](./PROTOCOL.md)** für die vollständige Architektur.

## Komponenten

| Schicht | Software |
|---------|----------|
| Identity | Authentik (extern, `idp.mkubalek.eu`) |
| CA-Engine | CFSSL `multirootca` |
| Web-UI | FastAPI + HTMX + Tailwind-like CSS (Dark-Theme) |
| Erneuerung | Python-Scheduler (Renewal-Agent) + E-Mail via externem SMTP |

## Schnellstart (Portainer)

1. **Env-Variablen** aus `.env.example` übernehmen und in Portainer als
   Stack-Environment-Variablen bzw. Secrets setzen.
   - `SECRET_KEY` z.B. mit `openssl rand -hex 32` erzeugen.
   - `CA_KEY_PASSPHRASE` frei wählen (verschlüsselt die CA-Private-Keys).
   - SMTP- und OIDC-Werte eintragen (aus Vaultwarden).
2. **Stack deployen** (Compose-Stack mit dieser `docker-compose.yml`).
   Das UI-Image wird per GitHub Actions nach GHCR gebaut und von Portainer
   nur noch gezogen (kein Build auf dem Host).
3. **Authentik** konfigurieren (siehe `docs/authentik.md`).
4. **NPM** Proxy-Host `ca.kubalek.local` → `http://<host>:8080` anlegen.

## Trust-Verteilung (einmal pro Rechner)

Root-Zertifikat (`<root-id>_ca.crt`) aus dem UI herunterladen und installieren:

- **Linux:** `cp <root>_ca.crt /usr/local/share/ca-certificates/` → `sudo update-ca-certificates`
- **Windows:** `certlm.msc` → Vertrauenswürdige Stammzertifizierungsstellen → Importieren
- **macOS:** Schlüsselbund → Import → „Immer vertrauen"

## Lokale Entwicklung

```bash
cd backend
pip install -r requirements.txt
export CA_DATA_DIR=./data CFSSL_URL=http://localhost:8888 SECRET_KEY=dev
uvicorn main:app --reload --port 8080
```
