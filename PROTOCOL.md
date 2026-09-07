# PROTOCOL.md — Private Multi-Root CA (CA-Manager)

> Interne PKI für Michi. Ein Root-Zertifikat auf einem Rechner vertrauen →
> alle von dieser Root ausgestellten Zertifikate sind automatisch gültig.

## 1. Zweck & Umfang

Betrieb einer privaten **Multi-Root-CA** mit Web-UI. Ziel: Server- und
Client-Zertifikate für die eigene Infrastruktur (~30 Zertifikate) ausstellen,
verwalten, erneuern und widerrufen — bequem über eine Oberfläche, ohne CLI.

- **Betrieb:** nur lokal (LAN), geroutet über Nginx Proxy Manager
- **Hostname:** `ca.kubalek.local`
- **Auth:** OIDC über bestehendes Authentik (`idp.mkubalek.eu`)
- **Deployment:** Portainer (Docker-Compose Stack)

## 2. Architektur

```
┌─────────────────────────────────────────────────────────┐
│  Browser (Michi)                                        │
│      │ 1. OIDC-Login (Authentik)                        │
│      ▼                                                  │
│  Authentik (idp.mkubalek.eu, separater Server)          │
│      │ 2. Session/Token                                 │
│      ▼                                                  │
│  CA-UI (FastAPI)  ── NPM: ca.kubalek.local              │
│      │ (openssl: signieren, revoken, PKCS#12)          │
│      ▼                                                  │
│  Multi-Root CA (Roots 1..3)                            │
│      │                                                  │
│      ├── Root-CA 1 (z.B. "Home")                        │
│      ├── Root-CA 2 (z.B. "Services")                    │
│      └── Root-CA 3 (z.B. "Users")                       │
│                                                         │
│  Renewal-Agent (Scheduler) ── SMTP (extern) ── Warnung  │
└─────────────────────────────────────────────────────────┘
```

### Komponenten
| Schicht | Software | Funktion |
|---------|----------|----------|
| Identity | Authentik (extern) | OIDC-Login + RBAC (Gruppen) |
| CA-Engine | openssl (im Backend) | Multi-Root, Signieren, Revoke |
| Web-UI | FastAPI + HTMX + Tailwind | Bedienoberfläche |
| Renewal | Python-Scheduler | Ablauf-Prüfung, Auto-Erneuerung, E-Mail-Warnung |

## 3. Multi-Root-Modell

- **2–3 parallele Root-CAs**, jede signiert unabhängige Zertifikate.
- Pro ausgestelltem Zertifikat wird die **signierende Root** gewählt.
- Root-Lebenszyklus vollständig in der UI:
  - **erstellen** (Schlüsselgenerierung + Self-Sign)
  - **erneuern** (Rotation: neue Root, alte bis Ablauf weiter vertrauen)
  - **widerrufen** (Root in CRL)
  - **downloaden** (öffentliches Zertifikat `*_ca.crt` zum Verteilen)

### Trust-Verteilung (einmal pro Rechner pro Root)
| OS | Schritte |
|----|----------|
| Linux | `cp <root>_ca.crt /usr/local/share/ca-certificates/` → `sudo update-ca-certificates` |
| Windows | `certlm.msc` → Vertrauenswürdige Stammzertifizierungsstellen → Importieren |
| macOS | Schlüsselbund → Import → „Immer vertrauen" |
| Android/iOS | Download → Installieren → (iOS) „Volles Vertrauen aktivieren" |

## 4. Zertifikatstypen

| Typ | keyUsage / EKU | Verwendung |
|-----|----------------|------------|
| **Server** | digitalSignature, keyEncipherment / `serverAuth` | HTTPS, interne Dienste (nginx, POCSAG, etc.) |
| **Client** | digitalSignature / `clientAuth` | Identitäts-Zertifikate, an Authentik-User gebunden |

- Client-Certs: CN = Username, optional SAN (E-Mail/UPN).
- Server-Certs: CN + SANs (DNS-Namen und/oder IPs).
- Export: PEM (cert+key) **und** PKCS#12 (`.pfx`/`.p12`, für Windows/Clients).

## 5. Schlüssel-Handling (CRITICAL)

- **Root- & Intermediate-Private-Keys liegen NIE im Klartext.**
- Auf Disk **verschlüsselt** (Passphrase, via env/Secret injiziert).
- Die UI **zeigt und exportiert niemals** einen Private Key.
- Verteilbar ist ausschließlich das **öffentliche** CA-Zertifikat (`*_ca.crt`).
- Passphrases & Secrets aus Vaultwarden, nicht im Repo/Stack-File.

## 6. Revocation

- Revoke-Gründe (RFC 5280): `unspecified`, `keyCompromise`, `caCompromise`,
  `affiliationChanged`, `superseded`, `cessationOfOperation`.
- Nach Revoke: Eintrag in CFSSL-DB + **neue CRL**.
- Gilt einheitlich für Server-, Client- **und** von Root signierte Zertifikate.
- Root-Widerruf setzt die Root selbst in die CRL.

## 7. Erneuerung (Renewal-Agent, kein ACME)

Der Agent prüft periodisch alle Zertifikate:
- **30 Tage** vor Ablauf → E-Mail-Warnung (Stufe gelb)
- **7 Tage** vor Ablauf → E-Mail-Warnung (Stufe rot)
- Optional **Auto-Erneuerung**: neues Zertifikat (gleiche CN/SANs), altes automatisch widerrufen
- Versand über **externen SMTP** (STARTTLS 587), Absender/Empfänger konfigurierbar

## 8. OIDC-Integration

- Authentik: neue **OIDC Application + Provider** (Doku in `docs/authentik.md`).
- Redirect-URI: `https://ca.kubalek.local/oidc/callback`
- Token-Validierung gegen `idp.mkubalek.eu/.well-known/openid-configuration` (JWKS).
- RBAC: Authentik-Gruppen mappen auf UI-Rollen (viewer / operator / admin).

## 9. Verzeichnisstruktur (im Container)

```
/var/lib/ca/
├── roots/
│   ├── <root-id>/
│   │   ├── ca.pem          # öffentliches Root-Zertifikat
│   │   ├── ca-key.pem      # verschlüsselt (externes Secret)
│   │   └── ca.csr          # optional
├── certs/
│   ├── index.db            # Zertifikats-Index (serials, status)
│   └── <serial>/
│       ├── cert.pem
│       ├── key.pem         # verschlüsselt
│       └── bundle.p12      # PKCS#12 (optional)
├── crl/
│   └── <root-id>.crl
└── config/
    └── ca-config.json      # CFSSL signing profiles
```

## 10. Sicherheits-Prinzipien

- Zero-Trust für externe Inputs (CFSSL-API-Antworten, SMTP, OIDC-Tokens verifizieren).
- Alle Aktionen mit Audit-Log (wer/wann/was, Timestamp).
- Keine Klartext-Geheimnisse in Repo, Logs oder Chat.
- UI nur über HTTPS (NPM terminiert TLS) erreichbar.
