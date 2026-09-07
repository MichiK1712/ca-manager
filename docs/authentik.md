# Authentik OIDC-Konfiguration für CA-Manager

Der CA-Manager nutzt dein bestehendes Authentik (`idp.mkubalek.eu`) als OIDC-Provider.

> **Wichtig (Issuer-Slug):** Authentik legt OIDC-Endpoints pro Application an.
> Der Issuer ist daher IMMER
> `https://idp.mkubalek.eu/application/o/<SLUG>/` — ersetze `<SLUG>` durch den
> Application-Slug (hier `ca-manager`).

## 1. OIDC-Provider anlegen (oder bestehenden nutzen)

In Authentik unter **Applications → Providers → OIDC Provider**:

| Feld | Wert |
|------|------|
| Name | `CA-Manager` |
| Authorization flow | default-provider-authorization-implicit-consent (oder expliziten Consent) |
| Redirect URIs / Origins | `https://ca.kubalek.local/oidc/callback` |
| Signing Key | (Standard oder eigener RS256-Key) |
| Client type | `confidential` |
| Client ID | (automatisch) |
| Client Secret | (generieren → in `.env` als `OIDC_CLIENT_SECRET`) |

## 2. Application anlegen

**Applications → Create:**

| Feld | Wert |
|------|------|
| Name | `CA-Manager` |
| Slug | `ca-manager` |
| Provider | den eben erstellten OIDC-Provider |
| Launch URL | `https://ca.kubalek.local` |

## 3. Gruppen für RBAC (optional)

Für feingranulare Rollen (viewer/operator/admin) lege in Authentik Gruppen an
und weise sie der Application zu. Der CA-Manager liest `groups` aus dem
ID-Token (Scope `profile` + ggf. `groups`).

Empfohlener Scope in `.env`: `OIDC_SCOPE=openid profile email groups`

## 4. Env-Werte im CA-Manager

```
OIDC_ISSUER=https://idp.mkubalek.eu/application/o/ca-manager/
OIDC_CLIENT_ID=<Client ID aus step 1>
OIDC_CLIENT_SECRET=<Client Secret aus step 1>
OIDC_REDIRECT_URI=https://ca.kubalek.local/oidc/callback
OIDC_SCOPE=openid profile email
```

## 5. Wichtig

- Redirect-URI muss **exakt** mit der URL übereinstimmen, unter der das UI
  erreichbar ist (NPM-Proxy-Host `ca.kubalek.local`).
- `https_only` ist aktiv → das UI muss über HTTPS (NPM) laufen.
