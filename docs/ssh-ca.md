# SSH-CA — OpenSSH-Zertifikate

Der CA-Manager kann neben X.509-Zertifikaten auch **echte OpenSSH-Zertifikate**
ausstellen. Das ist eine **separate PKI** (eigenes Format, kein X.509).

## Warum SSH-CA?

- **Kein Passwort-Login** nötig — Identität wird vom CA bestätigt.
- **Ablaufdatum** je Zertifikat (`+8h`, `+52w`, …).
- **Widerrufbar** (Revoke im Dashboard).
- **Host-/User-Auth** zentral steuerbar.

## Konzept

| Rolle | Beschreibung |
|---|---|
| **SSH-CA-Root** | Signier-Schlüssel (ed25519/RSA/ECDSA), wird einmal angelegt. |
| **User-Zertifikat** | Signiert einen Client-Public-Key, Principals = Usernames. |
| **Host-Zertifikat** | Signiert einen Server-Public-Key, Principals = Hostnames/IPs. |

## 1. SSH-CA anlegen

Im Dashboard → **SSH-CA** → Name + Schlüsseltyp wählen → **SSH-CA erstellen**.

Danach den **Public Key** laden (`ssh-ca-<id>.pub`).

## 2. Server einrichten (User-Login)

Den Public Key der SSH-CA auf den Ziel-Server legen:

```bash
sudo install -m 644 ssh-ca.pub /etc/ssh/ssh-ca.pub
```

In `/etc/ssh/sshd_config` eintragen:

```sshconfig
TrustedUserCAKeys /etc/ssh/ssh-ca.pub
```

Neu laden:

```bash
sudo systemctl reload sshd
```

## 3. User-Zertifikat signieren

1. Client erzeugt (einmalig) ein Schlüsselpaar:

   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
   ```

2. Client schickt den Inhalt von `~/.ssh/id_ed25519.pub` an den Admin.
3. Admin: Dashboard → **SSH-CA → Zertifikat signieren**:
   - Typ **User**
   - Principals: Usernames, kommagetrennt (z.B. `michi,root`)
   - Public Key einfügen
   - Gültigkeit wählen (z.B. `+8h` für kurzlebige Zugriffe)
4. Client lädt die erzeugte `*-cert.pub` und legt sie **neben den privaten Key**:

   ```bash
   # ~/.ssh/id_ed25519-cert.pub
   ```

Login läuft dann über den CA — kein Passwort, mit Ablauf und Revoke.

## 4. Host-Zertifikat (Host-Auth)

1. Public Key des Hosts holen:

   ```bash
   cat /etc/ssh/ssh_host_ed25519_key.pub
   ```

2. Dashboard → **SSH-CA → Zertifikat signieren**:
   - Typ **Host**
   - Principals: Hostname + IPs (z.B. `nas.local,172.16.0.10`)
3. Download als `/etc/ssh/ssh_host_ed25519_key-cert.pub` ablegen.
4. In `sshd_config` referenzieren:

   ```sshconfig
   HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
   ```

## Widerruf

Im Dashboard → **SSH-Zertifikate** → **Widerrufen**. Das Zertifikat ist ab
sofort ungültig (Status `revoked`).
