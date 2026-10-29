# Switchyard 0.4.0

Independent, self-hosted remote operations console, with persistent SQLite data and optional Vaultwarden password-vault integration. **This is an ongoing development release, not production-certified**. It is not a fork of Nexterm or Next Terminal. Use on a restricted trusted network with HTTPS termination; do not expose it directly to the Internet.

## Implemented workspaces

| Workspace | Implemented operations |
| --- | --- |
| Overview | Saved assets, environments, audit count, quick SSH connections |
| Assets | Persistent CRUD/search, SSH port, environment, notes, tmux, SSH authentication mode |
| Terminals | Multiple browser SSH tabs, xterm.js, resize, optional remote tmux reattachment |
| SFTP | Browse, create directory, upload/download (64 MiB max), rename, remove file or empty directory, **UTF-8 text edit with hash conflict detection, atomic overwrite where supported** (256 KiB max) |
| Docker | Remote Engine summary, containers/images/networks/volumes, inspect, logs/stats, start/stop/restart; **Compose project inventory, start/stop/restart** |
| Host health | On-demand agentless Linux `/proc` and filesystem monitoring via SSH; hostname, kernel, uptime, load average, available RAM, root disk; **persistent last 500 observations per asset** |
| Runbooks | Persistent command templates, descriptions and execution confirmation; execute against selected asset using existing auth, capture bounded output in browser, **persist only outcome metadata** |
| Vaultwarden | HTTPS origin config, Bitwarden Password Manager CLI API key login, unlock, lock, sync, list login IDs, use password on SSH connection |
| SSH keys | Generate Ed25519, import RSA/ECDSA/Ed25519 unencrypted private keys, copy public keys, prevent deletion when assigned |
| Host trust | Host-key discovery and fingerprint review; explicit trust/revocation; no silent key rotation |
| Audit | Local event journal, filter/pagination, CSV export with spreadsheet formula escaping |
| Settings | Change admin password, revoke other sessions, download WAL-consistent SQLite + trust-list backup |

## Remote desktops — RDP, VNC and SPICE (0.4.0)

The **Desktops** workspace now stores named RDP, VNC and SPICE targets, supports multiple browser tabs, favorites, duplicate/edit/remove, JSON inventory import/export (excluding credentials), bulk reachability checks, session history/CSV and administrator disconnect of active sessions. Interactive passwords stay in bounded, session-bound ephemeral tickets rather than SQLite. Keyboard, mouse, resize and clipboard features depend on the selected protocol/client. **SPICE read-only enforcement is not offered**; SPICE sessions must be treated as interactive. Check the actual security configuration of the remote server before enabling a console.

- **RDP and VNC:** A private `guacd` container (Apache Guacamole 1.6.0) performs protocol translation. The browser connects to Switchyard's authenticated WebSocket bridge, not directly to the managed desktop. `guacd` is not published on the host. Install/allow RDP or VNC on each remote target and configure network access from the Docker deployment.
- **SPICE:** A separate isolated `spice-html5` browser viewer connects over Switchyard's authenticated, short-lived, multi-channel WebSocket proxy. It supports saved direct SPICE endpoints and one-time QEMU/Proxmox `.vv` consoles. `.vv` contents (including SPICE passwords and proxy tokens) are not stored as saved desktop credentials. Verified SPICE TLS and HTTP CONNECT proxy flows are implemented, but need live validation against your hypervisor.
- **Vaultwarden:** Existing `bw` vault lookup can supply passwords for desktop sessions where configured. Vault sessions and target credentials must be unlocked independently.
- **Security:** Browser sessions are bound to the authenticated Switchyard administrator session. Session limits, origin checks, connection timeouts and host-side session management reduce abuse; these are not substitutes for firewall segmentation, MFA at the proxy and TLS. Do **not** publish the guacd port or a bare SPICE TCP port on the Internet.

For offline deployments, note that the Dockerfile retrieves the Guacamole 1.6.0 browser artifact from Maven Central during image build, npm client packages, and Debian `spice-html5=0.3.0-2`. The image build fails if required runtime JavaScript and CSS files cannot be found. A source ZIP alone does not include all third-party browser runtime assets.

Run the included smoke test against a temporary deployed instance (`scripts/smoke-test.sh`) and test a real RDP, VNC and SPICE server before production use. In particular, a passing API unit test **does not verify video, audio, keyboard, clipboard or hypervisor-console correctness**.

## Install on the LAN (default)

Requires Docker Engine, Docker Compose V2, OpenSSL, and reachable target hosts. **No SSH tunnel is required.** Switchyard listens on TCP 9791 on all host interfaces (`SWITCHYARD_BIND=0.0.0.0`) and authenticates LAN users with the administrator username/password. Keep the Docker host firewall restricted to trusted local subnets. **Never directly port-forward TCP/9791 from your router to the Internet.** Docker's published ports can bypass some simple host-firewall rules, so confirm effective firewall behavior with the actual Docker host network configuration.

```bash
git clone https://github.com/gigabytegrove/switchyard.git
cd switchyard
cp .env.example .env
chmod 600 .env
./scripts/deploy.sh
./scripts/smoke-test.sh
cat secrets/admin_password.txt
```

Browse to `http://DOCKER-HOST-LAN-IP:9791` from another LAN device and sign in as `admin`. Change your password in Settings. The deployment helper generates `secrets/admin_password.txt` and `secrets/mfa_key.txt` if absent, sets permissions to `0600`, and retains both on upgrades. Do not overwrite either secret. The default application listener is `0.0.0.0:9791`; the `guacd` service is *not* published on the host.

LAN IP addresses in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and local loopback/link-local addresses are accepted automatically. For LAN DNS names, add exact origin(s) to `LAN_ORIGINS`, separated by commas, e.g. `LAN_ORIGINS=http://switchyard.lan:9791,http://ops.home.arpa:9791`. Never list your public Internet domain in `LAN_ORIGINS`.

## HTTPS reverse proxy + mandatory external TOTP

**Enrollment order matters:** First sign in from a trusted LAN address, open **Settings → Two-factor authentication**, enter your administrator password, and generate an authenticator key. Add it to a TOTP-compatible authenticator app, then enter the displayed six-digit code to enable MFA. You must complete enrollment before external sign-in will work. The encrypted TOTP secret is persisted in SQLite, and its encryption key resides separately at `secrets/mfa_key.txt` (include both in a secure backup).

Next set the public HTTPS origin in `.env`:

```dotenv
SWITCHYARD_BIND=0.0.0.0
LAN_ORIGINS=
PUBLIC_ORIGIN=https://ops.example.net
COOKIE_SECURE=true
```

Set `PUBLIC_ORIGIN` to your *actual* HTTPS hostname, then run `./scripts/deploy.sh` again. **Public-origin logins require username + password + a six-digit TOTP**, even if the browser has a previously created password-only LAN session. The admin login form includes a TOTP field. Sessions authenticated without MFA cannot use APIs, terminal WebSockets or remote desktop sessions through the public origin. All external requests must pass via HTTPS with the original public `Host` header preserved.

### Nginx Proxy Manager / nginx

For NPM, configure a Proxy Host for your configured `PUBLIC_ORIGIN`, forward HTTP to your Docker host's LAN IP on port `9791`, enable **WebSockets Support**, request a valid TLS certificate, enable **Force SSL**, and ensure the incoming `Host` remains the public hostname. NPM must not route arbitrary/unmatched hostnames to Switchyard; this is an authentication boundary. Do not create a router NAT rule exposing `9791` directly.

Equivalent nginx proxy directives (inside its TLS `location /`):

```nginx
proxy_pass http://192.168.0.35:9791;  # replace with your actual Docker host address
proxy_http_version 1.1;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 3600s;
```

The reverse proxy must exclusively serve the exact configured HTTPS hostname and reject unknown `Host` values. Since the LAN port remains accessible, the application is not a substitute for firewall policy. For extra assurance, terminate remote access at a VPN or a separately authenticated proxy rather than forwarding the app's bare TCP port. The backend does not treat client-provided `X-Forwarded-For` as proof of LAN proximity.

### Authentication and MFA behavior

- LAN login: administrator password; TOTP optional. LAN HTTP session cookies are host-only, HttpOnly, SameSite=Strict, and not marked Secure so LAN browsing actually works.
- Public HTTPS login: administrator password plus time-based six-digit code, with single-use per time step, rate limiting, and Secure/HttpOnly/SameSite=Strict cookies.
- External access before MFA enrollment: explicitly blocked. MFA setup and disable actions are LAN-only, require the current password; disabling also requires a fresh TOTP code.
- Public HTTPS host must match `PUBLIC_ORIGIN` exactly, with no alternative public domains; requests from other hostnames are rejected. Remote desktop and terminal WebSockets enforce the same host/origin + MFA-session check.
- TOTP enrollment and secret encryption key survive restarts. Back up `secrets/mfa_key.txt` securely alongside the persistent data volume. Without that key, the saved MFA enrollment cannot be recovered.

For upgrades, preserve your existing data volume, Compose project name, `.env` and `secrets/` and use `./scripts/deploy.sh`; **never** run `docker compose down -v`.

## Upgrade from 0.1.0 / 0.2.0

**Preserve your named volume and Compose project name.** If you simply deploy the new ZIP from a differently named directory, Compose will typically create a differently named volume and your old asset database will appear missing. Upgrade the *existing* deployment directory instead:

1. Take an independent backup of the existing deployment data volume and save `.env` and `secrets/` separately. Save current image/source for rollback.
2. Extract the new source to a staging directory and copy its application files into the existing project directory. Preserve the existing `.env`, `secrets/` and volume; do not use `docker compose down -v`.
3. Run:

```bash
docker compose build --no-cache
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:9791/healthz
```

New runbook and host-snapshot tables are **created automatically**, leaving existing assets, SSH keys, trust inventory, audit records and Vaultwarden CLI cache in the volume. Rollback to the original v0.2.0 files/image is possible after a backed-up restore (older versions ignore the new tables), but do not claim full rollback until you verify your old version boots and logs in.

## Runbooks — operational behavior and security

Create a named command under **Runbooks**. Set an optional explanation and keep *Require confirmation* enabled for potentially disruptive work. Choose an asset and select **Run**; the command is executed as that asset's SSH identity with a **30-second deadline** and **256 KiB combined stdout/stderr limit**. The output appears in the current browser view only and is not written to the database or audit journal; status, target, start time, elapsed time and exit code are persisted. Errors record a failed run. No output replay is available after navigating away or reloading.

**Runbook commands are stored in plain text in SQLite.** Do not embed secrets directly in a command or description; use the asset's existing Vaultwarden SSH authentication where appropriate. Commands execute with the same privileges as a normal shell, so a misconfigured runbook can be destructive. The product currently has *single-administrator access only*; multi-user RBAC and per-runbook permissions are not implemented.

## Host health

Choose an asset under **Host health** and select **Check health**. This runs a fixed Linux shell probe over the verified SSH connection and parses `/proc/uptime`, `/proc/loadavg`, `/proc/meminfo`, `df` and `uname`. It stores a new success/failure observation on each check; older observations are trimmed to 500 per asset. This is **manual collection, not a background monitoring daemon**. It requires Linux with a POSIX shell and supported `/proc` fields. Non-Linux targets may fail and leave a failed observation.

## Safe SFTP text editor

Choose **Files**, browse to a text file, and click **Edit text**. Files are UTF-8, regular and at most **256 KiB**. Switchyard reads and hashes the original content, prompts before saving, compares the remote file again, writes to an exclusive temp name in the same directory, preserves the file permission bits, rechecks the remote hash and uses the server's OpenSSH `posix-rename` extension to atomically replace it. When the hash differs, it returns HTTP 409 and **does not silently overwrite**. If the server does not support atomic replacement it refuses the update (HTTP 501); use another editor. There remains a small compare-and-swap race if another editor changes the file immediately after the final hash check. Do not rely on the tool for concurrent high-integrity editing without external locking. Uploads still exclusively create and do not overwrite an existing file.

## Remote Docker and Compose

The SSH account must have existing rights to operate the target Docker daemon. Docker-group membership is effectively root-equivalent. The container running Switchyard itself has neither a Docker socket mount nor elevated Docker capabilities. Container metadata returned from `inspect` is allowlisted to avoid returning raw environment variables. **Log content may contain sensitive values**; it stays in the requesting browser response.

Compose inventory uses `docker compose ls --all --format json`. For start/stop/restart, Switchyard checks that the requested project exists in the current remote list, validates its project name, obtains its Compose configuration filenames from the server-side inventory, restricts them to absolute paths and quotes them before execution. Multi-file Compose projects support up to eight config paths. No implicit `up`, `down`, deletion, image pull or recreation is performed. Existing stacks with unsupported configuration metadata are inspect-only. The remote account must have the Compose V2 plugin and read access to its project files. Docker Compose syntax was checked against the official CLI reference: <https://docs.docker.com/reference/cli/docker/compose/ls/> and <https://docs.docker.com/reference/cli/docker/compose/>.

## Vaultwarden / SSH trust / private keys

Use **Bitwarden Password Manager CLI** (`bw`) with your existing Vaultwarden server, not Secrets Manager (`bws`). Configure the HTTPS origin, login using personal API key values, unlock with your vault master password and choose the appropriate vault item UUID in an asset. The application never persists the cleartext SSH password or vault master password in its own SQLite database. The CLI may save encrypted account/cache state in `/data/bw`; an unlocked `BW_SESSION` is memory-only and is lost on restart. Lock or log out from the Vaultwarden section when done.

Under **Host trust**, discover a key and independently verify the fingerprint before approving. A changed key must be explicitly revoked and re-approved. Under **SSH keys**, generated/imported private keys remain at `/data/keys` as restricted volume files; the API exposes only public material. Passphrase-protected keys are not supported yet.

## Data backup

**Settings → Download consistent backup** exports a SQLite WAL-consistent snapshot and `known_hosts`, with a SHA-256 manifest. The new runbooks, run history and host snapshots are in the SQLite file. Active sessions are stripped. The ZIP intentionally excludes private keys, Bitwarden CLI state, `.env` and bootstrap passwords, so it is **not a complete disaster recovery bundle**. The SQLite export includes password hashes, saved commands and asset metadata; encrypt and protect the backup. To restore, verify hashes, stop the container, restore files to the existing volume with owner UID/GID `10001`, then restart. Never overwrite a live SQLite database. The database limit remains 32 MiB and known-hosts limit 1 MiB.

## Earlier 0.3.0 verification (historical; not 0.4.0 certification)

- Python static compilation of backend and test suite: passed.
- API regression suite: **24 passed, 1 skipped**. The skip is the test requiring a real Paramiko installation in this environment. Tests cover API authentication, commands, SFTP mock operations, Compose invocation, JSON parsing, host history, backup exclusions, and v0.2-table upgrade simulation.
- JavaScript: `node --check static/app.js` passed.
- HTML: 116 JavaScript id references resolved with zero duplicates; all navigation pages resolved. Static frontend-contract test is part of pytest.
- Linux host health command: executed locally against the runtime's actual Linux `/proc` and parsed successfully. This is *not* a remote SSH integration test.
- FastAPI server: local `GET /healthz` returned version `0.3.0` during the prior release.
- Docker Engine and Compose build: not installed in this test environment, so **image build was not tested**.
- Live Paramiko SSH, SFTP server, remote Docker/Compose workloads and Vaultwarden CLI: **not tested**.
- Chromium browser navigation: blocked by administrator policy (`ERR_BLOCKED_BY_ADMINISTRATOR`); no successful UI-rendering test claimed.

Run local tests with the pinned test requirements:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check static/app.js
```

## Remaining work

SSH jump/proxy chains, multi-user RBAC/SSO/OIDC, full session recording and retention policies, background polling/alerts and trend charts, concurrent-safe server-side file locks, advanced upload/resume and remote editing beyond 256 KiB, scheduled and approval-based runbooks, passphrase-protected key storage, tested install/upgrade/rollback on an actual Docker host, and real Vaultwarden acceptance are **not implemented** in this version.
