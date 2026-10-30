<div align="center">

# Switchyard

**Infrastructure in motion. Everything in view.**

Self-hosted machine profiles with SSH, SFTP, Docker, Linux health, and remote desktops (RDP, VNC, SPICE). Optional encrypted stored passwords and Vaultwarden integration.

[![Source tests and Docker build](https://github.com/gigabytegrove/switchyard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gigabytegrove/switchyard/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-0.5.3--dev.5-B72237)
![Docker](https://img.shields.io/badge/deployment-Docker-B72237?logo=docker)
![Protocols](https://img.shields.io/badge/desktops-RDP%20%7C%20VNC%20%7C%20SPICE-5934AC)
![Status](https://img.shields.io/badge/status-development-orange)

[Quick start](#quick-start) · [Setup wizard](#first-run-setup) · [Features](#features) · [Reverse proxy and MFA](#reverse-proxy-and-mfa) · [Upgrades](#upgrading-existing-installations) · [Security](#security-and-limitations)

</div>

> **Development build, not production-certified.** Source tests and selected deployment contracts can pass without proving live SSH/RDP/VNC/SPICE connectivity or complete hypervisor/OS compatibility. Restrict the host TCP 9791 port to your LAN, and do not expose it directly to the public Internet.

## Quick start

Prerequisites: Linux Docker Engine and the Docker Compose v2 plugin. No `.env`, secrets files, SSH tunnel, configuration YAML, CLI password generation, or database editing is required.

```bash
git clone https://github.com/gigabytegrove/switchyard.git
cd switchyard
./scripts/deploy.sh
docker compose logs switchyard
```

Open **`http://YOUR-DOCKER-HOST-IP:9791`** on a trusted LAN browser. Use the **one-time claim code** printed by `docker compose logs switchyard` to start the setup wizard. The container binds `0.0.0.0:9791` by default; your firewall must limit who can reach it. To validate the HTTP endpoint and browser-runtime files afterward:

```bash
./scripts/smoke-test.sh
docker compose ps
```

**LAN browser compatibility:** Session IDs for SSH, RDP, VNC, and SPICE use `crypto.getRandomValues()`, which works over private-IP HTTP as well as HTTPS. Browser UUID availability is regression tested in Chromium over an simulated LAN browser constraints.

**Machine navigation:** v0.5.3-dev.5 fixes a JavaScript crash when switching machines, Runbooks, or Files. The selector regression is exercised by an executable Node DOM test in CI.

**Operator workspace:** Resizable connection tree (196–440px) with remembered width; persisted collapsed folders; keyboard shortcuts Ctrl/Cmd+K and / for quick search; sorted folders and machines; narrow-screen slide-in directory with full-width terminal; session tabs indicate disconnected state. These are browser-only layout preferences, not server or credential configuration.

**Connection reliability (v0.5.3-dev.2):** SSH Reconnect now reuses the existing terminal tab and listeners. The explicit New session action is separate. Desktop sessions focus an existing connection, and the Reconnect control obtains a new ticket while replacing a disconnected viewer. SSH failures now report safe, actionable causes; Host trust review is available directly for the selected machine. These changes were tested with mocked SSH and browser transports; live target acceptance is still required.

**Live protocol acceptance:** The CI source-test job now provisions an isolated OpenSSH server and checks actual SSH host verification, saved-password authentication, SFTP upload/download, and the WebSocket terminal. This does not substitute for Windows RDP, VNC, SPICE or Vaultwarden acceptance against your targets.

**SSH password retry (v0.5.3-dev.5):** After a rejected login, Switchyard clears that attempt’s cached password and prompts for a new value in the **same SSH tab**. A successfully entered override is used for that login session, even when a saved encrypted password exists. To replace the saved value permanently, edit the machine. SSH protocol failures, host-key mismatches, and rejected credentials are reported separately.

**WebSocket transport (v0.5.3-dev.5):** SSH/RDP/VNC/SPICE require real HTTP WebSocket upgrade support. Earlier images omitted the Python WebSocket protocol dependency and could pass HTTP health checks while browser terminal sessions failed. The image now explicitly installs `websockets==16.0`; GitHub CI verifies a real authenticated 101 upgrade over TCP to the freshly built running container and rejects unauthorized upgrades. A passing health endpoint alone is not sufficient.

**Deployment images:** Docker Compose pulls published artifacts from GHCR. The app is built in GitHub Actions; Docker Hub is not required on the deployment host. All application configuration is written from the browser to the existing persistent `switchyard_data` Docker volume at `/data`.


## Machine-centric operation

When you sign in, **Machines** is the default landing page, with nested folders, an environment filter and search. Each machine profile contains **Overview, Terminal, Remote desktop, File transfer, Docker and Health** tabs. SFTP browsing, upload, download and editing are scoped automatically to the SSH connection of that machine; no independent File Transfer menu is required. RDP/VNC/SPICE connections sharing the same hostname appear together, including desktop-only machines. Creating a desktop connection from a machine profile prepopulates its host.

The SSH and desktop editors now offer **Save encrypted password**. Leaving that input blank on edits retains the existing saved secret; checking **Remove saved password** clears it. No plaintext password is stored in SQLite. The encryption key resides in the persistent `/data/credentials.key` and is included in the **sensitive** backup archive. There is no browser `prompt()` or `confirm()`; the app uses accessible native dialogs for credentials and confirmation. One-time unsaved SSH passwords remain in browser memory only until logout.

### In-app Docker updater

Navigate to **Settings → Software updates**, configure a previously saved SSH machine corresponding to the Docker host, the exact Compose project name, and the absolute directory of your Git checkout. Reenter the Switchyard administrator password to save. When requested, **Install update** executes a detached SSH job that verifies the GitHub remote, fast-forwards the checkout, pulls images and recreates that specific Compose project. Its log can be inspected after reconnecting. You must use a saved SSH password, key or unlocked Vaultwarden credential for that host. No host Docker socket is mounted into Switchyard. A failed update is visible in the job log; automated rollback is not yet implemented. Only configure this workflow on a trusted host under your control.

**Testing qualification:** Browser controls were exercised in Chromium using mocked API replies and the backend regression suite; an actual Docker host self-update and live SSH/RDP/VNC/SPICE end-to-end session have not been validated in this release.

## Connections workspace — two-column layout

Switchyard opens directly into a connection manager instead of a full-page machine profile. The **left column** is a permanent searchable tree of machines grouped into nested folders. One click selects a host; double-click connects using its first configured protocol. Folder creation, editing and nested organization use the existing persistent database. The **right column** is a compact connection canvas with open SSH/RDP/VNC/SPICE tabs and session-close controls. Machine details appear in an optional narrow inspector rather than consuming a full page.

Files, Docker, Health, Runbooks, Activity, SSH keys, Host trust and Settings live in global navigation. Files, Docker and Health preselect the current SSH machine. The user's supplied red/silver SwitchYard mark is used in the app bar, with the full wordmark on sign-in and a favicon. Existing saved machines, passwords and Docker volumes are unchanged.

**Verification boundary:** The two-pane workbench and session navigation are tested using mocked browser connections; live protocol operation still requires testing against real SSH/RDP/VNC/SPICE hosts.

## First-run setup

1. **Claim the appliance.** Enter the one-time bootstrap code emitted in the container logs. This code changes each time an unconfigured container restarts and is invalidated after setup. Choose an administrator username and password (14-character minimum). Passwords use Argon2id hashes.
2. **LAN access.** The server already accepts private IP addresses. Optionally supply extra local DNS origins such as `http://switchyard.lan:9791` or `http://ops.home.arpa:9791`.
3. **Remote access.** Optionally enter the exact HTTPS hostname to use in your reverse proxy (for example `https://switchyard.example.com`). It is stored in SQLite, not a file or environment variable. Remote HTTPS sign-in initially uses the administrator password. Optional TOTP can be enrolled from **Settings → Two-factor authentication**; once enabled, all HTTPS proxy sessions require the authenticator code.

After first-run completion, use **Settings → Browser and network access** to update trusted LAN aliases, your HTTPS hostname, and the optional trusted-LAN HTTP Vaultwarden exception. Saving requires the current admin password and revokes other sessions. Settings apply without a container rebuild or restart.

### Where configuration actually lives

| Item | Storage | Edited through |
| --- | --- | --- |
| Admin username and Argon2id password hash | `/data/switchyard.sqlite3` | First-run wizard; password change in Settings |
| Browser origins, HTTPS proxy domain, Vaultwarden HTTP exception | SQLite settings table | First-run wizard; Settings |
| TOTP encrypted enrollment | SQLite users table | Settings |
| TOTP encryption key | `/data/mfa.key` (mode `0600`) | Generated and maintained internally; never enter manually |
| SSH assets, desktops, runbooks, audit, health observations | SQLite | Relevant workspaces |
| SSH keys, SSH host trust, Bitwarden CLI runtime files | `/data/keys`, `/data/known_hosts`, `/data/bw` | Relevant workspaces |
| Machine folders and encrypted saved passwords | SQLite (`folders`, `saved_passwords`) + `/data/credentials.key` | Machine editor / folders |
| In-app updater executor | SQLite settings | Settings → Software updates |

**The `/data` Docker named volume is required for persistence.** Never use `docker compose down -v` during upgrades or normal maintenance. A container/image replacement does not reset settings when the volume is preserved.

## Machine workspace (v0.5.3-dev.5)

The Machines directory is now the primary navigation destination. The host-first workspace presents a persistent machine switcher and one compact machine header, followed by **Overview, Terminal, Remote desktop, Files, Docker and Health** tabs. These tabs reuse existing SSH, SFTP, Docker, remote desktop and agentless health APIs, preserving machine records and credentials in the Docker volume. Available connection rows open SSH or the matching RDP/VNC/SPICE session directly; the Terminal tab provides a new-session / reconnect action and clear connection states. Non-SSH machines keep their desktop access without misleading file, Docker or health controls.

At ≤920px, the machine switcher becomes a horizontally scrollable strip; at ≤660px, the header and actions reorganize for touch and small screens. All machine tabs are keyboard accessible (arrow keys, Home, End), with visible focus and reduced-motion support.

The machine-specific workspace rules are in `static/workspace.css`, loaded after the existing product stylesheet. The UI does not claim that a machine is live or healthy until a real connection or host check has succeeded.

## Features

| Workspace | Capabilities |
| --- | --- |
| Machines | Persistent host inventory, nested folders, environment categories, unified host workspaces and connection shortcuts |
| SSH terminals | Per-machine browser terminal, tabs, resizing, managed keys, optional tmux reattachment |
| File manager | Inside each SSH machine profile: SFTP browse/upload/download/rename/delete, folder creation, atomic text editing with conflict detection |
| Docker | Inside each SSH machine profile: container lists, start/stop/restart, inspect, stats, logs, images, volumes, networks and Compose projects |
| Remote desktops | Browser RDP/VNC through isolated `guacd`; SPICE via isolated viewer, direct hosts and ephemeral Proxmox/QEMU `.vv` consoles |
| Assets | Named hosts, favorites, environments, tags/notes and credential modes |
| Runbooks | Saved SSH commands, explicit confirmation, bounded execution, persistent execution outcome history |
| Health | Inside each SSH machine profile: on-demand Linux metrics, uptime, load, memory, disk and observation history |
| Vaultwarden | Located under Settings → Integrations; Bitwarden CLI login, sync, unlock/lock, and credential retrieval |
| Saved credentials | SSH and RDP/VNC/SPICE passwords may be encrypted in `/data` using Fernet. Cleartext is never sent back in inventory responses |
| Updater | Settings → Software updates: configure an SSH-based executor for a specific Docker Compose project; explicit admin reauthentication and log inspection |
| Security | SSH host-key trust, optional TOTP for HTTPS proxy, session controls, CSRF origin verification, activity journal |
| Backups | Consistent database snapshot, host trust, and TOTP recovery key with SHA-256 manifest (sensitive backup) |

## Reverse proxy and MFA

1. Optional: from the trusted LAN URL, sign in and enroll an authenticator under **Settings → Two-factor authentication**. Enter your administrator password, scan or copy the presented authenticator secret, then confirm with the current six-digit code.
2. Under **Settings → Browser and network access**, enter your actual public **HTTPS origin**. Do not put the public hostname in LAN aliases. No source config edits or restart are required.
3. In Nginx Proxy Manager, set an HTTPS Proxy Host forwarding to `http://YOUR-DOCKER-HOST-LAN-IP:9791`. Enable **WebSockets Support**, a valid TLS certificate, **Force SSL**, and preserve the original public `Host` header. Reject unmatched hostnames at the proxy.
4. Open your HTTPS domain and sign in with **username + password**, plus TOTP **only if you enabled it**. A LAN login is not accepted as a remote HTTPS session because separate origin-scoped cookies are used.

Equivalent nginx location directives:

```nginx
proxy_pass http://YOUR-DOCKER-HOST-LAN-IP:9791;
proxy_http_version 1.1;
proxy_set_header Host $http_host;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-Proto https;
proxy_read_timeout 3600s;
```

**Security boundary:** Public-origin classification is based on exact configured `Host` and browser `Origin`; forwarding to it requires an HTTPS reverse proxy that **rejects unknown hostnames**. Never publicly forward TCP 9791. Docker-published host ports may bypass simplistic UFW rules, so test effective host firewall/DOCKER-USER policy. Host-IP LAN connections also require a private source IP (direct WAN attempts are rejected), then use password authentication; public-host sessions require MFA only when the administrator enabled it. SSH and desktop WebSockets enforce the same authentication rules.

## Upgrading existing installations

```bash
cd switchyard
git pull --ff-only origin main
./scripts/deploy.sh
./scripts/smoke-test.sh
```

For an older `.env`/Docker-secret based Switchyard installation, `./scripts/deploy.sh` attempts to migrate the existing MFA encryption key from the **currently running old container** into `/data/mfa.key` *before* recreating it. This preserves existing TOTP secrets. Keep the old container available for the migration. **If the original key is missing and MFA was previously enrolled, remote authentication is intentionally blocked** rather than silently generating an incompatible replacement key. Back up the volume before upgrading. Existing users and their password hashes remain unchanged, and network addresses can be re-entered in the UI. Old `.env` and `secrets/` files are no longer consulted; remove them securely only after validating the upgrade and rollback plan.

### Backup and recovery

**Settings → Download consistent backup** exports SQLite (excluding live sessions), `known_hosts`, `mfa.key` when enrolled, and `credentials.key` when present, plus a SHA-256 manifest. **The backup contains password hashes, and potentially TOTP and saved-password decryption keys. Treat it as a sensitive credential archive: encrypt it at rest and do not share it.** This is not a full disaster-recovery archive: SSH private keys and Vaultwarden CLI state are not included, and they must be backed up independently from the Docker volume if required. Restore only with the container stopped and file ownership/permissions preserved (UID/GID 10001). Never overwrite live WAL files.

## Security and limitations

- Switchyard is a **single-administrator development release**. Multi-user RBAC, SSO, mandatory MFA on every LAN login, and comprehensive production security review remain outstanding.
- The application uses separate HTTP- and HTTPS-origin cookies. When optional TOTP is enabled, public HTTPS sessions require it, with replay prevention and rate limiting. Enrollment and policy changes are LAN-only.
- RDP/VNC translation runs in a private `guacd` network; the SPICE viewer uses a separate authenticated WebSocket proxy. Neither private gateway port is published on the Docker host.
- Managed Docker operations occur over SSH against configured hosts. The Switchyard container **does not mount `/var/run/docker.sock`** and is not privileged.
- Live Windows RDP, third-party VNC, SPICE/QEMU/Proxmox, Vaultwarden API key login, and full browser UI workflows require testing on your own systems. A passing mocked API test or image build is not a real hardware acceptance test.
- Initial setup claim codes appear in **Docker logs**: protect Docker daemon access, rotate the code by restarting an unconfigured container, and treat anyone with Docker admin as already privileged.

## Development and verification

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q
node --check static/app.js
node --check static/spice-view.js
bash -n scripts/deploy.sh
```

Continuous integration: [source tests and Docker browser-runtime build](https://github.com/gigabytegrove/switchyard/actions/workflows/ci.yml). The source package alone does not include downloaded third-party Guacamole/xterm/SPICE browser assets; the Dockerfile installs them.

---

**Switchyard** is independent software. It is not affiliated with Nexterm, Apache Guacamole, Bitwarden or Vaultwarden. Apache Guacamole and SPICE HTML5 retain their respective upstream licenses. No production-ready claim is made for this development build.

## Visual identity — signal desk

Switchyard uses a light operational workstation layout inspired by an airport operations board: white (`#FFFFFF`) and mist (`#F5F6F9`), graphite (`#202027`) typography, signal red (`#B72237`) actions, violet (`#5934AC`) secondary indicators. Navigation is horizontal and split between operational and administrative workspaces. Headings use a bold condensed sans-serif, data uses monospace. Flat separators replace the prior green/tan cards. The change is visual only; asset IDs, URLs, permissions, and data layout are preserved.

**MFA policy:** Off by default. No credential, QR, or TOTP entry is required during initial setup. HTTPS proxy sign-in requires the administrator password; once the administrator explicitly enables TOTP in Settings and confirms a scanned code, HTTPS sign-in additionally requires TOTP. Internal LAN sign-ins remain password-only.
