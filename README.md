<div align="center">

# Switchyard

**Your infrastructure. One control room.**

Self-hosted SSH, SFTP, Docker operations and remote desktops (RDP, VNC, SPICE), with optional Vaultwarden credentials.

[![Source tests and Docker build](https://github.com/gigabytegrove/switchyard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gigabytegrove/switchyard/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-0.5.0--dev.1-CB562E)
![Docker](https://img.shields.io/badge/deployment-Docker-263C36?logo=docker)
![Protocols](https://img.shields.io/badge/desktops-RDP%20%7C%20VNC%20%7C%20SPICE-2E7362)
![Status](https://img.shields.io/badge/status-development-orange)

[Quick start](#quick-start) · [Setup wizard](#first-run-setup) · [Features](#features) · [Reverse proxy and MFA](#reverse-proxy-and-mfa) · [Upgrades](#upgrading-existing-installations) · [Security](#security-and-limitations)

</div>

> **Development build, not production-certified.** Source tests and selected deployment contracts can pass without proving live SSH/RDP/VNC/SPICE connectivity or complete hypervisor/OS compatibility. Restrict the host TCP 9791 port to your LAN, and do not expose it directly to the public Internet.

## Quick start

Prerequisites: Linux Docker Engine and the Docker Compose v2 plugin. No `.env`, secrets files, SSH tunnel, CLI password generation, or database editing is required. The Compose deployment consumes prebuilt images and does not need a Docker build context.

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

**Image distribution:** The standard deployment pulls `ghcr.io/gigabytegrove/switchyard:0.5.0-dev.1` and a pinned community-built Guacamole 1.6.0 daemon image from GHCR; it does not contact Docker Hub during deployment. The image build still downloads third-party artifacts in GitHub Actions. All application configuration is written from the browser to the existing persistent `switchyard_data` Docker volume at `/data`.

## Deploying through a raw Docker Compose panel

For systems that accept a pasted Compose document rather than a source checkout, paste the repository's [`compose.yaml`](compose.yaml) directly. It uses **only `image:` references**, no `build:`, no `.env`, and no bind-mounted source code. Keep the same Compose project identity across redeployments so the named data volume survives. Port `9791` must be limited to your trusted LAN; `guacd` has **no** published port. The application image must be publicly readable from GHCR (verify with `docker manifest inspect ghcr.io/gigabytegrove/switchyard:0.5.0-dev.1`).

The Guacamole daemon image is a **third-party rebuild** hosted on GHCR, not Apache's official Docker Hub image. It is pinned to a published digest and the publisher provides signed provenance, but live RDP/VNC interoperability still needs acceptance testing. See [registry recovery notes](docs/registry-recovery.md).

## First-run setup

1. **Claim the appliance.** Enter the one-time bootstrap code emitted in the container logs. This code changes each time an unconfigured container restarts and is invalidated after setup. Choose an administrator username and password (14-character minimum). Passwords use Argon2id hashes.
2. **LAN access.** The server already accepts private IP addresses. Optionally supply extra local DNS origins such as `http://switchyard.lan:9791` or `http://ops.home.arpa:9791`.
3. **Remote access.** Optionally enter the exact HTTPS hostname to use in your reverse proxy (for example `https://switchyard.example.com`). It is stored in SQLite, not a file or environment variable. Remote sign-in is **blocked** until TOTP is enrolled from an authenticated LAN session under **Settings → Two-factor authentication**.

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

**The `/data` Docker named volume is required for persistence.** Never use `docker compose down -v` during upgrades or normal maintenance. A container/image replacement does not reset settings when the volume is preserved.

## Features

| Workspace | Capabilities |
| --- | --- |
| SSH terminals | Browser-based SSH, tabs, dynamic resizing, managed keys, optional tmux reattachment |
| File manager | SFTP browse/upload/download/rename/delete, folder creation, atomic text editing with conflict detection |
| Docker | SSH-based container lists, start/stop/restart, inspect, stats, logs, images, volumes, networks and Compose projects |
| Remote desktops | Browser RDP/VNC through isolated `guacd`; SPICE via isolated viewer, direct hosts and ephemeral Proxmox/QEMU `.vv` consoles |
| Assets | Named hosts, favorites, environments, tags/notes and credential modes |
| Runbooks | Saved SSH commands, explicit confirmation, bounded execution, persistent execution outcome history |
| Health | On-demand Linux metrics, uptime, load, memory, disk and observation history |
| Vaultwarden | Bitwarden CLI backed login, sync, unlock/lock and item-to-connection credential retrieval |
| Security | SSH host-key trust, TOTP for HTTPS proxy, session controls, CSRF origin verification, activity journal |
| Backups | Consistent database snapshot, host trust, and TOTP recovery key with SHA-256 manifest (sensitive backup) |

## Reverse proxy and MFA

1. From the trusted LAN URL, sign in and enroll an authenticator under **Settings → Two-factor authentication**. Enter your administrator password, scan or copy the presented authenticator secret, then confirm with the current six-digit code.
2. Under **Settings → Browser and network access**, enter your actual public **HTTPS origin**. Do not put the public hostname in LAN aliases. No source config edits or restart are required.
3. In Nginx Proxy Manager, set an HTTPS Proxy Host forwarding to `http://YOUR-DOCKER-HOST-LAN-IP:9791`. Enable **WebSockets Support**, a valid TLS certificate, **Force SSL**, and preserve the original public `Host` header. Reject unmatched hostnames at the proxy.
4. Open your HTTPS domain and sign in with **username + password + TOTP**. A password-only LAN session is not valid through the remote hostname.

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

**Security boundary:** Public-origin classification is based on exact configured `Host` and browser `Origin`; forwarding to it requires an HTTPS reverse proxy that **rejects unknown hostnames**. Never publicly forward TCP 9791. Docker-published host ports may bypass simplistic UFW rules, so test effective host firewall/DOCKER-USER policy. Host-IP LAN connections also require a private source IP (direct WAN attempts are rejected), then use password authentication; public-host sessions always require MFA. SSH and desktop WebSockets enforce the same authentication rules.

## Upgrading existing installations

```bash
cd switchyard
git pull --ff-only origin main
./scripts/deploy.sh
./scripts/smoke-test.sh
```

For an older `.env`/Docker-secret based Switchyard installation, `./scripts/deploy.sh` attempts to migrate the existing MFA encryption key from the **currently running old container** into `/data/mfa.key` *before* recreating it. This preserves existing TOTP secrets. Keep the old container available for the migration. **If the original key is missing and MFA was previously enrolled, remote authentication is intentionally blocked** rather than silently generating an incompatible replacement key. Back up the volume before upgrading. Existing users and their password hashes remain unchanged, and network addresses can be re-entered in the UI. Old `.env` and `secrets/` files are no longer consulted; remove them securely only after validating the upgrade and rollback plan.

### Backup and recovery

**Settings → Download consistent backup** exports SQLite (excluding live sessions), `known_hosts`, and `mfa.key` when enrolled, plus a SHA-256 manifest. **The backup contains password hashes and the TOTP decryption key. Treat it as a sensitive credential archive: encrypt it at rest and do not share it.** This is not a full disaster-recovery archive: SSH private keys and Vaultwarden CLI state are not included, and they must be backed up independently from the Docker volume if required. Restore only with the container stopped and file ownership/permissions preserved (UID/GID 10001). Never overwrite live WAL files.

## Security and limitations

- Switchyard is a **single-administrator development release**. Multi-user RBAC, SSO, mandatory MFA on every LAN login, and comprehensive production security review remain outstanding.
- The application uses separate HTTP- and HTTPS-origin cookies. Public sessions require TOTP, with replay prevention and rate limiting. Enrollment and policy changes are LAN-only.
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
