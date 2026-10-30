# 0.5.4-dev.1 (2026-10-30)

- Add portable, password-free SSH machine and nested-folder JSON import/export with strict validation, conflict rejection and atomic SQLite commits.
- Add dedicated connection workspace import/export controls and transaction/secret-redaction regression tests.
- Expand SFTP with remote regular-file copy, no-overwrite, mode preservation, chmod, move-path controls, symlink/permission listing, and multi-file uploads with failure reporting.
- Add API safety regressions for copy, chmod, symlinks, and duplicate targets.

## 0.5.3-dev.6 — interactive first-use SSH host trust

- Automatically discover unknown SSH host identity on Connect, show an explicit SHA-256 fingerprint confirmation dialog (host, port, algorithm), and retry in the same terminal tab only after approval.
- Cancel/Escape leave the host untrusted; host-key changes remain blocked pending independent verification.
- Provide typed WebSocket errors for unknown and changed keys. No data reset or credential migration.
- Test first-connection approval, refusal and key changes against shipped handlers, plus unknown-host errors against a real OpenSSH server.

## 0.5.3-dev.5 — restore real network WebSocket connections

- **Root-cause fix:** The Docker image installed bare `uvicorn` without any Python WebSocket protocol implementation. HTTP health/setup worked while the browser terminal WebSocket upgrade failed before SSH authentication.
- Install pinned `websockets==16.0` in the actual runtime image. This enables Uvicorn's WebSocket ASGI protocol for SSH terminals and Guacamole tunnels.
- Add a true TCP-network acceptance test against the built, running Docker Compose container: first-run login, authorized WebSocket HTTP 101 upgrade, WebSocket auth message handling and unauthenticated rejection. Unlike TestClient, this catches missing protocol packages.
- Make pre-upgrade failures distinguishable from an established SSH transport failure.
- Preserve machine folders, stored credentials, host trust, UI layout and the original persistent volume. No manual migration.

## 0.5.3-dev.4 — stop replaying rejected SSH passwords

- Fix endless SSH login failures caused by caching a rejected temporary password and silently reusing it during reconnect.
- After an authentication rejection, the same terminal tab now explicitly prompts for a replacement password. It no longer traps users behind a stale encrypted saved credential.
- Successful one-time override takes precedence over the stored password for the current login session; saving a replacement remains a deliberate edit-machine action.
- Signal a distinct terminal-WebSocket authentication error and an explicit connected state. Suppress generic transport errors when an actionable SSH error has already arrived.
- Invalidate rejected SSH passwords during SFTP, Docker and health API operations as well.
- Add browser regression and real OpenSSH regression for bad saved password, successful supplied override, and typed WebSocket authentication failures.
- Preserve the two-pane layout, existing machine records, trusted host keys, saved secrets and Docker volume; no migration.

## 0.5.3-dev.3 — real SSH/SFTP integration qualification

- Fix actual Paramiko SFTP failures: exclusive-create mode `x` does not provide write access; use `wx` for both file upload and atomic editor staging. The previous mocked editor test failed to check the writable flag and has been corrected.

- Add a live OpenSSH test target to GitHub Actions source validation (loopback-only, non-production credentials).
- Verify unknown SSH hosts are rejected, independently corroborate an Ed25519 host fingerprint, explicitly trust the key, authenticate using a saved encrypted password, and execute a real SSH command.
- Exercise real SFTP listing, exclusive upload and download, and an authenticated interactive SSH WebSocket terminal against the disposable server.
- Run the integration test under a hard timeout. Existing Docker/runtime and machine configurations remain unchanged.

## 0.5.3-dev.2 — connection reliability and workbench corrections

- Reconnect an SSH session in its original tab using a fresh WebSocket, preserving terminal history and registering input/resize listeners exactly once. New session remains explicit and separate.
- Selecting an already active RDP/VNC/SPICE connection focuses it. Retry replaces a failed or disconnected desktop after obtaining a fresh ticket rather than stacking another tab.
- Add a remote desktop Reconnect control, and a machine-scoped Host trust action that pre-fills the currently selected SSH host and port.
- Return actionable, sanitized SSH failure reasons (host trust, key change, authentication, DNS, connection refused, timeout, protocol negotiation) to the terminal browser.
- Add executable connection/session regression tests. Preserve existing Compose project, credentials, machine folders, database and remote-access UI design.

## 0.5.3-dev.1 — operator workspace refinement

- Resize the connection tree from 196 to 440 pixels using mouse/pointer, accessible arrow keys and Home/End; double-click resets.
- Preserve collapsed folder state and preferred width in safe local browser preferences, without changing credentials or data models.
- Provide Ctrl/Cmd+K and / connection search, Escape handling, keyboard tree navigation and sorted inventory.
- Replace the cramped mobile tree/terminal split with an accessible slide-in directory and full-width session canvas.
- Keep SSH sessions visible when reopening an active machine; gracefully fall back to Connections after the last session closes.
- Improve session status, errors, middle-click tab closing, focus indication and concise connection launcher guidance.
- Preserve the Signal Desk red/graphite identity and existing Docker volume, APIs and machine records.
- Add executable JavaScript interaction regression checks alongside backend and Compose tests.

## 0.5.3-dev.1 — repair machine navigation crash

- Fix the single-element selector incorrectly used as a NodeList when navigating between machines, Runbooks and Files.
- Add an executable DOM navigation regression test, verifying navigation active states and selected-host Files context; confirm it rejects the original `$(...).forEach is not a function` error.
- No database, connection, credential, or external configuration changes.

## 0.5.3-dev.1 — two-pane connection manager and official branding

- Replace the large machine profile with a permanent folder tree on the left and connection workspace on the right.
- Shared SSH/RDP/VNC/SPICE session tab strip, keyboard navigation, close actions, machine selection, and details inspector.
- Move Files, Docker and Health into global navigation with the selected machine propagated to those workspaces.
- Integrate the supplied transparent red/silver SwitchYard wordmark, compact symbol and favicon.
- Preserve existing SQLite records, encrypted credentials and Docker data volume; no external configuration.
- Add browser-workbench tests; live remote-target interoperability remains to be qualified.

## 0.5.3-dev.1 — machine workspace refinement

- Replaced the nested, duplicate-title machine pages with a contextual two-column console: machine switcher, machine identity, explicit connection actions, and machine-scoped operational tabs.
- Rebuilt Overview around factual connection inventory, SSH/desktop launch entries, and direct Files/Docker/Health tools. Existing asset folders and desktop records are preserved.
- Reworked terminal presentation with connection state, new-session/reconnect control and per-machine session filtering, preventing unrelated hosts' terminal tabs appearing under the current machine.
- Added accessible tab semantics and Arrow/Home/End keyboard support, responsive 390px navigation, visible focus, and reduced-motion handling.
- Added separate `static/workspace.css` for this machine workspace, keeping the established white/graphite/signal-red identity; removed the misleading gateway-ready copy from the header.
- Verified with mocked Chromium flows at desktop and mobile widths, backend tests, and frontend static/JS checks. Live SSH/RDP/VNC/SPICE remains unverified.

## 0.5.3-dev.1 — fix remote connection failures over LAN HTTP

- Fix Chromium `crypto.randomUUID is not a function` on private, plain-HTTP LAN origins. Use `crypto.getRandomValues` to produce RFC 4122 version-4 session IDs without downgrading randomness.
- Apply the correction to SSH terminals, Guacamole RDP/VNC sessions, SPICE sessions, and imported virt-viewer console sessions.
- Add actual Chromium insecure-origin regression coverage, plus repeatability and identifier-format checks. Protect the new test in CI.
- Preserve all existing machines, saved credentials, databases, proxy settings, and Docker volumes. No migration or reset is required.
- This fixes a browser-side connection blocker; live remote protocol operation still requires end-to-end verification.

## 0.5.1-dev.1 — machine-centric operations and integrated administration

- Replace disconnected SSH/desktop/file/Docker/health navigation with a single machines inventory and host profiles containing Overview, Terminal, Remote Desktop, File Transfer, Docker and Health tabs.
- Add persisted nested machine folders and environment filtering without losing existing SSH or desktop records. Group desktop-only hosts with SSH profiles by normalized host identity.
- Add opt-in encrypted SSH and desktop passwords stored in SQLite ciphertext under a permission-restricted `/data/credentials.key`; never return plaintext through listing/export. Retain or clear saved secrets explicitly.
- Replace browser `prompt()` / `confirm()` use with native application dialogs for credential entry, input, confirmation and remote operation safety. Keep transient unsaved SSH credentials in browser memory until logout.
- Move Vaultwarden into Settings → Integrations, and hide the MFA login field when the login policy does not require it.
- Add Settings → Software updates with operator-configured SSH-to-Docker Compose executor, password reauthentication, detached update job and recoverable log view. No Docker socket mount. Automated rollback not yet available.
- Include encrypted credential recovery key in protected backup bundles when present. Add source tests for folders, credential confidentiality, MFA visibility, and updater authorization and command safety.
- **Development**: Backend/API tests and mocked browser controls verified; live protocol sessions, Docker image build and an actual self-update still require qualification.

## 0.5.0-dev.2

- Fixed unintended mandatory remote MFA: HTTPS proxy access works with password alone until MFA is explicitly enrolled. Existing enabled MFA remains enforced.
- Added QR-code enrollment to Settings, rendered server-side without uploading authenticator secrets to third parties.
- Replaced forest/tan editorial presentation with a signal-red and graphite horizontal operations workbench; kept data models and workflows unchanged.
- Added regression tests covering optional MFA, enrollment QR, enabled MFA challenges, and session separation.
- Build and publish a separately versioned development container image after CI verification.

# Switchyard changes

## 0.5.0-dev.1 — container-owned first-run configuration and LAN/proxy policy (2026-10-28)

- Replace `.env`, external admin secrets, MFA key mounts and Compose variable interpolation with a first-run web wizard protected by a one-time log-only claim code.
- Store admin account, allowed LAN DNS browser origins and exact HTTPS reverse-proxy hostname in the persistent SQLite database; automatically maintain `/data/mfa.key` with restricted permissions.
- Make LAN binding `0.0.0.0:9791` without SSH tunneling; require password on LAN, with opt-in MFA on the configured public HTTPS hostname, including terminal/desktop WebSocket checks.
- Add authenticated LAN-only network settings editor requiring admin password, applying changes without restart and revoking other sessions.
- Migrate preexisting Docker-secret MFA key from running old container before Compose recreation; fail closed when previously enrolled key material is missing.
- Reject public-source connections masquerading as private LAN Host addresses; include TOTP decryption key (only when present) in sensitive backup ZIP for recovery, with manifest and clear warnings; continue excluding SSH private keys and Vaultwarden CLI cache.
- Add repository README workflow badge, version, deployment, protocol, and status badges, new install/upgrade guidance, and quality tests.
- Correct Docker build: Debian bookworm `spice-html5=0.3.0-2` installs assets directly in `/usr/share/spice-html5/` (not `/src`); source CI caught the previous incorrect image path.
- Development release; no hardware/proxy end-to-end acceptance claimed.

## 0.4.0 — RDP, VNC and SPICE remote desktops (2026-10-28)

- Private `guacd:1.6.0` gateway for RDP/VNC with authenticated WebSocket relay and packaged Guacamole browser client.
- Integrated multi-tab desktops UI with keyboard, pointer, scaling, clipboard controls, disconnect and adaptive layout.
- SPICE via isolated `spice-html5` viewer, authenticated multi-channel binary proxy, TCP/TLS transport, HTTP CONNECT and ephemeral `.vv` import for Proxmox/QEMU.
- Persistent desktop target CRUD, favorites, duplication, secret-free JSON export and safe bulk import.
- Network reachability checks, gateway health, connection history, CSV export and administrator session controls.
- Credential-bearing tickets bound to sessions with expiry; cross-origin rejections, activity limits and audit records.
- Container build fails fast when essential RDP/VNC/SPICE browser runtime files are unavailable.
- Integration with existing Vaultwarden credentials where supported; no plaintext vault passwords in desktop inventory.
- Verified by mocked API/protocol tests and static checks; a real guacd, SPICE or remote desktop server was **not** exercised.


## 0.3.0 — remote operations and persistent workflows (2026-10-28)

### NEW — Managed runbooks
- Create, edit, delete and list alphabetical reusable SSH shell procedures; command text and human notes persist in SQLite.
- Explicit approval gate before execution when selected in template; server refuses missing required confirmation.
- Reuses asset SSH authentication and host-key trust; enforces 30-second remote execution deadline and combined 256 KiB output ceiling.
- Drains stdout and stderr safely and closes SSH channel/client on exit or error.
- Outcome, target, duration, exit code and execution time persist in history; output and session SSH password do not.
- Responsive Runbooks workspace integrated with Switchyard navigation, edit/run/delete, targeted host selection and history.

### NEW — Agentless Linux health history
- Run fixed SSH-based Linux system inspection to collect uptime, 1/5/15-minute load, RAM and root filesystem capacity.
- Parse/validate results; expose current observations and history API; persist success/failure records, prune to 500 per asset.
- Render readable health metrics and recent status history in an independent workspace.

### NEW — SFTP text editor
- UTF-8 regular files up to 256 KiB; detect binary and invalid text.
- Read original SHA-256, verify original before and after writing a temporary file, preserve mode and atomically swap via OpenSSH posix-rename.
- Reject changed-file conflicts (409) and unsupported atomic replacement (501), with cleanup on failure.
- Integrated edit action from remote file rows with modal editor, save confirmation, error/loading feedback.

### NEW — Docker Compose stacks
- Discover remote Compose V2 projects over the existing SSH mechanism.
- Start, stop and restart existing stacks; only allow a project confirmed in live remote inventory, validated project name and shell-quoted absolute configuration paths.
- Multi-config (up to eight) projects supported; UI adds a dedicated Stacks view and explicit confirmation.

### FIXED — upgrade and contracts
- Additively initialize new SQLite tables without deleting old assets or settings; no destructive migration.
- Update FastAPI app version, health endpoint, backing ZIP manifest, Compose image tag and UI edition marker.
- Add static DOM ID contract test and expanded mocked API tests.

### VERIFICATION
- **24 passed, 1 skipped** (Paramiko-dependent host-key test skipped locally).
- Python compile, JavaScript syntax, DOM selector linkage, real local Linux health command and local HTTP health endpoint checked.
- Docker image build, remote servers, Vaultwarden integration and browser rendering not verified; headless Chromium was blocked by policy.

### UPGRADE
- Replace v0.2 source inside the **existing** Compose project directory, preserving `.env`, admin secret and volume; back up first, rebuild/restart. New DB tables created automatically. No `down -v`.

## 0.2.0 — substantial operations pass (2026-10-28)

### NEW — Remote Docker operations
- Explicit remote Engine summary with version, host, container counts, image count, CPU count.
- Container details: normalized health, state, restart policy, start/exit time, safe network and published-port fields.
- One-shot CPU, memory, network/block I/O, and process usage from `docker stats`.
- Up to 500 lines of timestamped log tail, bounded to 1 MiB.
- Read-only image, network and volume inventories, all routed through the asset's verified SSH path; no host socket mount.
- Inline details UI retaining the existing Switchyard visual language, responsive log console and state handling.

### NEW — SSH key lifecycle
- Server-generated Ed25519 OpenSSH private keys and one-time public key provisioning instructions.
- Import validated unencrypted RSA/ECDSA/Ed25519 private keys (16 KiB cap, exclusive file creation).
- Managed listing/public-key copy/assigned-assets count, permanent deletion prevented for assigned keys.
- Persistent restricted key directory, private keys never returned through read API.

### NEW — Backups and audit review
- Live, WAL-consistent SQLite ZIP snapshot with SHA-256 manifest, session redaction, trusted host keys.
- Explicit exclusion of private SSH keys, Vaultwarden cache and bootstrap credentials.
- Audit filtering, ID pagination and CSV export with spreadsheet-formula injection mitigation.

### FIXED — Host identity and reliable file writes
- Refuse silently replacing an existing trusted SSH host key with a new key of the same algorithm.
- Explicit host-key revocation requiring exact current fingerprint match; rebuild key inventory instead of modifying Paramiko SubDict view.
- Atomic file replacement for host-key list updates; raw private keys not exposed in Docker inspect responses.
- Drain Docker remote command stdout/stderr concurrently, bounding output sizes.
- Correct WAL backup finalization/checkpoint so exported snapshots have no active sessions.

### VERIFICATION
- **15 tests passed, 1 skipped** locally (Paramiko-dependent host-key integration test skipped because the dependency was not installed in the execution environment).
- Static Python and JavaScript checks passed. Selenium/Playwright browser pass blocked by administrator policy. Docker image build and live remote integrations not executed.

### UPGRADING
- Replace source in the original Compose deployment directory (not a new differently named Compose project), preserve `.env`, secrets and existing named volume, rebuild and restart. No application database schema change required.

## 0.1.0 — initial developer release (2026-10-28)
- Self-hosted Compose deploy, SSH xterm sessions, tmux support, persistent SQLite assets/audits, SFTP, remote Docker start/stop/restart, Vaultwarden CLI integration, single-admin authentication and known-host verification.
- Eleven backend API tests passed; image build and remote integrations were unverified.
