"""Switchyard: self-hosted SSH/SFTP operations console.

HTTP API is same-origin, single admin, cookie-authenticated. SSH passwords and
Vaultwarden master password are never written to application persistence.
"""
from __future__ import annotations

import asyncio
import hashlib
import csv
import base64
import tempfile
import zipfile
import hmac
import io
import ipaddress
import struct
import json
import os
import re
import secrets
import shlex
import socket
import posixpath
import stat
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from datetime import datetime, timezone
from typing import Annotated, Literal
from . import desktops
from .probes import probe
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Cookie, Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

ROOT = Path(__file__).resolve().parent.parent
DATA = Path('/data')
DB_FILE = DATA / 'switchyard.sqlite3'
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
# Network policy and credentials live in /data; no operator environment configuration.
BOOTSTRAP_CODE: str | None = None
SESSION_TTL = 12 * 3600
MAX_TRANSFER = 64 * 1024 * 1024
LOCK = threading.RLock()
VAULT_LOCK = threading.RLock()
BW_SESSION: str | None = None
FAILED: dict[str, list[float]] = {}

@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_data()
    yield


app = FastAPI(title='Switchyard', version='0.5.11-dev.2', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


def connection():
    db = sqlite3.connect(DB_FILE, timeout=15, isolation_level=None, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    return db


@contextmanager
def dbconn():
    with connection() as db:
        yield db


def init_data():
    DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    with dbconn() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY CHECK(id=1), username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          expires_at INTEGER NOT NULL, mfa_verified INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS assets (
          id TEXT PRIMARY KEY, label TEXT NOT NULL, host TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 22, username TEXT NOT NULL,
          environment TEXT NOT NULL DEFAULT '',
          auth_type TEXT NOT NULL CHECK(auth_type IN ('interactive','vault','key')),
          credential_ref TEXT NOT NULL DEFAULT '', key_file TEXT NOT NULL DEFAULT '',
          use_tmux INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
          actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
          outcome TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS audit_at_idx ON audit(at DESC);
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS folders (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT REFERENCES folders(id),
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS saved_passwords (
          kind TEXT NOT NULL CHECK(kind IN ('ssh','desktop')),
          entity_id TEXT NOT NULL, ciphertext TEXT NOT NULL,
          PRIMARY KEY(kind,entity_id)
        );
        CREATE TABLE IF NOT EXISTS runbooks (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          command TEXT NOT NULL, requires_confirmation INTEGER NOT NULL DEFAULT 1,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          runbook_id TEXT NOT NULL, runbook_name TEXT NOT NULL,
          asset_id TEXT NOT NULL, asset_name TEXT NOT NULL,
          started_at INTEGER NOT NULL, duration_ms INTEGER NOT NULL,
          outcome TEXT NOT NULL, exit_code INTEGER
        );
        CREATE INDEX IF NOT EXISTS run_history_time_idx ON run_history(id DESC);
        CREATE TABLE IF NOT EXISTS host_snapshots (
          id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL,
          at INTEGER NOT NULL, status TEXT NOT NULL, uptime_seconds INTEGER,
          load1 REAL, load5 REAL, load15 REAL,
          memory_total INTEGER, memory_available INTEGER,
          disk_total INTEGER, disk_used INTEGER
        );
        CREATE INDEX IF NOT EXISTS snapshot_asset_idx ON host_snapshots(asset_id, id DESC);
        ''')
        # Additive migration; preserve existing users and sessions.
        for table, column, definition in (
            ('users', 'mfa_secret', 'TEXT'),
            ('users', 'mfa_pending', 'TEXT'),
            ('users', 'mfa_pending_until', 'INTEGER'),
            ('users', 'mfa_last_step', 'INTEGER NOT NULL DEFAULT -1'),
            ('sessions', 'mfa_verified', 'INTEGER NOT NULL DEFAULT 0'),
        ):
            if column not in {r['name'] for r in db.execute(f'PRAGMA table_info({table})')}:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
        if 'folder_id' not in {r['name'] for r in db.execute('PRAGMA table_info(assets)')}:
            db.execute('ALTER TABLE assets ADD COLUMN folder_id TEXT')
        global BOOTSTRAP_CODE
        existing = db.execute('SELECT 1 FROM users LIMIT 1').fetchone()
        if not existing and not BOOTSTRAP_CODE:
            BOOTSTRAP_CODE = '-'.join(secrets.token_hex(4).upper() for _ in range(3))
            print('\nSWITCHYARD FIRST-RUN CLAIM CODE: ' + BOOTSTRAP_CODE + '\n'
                  'Open http://YOUR-LAN-HOST:9791 and enter this code in the setup wizard.\n'
                  'This code is valid only until initial setup completes or this container restarts.\n', flush=True)
        if existing:
            BOOTSTRAP_CODE = None
        db.execute('DELETE FROM sessions WHERE expires_at < ?', (int(time.time()),))
    desktops.initialize(dbconn)
    keys = DATA / 'keys'
    keys.mkdir(exist_ok=True, mode=0o700)
    os.chmod(keys, 0o700)
    bw = DATA / 'bw'
    bw.mkdir(exist_ok=True, mode=0o700)
    os.chmod(bw, 0o700)


def credential_cipher(create: bool = False) -> Fernet:
    path = DATA / 'credentials.key'
    with LOCK:
        if not path.exists():
            with dbconn() as db:
                has_secrets = db.execute('SELECT 1 FROM saved_passwords LIMIT 1').fetchone()
            if has_secrets or not create:
                raise HTTPException(503, 'Saved credential encryption key is missing; restore the original /data volume')
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as dest:
                    dest.write(Fernet.generate_key())
        if path.stat().st_mode & 0o077:
            raise HTTPException(503, 'Saved credential encryption key permissions are unsafe')
        return Fernet(path.read_bytes())


def saved_password(kind: str, entity_id: str) -> str | None:
    with dbconn() as db:
        row = db.execute('SELECT ciphertext FROM saved_passwords WHERE kind=? AND entity_id=?', (kind, entity_id)).fetchone()
    if row is None:
        return None
    try:
        return credential_cipher().decrypt(row['ciphertext'].encode()).decode()
    except InvalidToken:
        raise HTTPException(503, 'Saved credential cannot be decrypted; restore the original encryption key')


def put_saved_password(db, kind: str, entity_id: str, password: str | None, clear: bool = False):
    if clear:
        db.execute('DELETE FROM saved_passwords WHERE kind=? AND entity_id=?', (kind, entity_id))
    elif password:
        secret = credential_cipher(create=True).encrypt(password.encode()).decode()
        db.execute('INSERT INTO saved_passwords(kind,entity_id,ciphertext) VALUES(?,?,?) '
                   'ON CONFLICT(kind,entity_id) DO UPDATE SET ciphertext=excluded.ciphertext',
                   (kind, entity_id, secret))


def audit(action: str, target: str = '', outcome: str = 'ok'):
    with dbconn() as db:
        db.execute('INSERT INTO audit(at, actor, action, target, outcome) VALUES(?,?,?,?,?)',
                   (int(time.time()), 'admin', action[:80], target[:255], outcome[:100]))


def session_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def saved_setting(key: str, default: str = '') -> str:
    with dbconn() as db:
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    return row['value'] if row else default


def configured_remote_origin() -> str:
    return saved_setting('public_origin')


def validate_network(public_origin: str, lan_origins: list[str]) -> tuple[str, list[str]]:
    public_origin = public_origin.strip().rstrip('/')
    if public_origin:
        p = urlsplit(public_origin)
        if (p.scheme != 'https' or not p.hostname or p.username or p.password
                or p.path or p.query or p.fragment or not p.port in (None, 443)):
            raise HTTPException(422, 'Public origin must be an HTTPS hostname without a path or custom port')
        try:
            ipaddress.ip_address(p.hostname)
        except ValueError:
            if '.' not in p.hostname:
                raise HTTPException(422, 'Public origin requires a fully qualified DNS hostname')
        else:
            raise HTTPException(422, 'Use a public DNS hostname for the HTTPS reverse proxy')
    if len(lan_origins) > 8:
        raise HTTPException(422, 'Up to 8 LAN browser origins are supported')
    result = []
    for item in lan_origins:
        value = item.strip().rstrip('/')
        p = urlsplit(value)
        if (p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password
                or p.path or p.query or p.fragment):
            raise HTTPException(422, 'LAN origins must be HTTP(S) origins without paths')
        host = p.hostname.lower()
        try:
            ip = ipaddress.ip_address(host)
            allowed = ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            allowed = ('.' not in host or host.endswith(('.lan', '.local', '.home.arpa', '.internal', '.test')))
        if not allowed:
            raise HTTPException(422, 'LAN DNS aliases must use local-only names, not public domains')
        if public_origin and urlsplit(public_origin).netloc.lower() == p.netloc.lower():
            raise HTTPException(422, 'Public HTTPS origin cannot be a LAN origin')
        if value.lower() not in [x.lower() for x in result]:
            result.append(value)
    return public_origin, result


def private_host(host: str) -> bool:
    if not host or '/' in host or '@' in host or ',' in host or '\\' in host:
        return False
    parsed = urlsplit('http://' + host)
    address = parsed.hostname or ''
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return address == 'localhost'


def private_source(scope) -> bool:
    """Block direct WAN requests masquerading as a private-LAN Host header."""
    try:
        source = ipaddress.ip_address(scope.client.host)
        return source.is_private or source.is_loopback or source.is_link_local
    except (ValueError, AttributeError, TypeError):
        return False


def browser_origin(scope) -> tuple[str, bool]:
    """Classify by exact Host; private-origin access never bypasses public-host MFA."""
    host = (scope.headers.get('host') or '').lower()
    if not host or '/' in host or '@' in host or ',' in host or '\\' in host:
        raise HTTPException(403, 'Untrusted host')
    remote = configured_remote_origin()
    if remote and host == urlsplit(remote).netloc.lower():
        return remote, True
    for lan in json.loads(saved_setting('lan_origins', '[]')):
        if host == urlsplit(lan).netloc.lower():
            if not private_source(scope):
                raise HTTPException(403, 'LAN access requires a private network source')
            return lan, False
    if private_host(host):
        if not private_source(scope):
            raise HTTPException(403, 'LAN access requires a private network source')
        scheme = 'https' if scope.url.scheme in ('https', 'wss') else 'http'
        return f'{scheme}://{host}', False
    raise HTTPException(403, 'Host is not permitted. Add a LAN alias in Settings or configure the HTTPS proxy.')


def valid_session(token: str | None, require_mfa: bool = False) -> bool:
    if not token or len(token) != 64:
        return False
    with dbconn() as db:
        row = db.execute('SELECT mfa_verified FROM sessions WHERE token_hash=? AND expires_at>?',
                         (session_hash(token), int(time.time()))).fetchone()
        if not row:
            return False
        if not require_mfa:
            return True
        # MFA is opt-in. Once enrolled, HTTPS sessions must be independently
        # MFA-verified; prior password-only remote sessions cannot be reused.
        enrollment = db.execute('SELECT 1 FROM users WHERE mfa_secret IS NOT NULL LIMIT 1').fetchone()
        return not enrollment or bool(row['mfa_verified'])


def verify_origin(request: Request) -> bool:
    expected, remote = browser_origin(request)
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        if request.headers.get('origin') != expected:
            raise HTTPException(403, 'Origin validation failed')
    return remote


def require_auth(request: Request, switchyard_session: Annotated[str | None, Cookie()] = None):
    remote = verify_origin(request)
    if not valid_session(switchyard_session, require_mfa=remote):
        raise HTTPException(401, 'Authentication required' if not remote else 'MFA-authenticated session required')
    return 'admin'


def session_from_ws(ws: WebSocket) -> bool:
    try:
        expected, remote = browser_origin(ws)
    except HTTPException:
        return False
    return ws.headers.get('origin') == expected and valid_session(ws.cookies.get('switchyard_session'), require_mfa=remote)


def mfa_cipher() -> Fernet:
    path = DATA / 'mfa.key'
    try:
        if not path.exists():
            with dbconn() as db:
                has_enrollment = db.execute('SELECT 1 FROM users WHERE mfa_secret IS NOT NULL OR mfa_pending IS NOT NULL LIMIT 1').fetchone()
            if has_enrollment:
                raise HTTPException(503, 'MFA encryption key missing; recover /data/mfa.key from the original volume or backup')
            # Open with O_EXCL; two workers cannot replace each other's keys.
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(Fernet.generate_key())
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                path.unlink(missing_ok=True)
                raise
        if path.stat().st_mode & 0o077:
            raise OSError('MFA key file permissions are too permissive')
        return Fernet(path.read_bytes().strip())
    except FileExistsError:
        return Fernet(path.read_bytes().strip())
    except (OSError, ValueError) as exc:
        raise HTTPException(503, 'Persistent MFA encryption key is unavailable') from exc


def totp_step(secret: str, code: str, now: int | None = None) -> int | None:
    if not re.fullmatch(r'[0-9]{6}', code):
        return None
    try:
        key = base64.b32decode(secret, casefold=True)
    except (ValueError, base64.binascii.Error):
        return None
    current = int(time.time() if now is None else now) // 30
    for step in (current, current - 1, current + 1):
        digest = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
        offset = digest[-1] & 15
        value = (struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
        if hmac.compare_digest(f'{value:06d}', code):
            return step
    return None


def decrypted_mfa(value: str) -> str:
    try:
        return mfa_cipher().decrypt(value.encode()).decode('ascii')
    except (InvalidToken, UnicodeError) as exc:
        raise HTTPException(503, 'Stored MFA configuration cannot be decrypted') from exc

class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=4096)
    totp: str = Field(default='', max_length=6)


class InitialSetup(BaseModel):
    claim_code: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=3, max_length=80, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=14, max_length=4096)
    public_origin: str = Field(default='', max_length=255)
    lan_origins: list[str] = Field(default_factory=list)


class NetworkSettings(BaseModel):
    current_password: str = Field(min_length=1, max_length=4096)
    public_origin: str = Field(default='', max_length=255)
    lan_origins: list[str] = Field(default_factory=list)
    allow_http_vault: bool = False


@app.get('/api/setup/status')
def setup_status(request: Request):
    browser_origin(request)
    with dbconn() as db:
        completed = db.execute('SELECT 1 FROM users LIMIT 1').fetchone() is not None
    return {'setup_required': not completed, 'claim_in_container_logs': not completed}


@app.post('/api/setup/complete')
def setup_complete(body: InitialSetup, request: Request):
    global BOOTSTRAP_CODE
    verify_origin(request)
    if browser_origin(request)[1]:
        raise HTTPException(403, 'Initial setup requires a LAN browser origin')
    public, aliases = validate_network(body.public_origin, body.lan_origins)
    ip = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    with LOCK:
        FAILED[ip] = [t for t in FAILED.get(ip, []) if now - t < 300]
        if len(FAILED[ip]) >= 8:
            raise HTTPException(429, 'Too many setup attempts')
        if BOOTSTRAP_CODE is None:
            raise HTTPException(409, 'Already configured or setup code expired; restart the container if not configured')
        if not hmac.compare_digest(body.claim_code.upper(), BOOTSTRAP_CODE):
            FAILED.setdefault(ip, []).append(now)
            raise HTTPException(403, 'Invalid setup claim code')
        with dbconn() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                db.execute('ROLLBACK')
                BOOTSTRAP_CODE = None
                raise HTTPException(409, 'Setup has already completed')
            db.execute('INSERT INTO users(id,username,password_hash,created_at) VALUES(1,?,?,?)',
                       (body.username, HASHER.hash(body.password), int(time.time())))
            db.executemany('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                           [('public_origin', public), ('lan_origins', json.dumps(aliases))])
            db.execute('COMMIT')
        BOOTSTRAP_CODE = None
        FAILED.pop(ip, None)
    audit('setup.completed')
    return {'ok': True, 'login_required': True}


@app.get('/healthz')
def health():
    return {'status': 'ok', 'version': '0.5.11-dev.2'}


@app.get('/api/login/options')
def login_options(request: Request):
    _, remote = browser_origin(request)
    with dbconn() as db:
        row = db.execute('SELECT mfa_secret FROM users WHERE id=1').fetchone()
        enabled = bool(row and row['mfa_secret'])
    return {'mfa_required': bool(remote and enabled)}


@app.post('/api/login')
def login(body: Credentials, request: Request, response: Response):
    verify_origin(request)
    with dbconn() as db:
        if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            raise HTTPException(409, 'Complete the initial setup wizard first')
    ip = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    with LOCK:
        FAILED[ip] = [t for t in FAILED.get(ip, []) if now - t < 300]
        if len(FAILED[ip]) >= 8:
            raise HTTPException(429, 'Too many attempts. Try again later.')
    with dbconn() as db:
        user = db.execute('SELECT id,password_hash FROM users WHERE username=?', (body.username,)).fetchone()
        valid = False
        if user:
            try:
                valid = HASHER.verify(user['password_hash'], body.password)
            except Exception:
                pass
        if not valid:
            with LOCK:
                FAILED.setdefault(ip, []).append(now)
            audit('login', outcome='rejected')
            raise HTTPException(401, 'Invalid credentials')
        remote = browser_origin(request)[1]
        mfa_ok = False
        if remote:
            stored = db.execute('SELECT mfa_secret, mfa_last_step FROM users WHERE id=?', (user['id'],)).fetchone()
            if stored['mfa_secret']:
                step = totp_step(decrypted_mfa(stored['mfa_secret']), body.totp)
                if step is None or step <= stored['mfa_last_step']:
                    with LOCK:
                        FAILED.setdefault(ip, []).append(now)
                    audit('login.mfa', outcome='rejected')
                    raise HTTPException(401, 'Valid 6-digit authenticator code required')
                db.execute('UPDATE users SET mfa_last_step=? WHERE id=?', (step, user['id']))
                mfa_ok = True
        token = secrets.token_hex(32)
        db.execute('INSERT INTO sessions(token_hash,user_id,expires_at,mfa_verified) VALUES(?,?,?,?)',
                   (session_hash(token), user['id'], int(time.time()) + SESSION_TTL, int(mfa_ok)))
    with LOCK:
        FAILED.pop(ip, None)
    response.set_cookie('switchyard_session', token, max_age=SESSION_TTL, httponly=True,
                        secure=browser_origin(request)[0].startswith('https://'), samesite='strict', path='/')
    audit('login')
    return {'ok': True}


@app.post('/api/logout')
def logout(request: Request, response: Response, _=Depends(require_auth)):
    token = request.cookies.get('switchyard_session')
    with dbconn() as db:
        db.execute('DELETE FROM sessions WHERE token_hash=?', (session_hash(token),))
    response.delete_cookie('switchyard_session', path='/', secure=browser_origin(request)[0].startswith('https://'), samesite='strict')
    audit('logout')
    return {'ok': True}


@app.get('/api/me')
def me(_=Depends(require_auth)):
    with dbconn() as db:
        name = db.execute('SELECT username FROM users WHERE id=1').fetchone()['username']
    return {'username': name, 'role': 'administrator'}


class MfaSetupRequest(BaseModel):
    password: str = Field(min_length=1, max_length=4096)


class MfaCodeRequest(BaseModel):
    code: str = Field(pattern=r'^[0-9]{6}$')


class MfaDisableRequest(MfaCodeRequest):
    password: str = Field(min_length=1, max_length=4096)


def check_admin_password(db, password: str) -> bool:
    row = db.execute('SELECT password_hash FROM users WHERE id=1').fetchone()
    try:
        return HASHER.verify(row['password_hash'], password)
    except Exception:
        return False


@app.get('/api/network')
def get_network(_=Depends(require_auth)):
    return {'public_origin': configured_remote_origin(),
            'lan_origins': json.loads(saved_setting('lan_origins', '[]')),
            'allow_http_vault': saved_setting('allow_http_vault') == 'true'}


@app.put('/api/network')
def update_network(body: NetworkSettings, request: Request, _=Depends(require_auth)):
    if browser_origin(request)[1]:
        raise HTTPException(403, 'Change network access settings from the LAN')
    public, aliases = validate_network(body.public_origin, body.lan_origins)
    with dbconn() as db:
        if not check_admin_password(db, body.current_password):
            raise HTTPException(403, 'Current password incorrect')
        db.executemany('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                       [('public_origin', public), ('lan_origins', json.dumps(aliases)),
                        ('allow_http_vault', 'true' if body.allow_http_vault else 'false')])
        db.execute('DELETE FROM sessions WHERE token_hash != ?',
                   (session_hash(request.cookies.get('switchyard_session', '')),))
    audit('network.updated', public or 'LAN only')
    return {'ok': True, 'public_origin': public, 'lan_origins': aliases}


@app.get('/api/mfa/status')
def mfa_status(_=Depends(require_auth)):
    with dbconn() as db:
        enabled = bool(db.execute('SELECT mfa_secret FROM users WHERE id=1').fetchone()['mfa_secret'])
    return {'enabled': enabled, 'remote_origin': configured_remote_origin()}


@app.post('/api/mfa/setup')
def mfa_setup(body: MfaSetupRequest, request: Request, _=Depends(require_auth)):
    if browser_origin(request)[1]:
        raise HTTPException(403, 'Authenticator enrollment is restricted to the LAN')
    with dbconn() as db:
        if not check_admin_password(db, body.password):
            raise HTTPException(403, 'Current password incorrect')
        if db.execute('SELECT mfa_secret FROM users WHERE id=1').fetchone()['mfa_secret']:
            raise HTTPException(409, 'Disable existing MFA before re-enrolling')
        secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')
        db.execute('UPDATE users SET mfa_pending=?, mfa_pending_until=? WHERE id=1',
                   (mfa_cipher().encrypt(secret.encode()).decode(), int(time.time()) + 600))
        username = db.execute('SELECT username FROM users WHERE id=1').fetchone()['username']
    from urllib.parse import quote
    issuer = 'Switchyard'
    uri = f'otpauth://totp/{issuer}:{quote(username)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30'
    import qrcode
    from qrcode.image.svg import SvgPathImage
    qr_svg = qrcode.make(uri, image_factory=SvgPathImage, box_size=6, border=4).to_string()
    qr_data_uri = 'data:image/svg+xml;base64,' + base64.b64encode(qr_svg).decode('ascii')
    audit('mfa.enrollment.started')
    return {'secret': secret, 'otpauth_uri': uri, 'qr_data_uri': qr_data_uri, 'expires_seconds': 600}


@app.post('/api/mfa/enable')
def mfa_enable(body: MfaCodeRequest, request: Request, _=Depends(require_auth)):
    if browser_origin(request)[1]:
        raise HTTPException(403, 'Authenticator enrollment is restricted to the LAN')
    with dbconn() as db:
        row = db.execute('SELECT mfa_pending,mfa_pending_until,mfa_secret FROM users WHERE id=1').fetchone()
        if row['mfa_secret']:
            raise HTTPException(409, 'MFA is already enabled')
        if not row['mfa_pending'] or not row['mfa_pending_until'] or row['mfa_pending_until'] < int(time.time()):
            raise HTTPException(410, 'Enrollment expired; start again')
        step = totp_step(decrypted_mfa(row['mfa_pending']), body.code)
        if step is None:
            raise HTTPException(401, 'Incorrect authenticator code')
        db.execute('UPDATE users SET mfa_secret=mfa_pending,mfa_pending=NULL,mfa_pending_until=NULL,mfa_last_step=? WHERE id=1', (step,))
        # Clear any previously issued sessions; MFA must never be inherited.
        db.execute('DELETE FROM sessions WHERE token_hash != ?', (session_hash(request.cookies.get('switchyard_session', '')),))
    audit('mfa.enabled')
    return {'enabled': True}


@app.post('/api/mfa/disable')
def mfa_disable(body: MfaDisableRequest, request: Request, _=Depends(require_auth)):
    if browser_origin(request)[1]:
        raise HTTPException(403, 'Disable MFA only over a LAN session')
    with dbconn() as db:
        row = db.execute('SELECT mfa_secret,mfa_last_step FROM users WHERE id=1').fetchone()
        if not row['mfa_secret']:
            raise HTTPException(409, 'MFA is not enabled')
        if not check_admin_password(db, body.password):
            raise HTTPException(403, 'Current password incorrect')
        step = totp_step(decrypted_mfa(row['mfa_secret']), body.code)
        if step is None or step <= row['mfa_last_step']:
            raise HTTPException(401, 'Valid unused authenticator code required')
        db.execute('UPDATE users SET mfa_secret=NULL,mfa_pending=NULL,mfa_pending_until=NULL,mfa_last_step=-1 WHERE id=1')
        db.execute('DELETE FROM sessions WHERE token_hash != ?', (session_hash(request.cookies.get('switchyard_session', '')),))
    audit('mfa.disabled')
    return {'enabled': False}


class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(min_length=14, max_length=4096)


@app.post('/api/password')
def change_password(body: ChangePassword, request: Request, _=Depends(require_auth)):
    with dbconn() as db:
        old = db.execute('SELECT password_hash FROM users WHERE id=1').fetchone()['password_hash']
        try:
            verified = HASHER.verify(old, body.current_password)
        except Exception:
            verified = False
        if not verified:
            raise HTTPException(403, 'Current password incorrect')
        db.execute('UPDATE users SET password_hash=? WHERE id=1', (HASHER.hash(body.new_password),))
        db.execute('DELETE FROM sessions WHERE token_hash != ?', (session_hash(request.cookies['switchyard_session']),))
    audit('password.changed')
    return {'ok': True}


HOST_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,252}$')
FILE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}$')


class AssetModel(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    environment: str = Field(default='', max_length=80)
    auth_type: Literal['interactive', 'vault', 'key'] = 'interactive'
    credential_ref: str = Field(default='', max_length=80)
    key_file: str = Field(default='', max_length=120)
    use_tmux: bool = False
    note: str = Field(default='', max_length=500)
    folder_id: str = Field(default='', max_length=36)
    password: str | None = Field(default=None, max_length=4096, repr=False)
    clear_password: bool = False

    @model_validator(mode='after')
    def check_credential(self):
        if self.auth_type == 'vault' and not self.credential_ref:
            raise ValueError('Vaultwarden item ID is required')
        if self.auth_type == 'key' and not self.key_file:
            raise ValueError('Mounted SSH key filename is required')
        return self

    @field_validator('host')
    @classmethod
    def check_host(cls, val):
        if not HOST_RE.fullmatch(val) or '..' in val or val.endswith('.'):
            raise ValueError('Invalid hostname or IP')
        return val

    @field_validator('key_file')
    @classmethod
    def check_key(cls, val):
        if val and not FILE_RE.fullmatch(val):
            raise ValueError('Key file must be a simple filename')
        return val


def asset_as_dict(row):
    asset = dict(row)
    with dbconn() as db:
        asset['has_saved_password'] = bool(db.execute(
            "SELECT 1 FROM saved_passwords WHERE kind='ssh' AND entity_id=?", (asset['id'],)).fetchone())
    return asset


class FolderInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    parent_id: str | None = None

    @field_validator('name')
    @classmethod
    def valid_folder_name(cls, value):
        value = value.strip()
        if not value or '/' in value or '\\' in value or value in ('.', '..'):
            raise ValueError('Invalid folder name')
        return value


@app.get('/api/folders')
def list_folders(_=Depends(require_auth)):
    with dbconn() as db:
        return [dict(row) for row in db.execute('SELECT * FROM folders ORDER BY name COLLATE NOCASE')]


@app.post('/api/folders', status_code=201)
def create_folder(body: FolderInput, _=Depends(require_auth)):
    fid = str(uuid.uuid4())
    with dbconn() as db:
        if body.parent_id and not db.execute('SELECT 1 FROM folders WHERE id=?', (body.parent_id,)).fetchone():
            raise HTTPException(422, 'Parent folder not found')
        if db.execute('SELECT 1 FROM folders WHERE parent_id IS ? AND name=? COLLATE NOCASE',
                      (body.parent_id, body.name)).fetchone():
            raise HTTPException(409, 'A folder with that name already exists here')
        db.execute('INSERT INTO folders(id,name,parent_id,created_at) VALUES(?,?,?,?)',
                   (fid, body.name, body.parent_id, int(time.time())))
    audit('folder.created', fid)
    return {'id': fid}


@app.put('/api/folders/{fid}')
def rename_folder(fid: str, body: FolderInput, _=Depends(require_auth)):
    with dbconn() as db:
        if not db.execute('SELECT 1 FROM folders WHERE id=?', (fid,)).fetchone():
            raise HTTPException(404, 'Folder not found')
        if body.parent_id == fid:
            raise HTTPException(422, 'A folder cannot contain itself')
        parent = body.parent_id
        seen = {fid}
        while parent:
            if parent in seen:
                raise HTTPException(422, 'Folder hierarchy cycle detected')
            seen.add(parent)
            ancestor = db.execute('SELECT parent_id FROM folders WHERE id=?', (parent,)).fetchone()
            if not ancestor:
                raise HTTPException(422, 'Parent folder not found')
            parent = ancestor['parent_id']
        if db.execute('SELECT 1 FROM folders WHERE id!=? AND parent_id IS ? AND name=? COLLATE NOCASE',
                      (fid, body.parent_id, body.name)).fetchone():
            raise HTTPException(409, 'Folder name already exists here')
        db.execute('UPDATE folders SET name=?,parent_id=? WHERE id=?', (body.name, body.parent_id, fid))
    audit('folder.updated', fid)
    return {'ok': True}


@app.delete('/api/folders/{fid}')
def delete_folder(fid: str, _=Depends(require_auth)):
    with dbconn() as db:
        if not db.execute('SELECT 1 FROM folders WHERE id=?', (fid,)).fetchone():
            raise HTTPException(404, 'Folder not found')
        if db.execute('SELECT 1 FROM folders WHERE parent_id=?', (fid,)).fetchone():
            raise HTTPException(409, 'Move or remove child folders before deleting this folder')
        if db.execute('SELECT 1 FROM assets WHERE folder_id=?', (fid,)).fetchone():
            raise HTTPException(409, 'Move machines out of this folder before deleting it')
        db.execute('DELETE FROM folders WHERE id=?', (fid,))
    audit('folder.deleted', fid)
    return {'ok': True}


@app.get('/api/assets')
def list_assets(_=Depends(require_auth)):
    with dbconn() as db:
        return [asset_as_dict(x) for x in db.execute('SELECT * FROM assets ORDER BY environment,label')]



# Portable SSH inventory: never serialize credential material or key bytes.
SSH_INVENTORY_FIELDS = (
    'label', 'host', 'port', 'username', 'environment', 'auth_type',
    'credential_ref', 'key_file', 'use_tmux', 'note', 'folder_id'
)


class SSHInventoryImport(BaseModel):
    format: Literal['switchyard-ssh-v1']
    folders: list[dict] = Field(default_factory=list, max_length=300)
    assets: list[dict] = Field(default_factory=list, max_length=1000)



class SSHBatchProbe(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator('ids')
    @classmethod
    def validate_ids(cls, ids):
        if len(ids) != len(set(ids)):
            raise ValueError('Duplicate machine IDs')
        for aid in ids:
            try:
                uuid.UUID(aid)
            except ValueError as exc:
                raise ValueError('Invalid machine ID') from exc
        return ids


@app.post('/api/assets/probes')
async def ssh_probe_batch(body: SSHBatchProbe, _=Depends(require_auth)):
    targets = [fetch_asset(aid) for aid in body.ids]
    limit = asyncio.Semaphore(4)

    async def check(asset):
        async with limit:
            result = await probe(asset['host'], asset['port'])
            return {'id': asset['id'], 'label': asset['label'],
                    'host': asset['host'], 'port': asset['port'],
                    'reachable': result['reachable'], 'elapsed_ms': result['elapsed_ms'],
                    'message': 'TCP port reachable; SSH identity and authentication not tested'
                    if result['reachable'] else result['message']}
    results = await asyncio.gather(*(check(a) for a in targets))
    audit('ssh.probe.batch', str(len(results)))
    return {'count': len(results), 'results': results}


@app.post('/api/assets/{aid}/probe')
async def ssh_probe_one(aid: str, _=Depends(require_auth)):
    asset = fetch_asset(aid)
    result = await probe(asset['host'], asset['port'])
    audit('ssh.probe', aid, 'success' if result['reachable'] else 'failed')
    return {'id': aid, 'host': asset['host'], 'port': asset['port'],
            'reachable': result['reachable'], 'elapsed_ms': result['elapsed_ms'],
            'message': 'TCP port reachable; SSH identity and authentication not tested'
            if result['reachable'] else result['message']}


@app.get('/api/assets/export')
def export_ssh_inventory(_=Depends(require_auth)):
    with dbconn() as db:
        folders = [dict(row) for row in db.execute(
            'SELECT id,name,parent_id FROM folders ORDER BY name COLLATE NOCASE')]
        records = []
        for row in db.execute('SELECT ' + ','.join(SSH_INVENTORY_FIELDS) +
                              ' FROM assets ORDER BY label COLLATE NOCASE'):
            record = dict(row)
            record['use_tmux'] = bool(record['use_tmux'])
            record['folder_id'] = record['folder_id'] or ''
            records.append(record)
    audit('asset.inventory.exported', str(len(records)))
    return JSONResponse({'format': 'switchyard-ssh-v1', 'folders': folders,
                         'assets': records},
                        headers={'Cache-Control': 'no-store',
                                 'Content-Disposition': 'attachment; filename="switchyard-ssh-inventory.json"'})


@app.post('/api/assets/import')
def import_ssh_inventory(body: SSHInventoryImport, _=Depends(require_auth)):
    # Reject unknown fields rather than silently accepting secrets. Validate the
    # entire document before beginning a transaction so imports cannot half-apply.
    folder_map = {}
    folder_specs = {}
    sibling_names = set()
    for raw in body.folders:
        if not isinstance(raw, dict) or set(raw) - {'id', 'name', 'parent_id'}:
            raise HTTPException(422, 'Invalid SSH inventory folder fields')
        old_id = raw.get('id')
        if not isinstance(old_id, str) or len(old_id) > 36 or not old_id:
            raise HTTPException(422, 'Invalid exported folder ID')
        if old_id in folder_map:
            raise HTTPException(422, 'Duplicate folder ID in inventory')
        try:
            folder = FolderInput.model_validate({
                'name': raw.get('name'), 'parent_id': raw.get('parent_id')})
        except ValueError as exc:
            raise HTTPException(422, 'Invalid exported folder') from exc
        if folder.parent_id is not None and len(folder.parent_id) > 36:
            raise HTTPException(422, 'Invalid exported parent folder')
        folder_map[old_id] = str(uuid.uuid4())
        folder_specs[old_id] = folder
        sibling = (folder.parent_id or '', folder.name.casefold())
        if sibling in sibling_names:
            raise HTTPException(422, 'Duplicate sibling folder names in inventory')
        sibling_names.add(sibling)
    for fid in folder_specs:
        visited = set()
        parent = fid
        while parent:
            if parent in visited:
                raise HTTPException(422, 'Folder hierarchy cycle detected')
            visited.add(parent)
            folder = folder_specs.get(parent)
            if folder is None:
                raise HTTPException(422, 'Inventory references a missing folder')
            parent = folder.parent_id

    imported = []
    unique = set()
    for raw in body.assets:
        if not isinstance(raw, dict) or set(raw) - set(SSH_INVENTORY_FIELDS):
            raise HTTPException(422, 'Unknown or sensitive SSH inventory fields')
        try:
            item = AssetModel.model_validate(raw)
        except ValueError as exc:
            raise HTTPException(422, 'Invalid SSH machine entry') from exc
        if item.folder_id and item.folder_id not in folder_map:
            raise HTTPException(422, 'Machine refers to a missing inventory folder')
        signature = (item.host.casefold(), item.port, item.username, item.label.casefold())
        if signature in unique:
            raise HTTPException(422, 'Duplicate SSH machine entry in inventory')
        unique.add(signature)
        imported.append(item)

    now = int(time.time())
    with LOCK:
        with dbconn() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                if db.execute('SELECT count(*) FROM assets').fetchone()[0] + len(imported) > 5000:
                    raise HTTPException(409, 'SSH machine inventory capacity exceeded')
                for item in imported:
                    if db.execute(
                        'SELECT 1 FROM assets WHERE host=? COLLATE NOCASE AND port=? '
                        'AND username=? AND label=? COLLATE NOCASE',
                        (item.host, item.port, item.username, item.label)
                    ).fetchone():
                        raise HTTPException(409, 'Imported SSH machine already exists; no changes made')
                pending = set(folder_specs)
                while pending:
                    ready = [fid for fid in pending if not folder_specs[fid].parent_id or
                             folder_specs[fid].parent_id not in pending]
                    if not ready:
                        raise HTTPException(422, 'Invalid folder hierarchy')
                    for fid in ready:
                        folder = folder_specs[fid]
                        parent_id = folder_map.get(folder.parent_id) if folder.parent_id else None
                        if db.execute('SELECT 1 FROM folders WHERE parent_id IS ? AND name=? COLLATE NOCASE',
                                      (parent_id, folder.name)).fetchone():
                            raise HTTPException(409, 'Imported folder already exists; no changes made')
                        db.execute('INSERT INTO folders(id,name,parent_id,created_at) VALUES(?,?,?,?)',
                                   (folder_map[fid], folder.name, parent_id, now))
                        pending.remove(fid)
                for item in imported:
                    db.execute('''INSERT INTO assets(id,label,host,port,username,environment,auth_type,
                       credential_ref,key_file,use_tmux,note,created_at,updated_at,folder_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (str(uuid.uuid4()), item.label, item.host, item.port, item.username,
                        item.environment, item.auth_type, item.credential_ref, item.key_file,
                        int(item.use_tmux), item.note, now, now,
                        folder_map.get(item.folder_id) if item.folder_id else None))
                db.execute('COMMIT')
            except Exception:
                db.execute('ROLLBACK')
                raise
    audit('asset.inventory.imported', str(len(imported)))
    return {'ok': True, 'assets_created': len(imported),
            'folders_created': len(folder_map), 'credentials_imported': False}


@app.post('/api/assets', status_code=201)
def create_asset(body: AssetModel, _=Depends(require_auth)):
    aid = str(uuid.uuid4())
    now = int(time.time())
    with dbconn() as db:
        if body.folder_id and not db.execute('SELECT 1 FROM folders WHERE id=?', (body.folder_id,)).fetchone():
            raise HTTPException(422, 'Folder does not exist')
        db.execute('''INSERT INTO assets(id,label,host,port,username,environment,auth_type,
                      credential_ref,key_file,use_tmux,note,created_at,updated_at,folder_id)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                   (aid, body.label, body.host, body.port, body.username, body.environment,
                    body.auth_type, body.credential_ref, body.key_file, int(body.use_tmux),
                    body.note, now, now, body.folder_id or None))
        put_saved_password(db, 'ssh', aid, body.password, body.clear_password)
    audit('asset.created', aid)
    return {'id': aid}


@app.put('/api/assets/{aid}')
def update_asset(aid: str, body: AssetModel, _=Depends(require_auth)):
    with dbconn() as db:
        if body.folder_id and not db.execute('SELECT 1 FROM folders WHERE id=?', (body.folder_id,)).fetchone():
            raise HTTPException(422, 'Folder does not exist')
        cur = db.execute('''UPDATE assets SET label=?,host=?,port=?,username=?,environment=?,
                auth_type=?,credential_ref=?,key_file=?,use_tmux=?,note=?,updated_at=?,folder_id=? WHERE id=?''',
                (body.label, body.host, body.port, body.username, body.environment,
                 body.auth_type, body.credential_ref, body.key_file, int(body.use_tmux),
                 body.note, int(time.time()), body.folder_id or None, aid))
        if cur.rowcount != 1:
            raise HTTPException(404, 'Asset not found')
        put_saved_password(db, 'ssh', aid, body.password, body.clear_password)
    audit('asset.updated', aid)
    return {'ok': True}


@app.delete('/api/assets/{aid}')
def delete_asset(aid: str, _=Depends(require_auth)):
    with dbconn() as db:
        cur = db.execute('DELETE FROM assets WHERE id=?', (aid,))
        if not cur.rowcount:
            raise HTTPException(404, 'Asset not found')
        db.execute("DELETE FROM saved_passwords WHERE kind='ssh' AND entity_id=?", (aid,))
    audit('asset.deleted', aid)
    return {'ok': True}


def fetch_asset(aid: str):
    with dbconn() as db:
        row = db.execute('SELECT * FROM assets WHERE id=?', (aid,)).fetchone()
    if not row:
        raise HTTPException(404, 'Asset not found')
    return dict(row)


@app.get('/api/audit')
def list_audit(limit: int = 100, before: int | None = None, action: str = '',
               outcome: str = '', _=Depends(require_auth)):
    if len(action) > 80 or len(outcome) > 100:
        raise HTTPException(422, 'Invalid audit filter')
    query = 'SELECT * FROM audit WHERE 1=1'
    args: list = []
    if before is not None:
        query += ' AND id<?'
        args.append(max(1, before))
    if action:
        query += ' AND action=?'
        args.append(action)
    if outcome:
        query += ' AND outcome=?'
        args.append(outcome)
    query += ' ORDER BY id DESC LIMIT ?'
    args.append(max(1, min(limit, 500)))
    with dbconn() as db:
        return [dict(x) for x in db.execute(query, args)]


@app.get('/api/audit/export')
def export_audit(_=Depends(require_auth)):
    import io as _io
    with dbconn() as db:
        count = db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]
        if count > 100000:
            raise HTTPException(413, 'Audit export exceeds 100,000 records')
        records = db.execute('SELECT id,at,actor,action,target,outcome FROM audit ORDER BY id DESC').fetchall()
    stream = _io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(('id', 'utc_time', 'actor', 'action', 'target', 'outcome'))
    # Prevent CSV spreadsheet formula injection (including tab/whitespace-prefixed formulas).
    def safe(value):
        value = str(value)
        return "'" + value if value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else value
    for r in records:
        writer.writerow((r['id'], datetime.fromtimestamp(r['at'], timezone.utc).isoformat(),
                         safe(r['actor']), safe(r['action']), safe(r['target']), safe(r['outcome'])))
    audit('audit.exported')
    return Response(stream.getvalue(), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="switchyard-audit.csv"', 'Cache-Control': 'no-store'})


@app.get('/api/backup')
def backup(_=Depends(require_auth)):
    # SQLite's backup API captures a consistent WAL snapshot without stopping the application.
    # Exclude live sessions, private SSH keys and Bitwarden CLI storage intentionally.
    audit('backup.exported')
    import io as _io
    with tempfile.TemporaryDirectory(prefix='switchyard-backup-') as tmp:
        snapshot = Path(tmp) / 'switchyard.sqlite3'
        from contextlib import closing
        with dbconn() as source, closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination)
            destination.execute('DELETE FROM sessions')
            destination.commit()
            destination.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            destination.execute('PRAGMA journal_mode=DELETE')
        content = snapshot.read_bytes()
        if len(content) > 32 * 1024 * 1024:
            raise HTTPException(413, 'Database snapshot exceeds 32 MiB backup limit')
        trusted = DATA / 'known_hosts'
        hosts = trusted.read_bytes() if trusted.is_file() else b''
        if len(hosts) > 1024 * 1024:
            raise HTTPException(413, 'Host key inventory too large')
        keyfile = DATA / 'mfa.key'
        mfa_key = keyfile.read_bytes() if keyfile.is_file() else b''
        if mfa_key and (len(mfa_key) != 44 or keyfile.stat().st_mode & 0o077):
            raise HTTPException(503, 'Stored MFA key has invalid format or permissions')
        with dbconn() as source:
            saved_exists = bool(source.execute('SELECT 1 FROM saved_passwords LIMIT 1').fetchone())
        credkey = DATA / 'credentials.key'
        credentials_key = credkey.read_bytes() if credkey.is_file() else b''
        if saved_exists and not credentials_key:
            raise HTTPException(503, 'Encrypted saved passwords exist but the recovery key is missing')
        if credentials_key and (len(credentials_key) != 44 or credkey.stat().st_mode & 0o077):
            raise HTTPException(503, 'Saved credentials key format or file permissions are unsafe')
        manifest = {
            'application': 'Switchyard', 'format': 2, 'version': '0.5.11-dev.2',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'files': {'switchyard.sqlite3': hashlib.sha256(content).hexdigest(),
                      'known_hosts': hashlib.sha256(hosts).hexdigest(),
                      **({'mfa.key': hashlib.sha256(mfa_key).hexdigest()} if mfa_key else {}),
                      **({'credentials.key': hashlib.sha256(credentials_key).hexdigest()} if credentials_key else {})},
            'excluded': ['sessions', 'SSH private keys', 'Vaultwarden CLI state'],
            'warning': 'HIGHLY SENSITIVE: backup includes credential decryption keys and password hashes. Encrypt offline.',
        }
        output = _io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', json.dumps(manifest, indent=2))
            archive.writestr('switchyard.sqlite3', content)
            archive.writestr('known_hosts', hosts)
            if mfa_key:
                archive.writestr('mfa.key', mfa_key)
            if credentials_key:
                archive.writestr('credentials.key', credentials_key)
    return Response(output.getvalue(), media_type='application/zip',
                    headers={'Content-Disposition': 'attachment; filename="switchyard-backup.zip"', 'Cache-Control': 'no-store'})


class UpdateConfig(BaseModel):
    asset_id: str = Field(min_length=36, max_length=36)
    compose_project: str = Field(pattern=r'^[a-z0-9][a-z0-9_-]{1,62}$')
    repository_directory: str = Field(min_length=2, max_length=255)
    current_password: str = Field(min_length=1, max_length=4096)

    @field_validator('repository_directory')
    @classmethod
    def validate_repository_directory(cls, path: str):
        if (not path.startswith('/') or '\x00' in path or any(
                part in ('.', '..') for part in path.split('/')) or
                not re.fullmatch(r'/[A-Za-z0-9._/+-]+', path)):
            raise ValueError('Enter an absolute Linux checkout directory without traversal or shell characters')
        return path.rstrip('/')


class UpdateInstall(BaseModel):
    current_password: str = Field(min_length=1, max_length=4096)


@app.get('/api/update/config')
def get_update_config(_=Depends(require_auth)):
    with dbconn() as db:
        keys = ['update_asset_id', 'update_project', 'update_directory', 'update_job']
        return {key.removeprefix('update_'): saved_setting(key) for key in keys}


@app.put('/api/update/config')
def configure_update(body: UpdateConfig, request: Request, _=Depends(require_auth)):
    verify_origin(request)
    fetch_asset(body.asset_id)
    with dbconn() as db:
        if not check_admin_password(db, body.current_password):
            raise HTTPException(403, 'Administrator password is incorrect')
        db.executemany('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)', [
            ('update_asset_id', body.asset_id), ('update_project', body.compose_project),
            ('update_directory', body.repository_directory)])
    audit('update.configuration.changed')
    return {'ok': True}


@app.get('/api/update/status')
def update_status(_=Depends(require_auth)):
    configured = bool(saved_setting('update_asset_id') and saved_setting('update_project') and saved_setting('update_directory'))
    installed = '0.5.11-dev.2'
    latest = None
    check_error = None
    try:
        from urllib.request import Request as UrlRequest, urlopen
        req = UrlRequest('https://raw.githubusercontent.com/gigabytegrove/switchyard/main/VERSION',
                         headers={'User-Agent':'Switchyard/0.5.11-dev.2'})
        with urlopen(req, timeout=3) as remote:
            contents = remote.read(80).decode('ascii').strip()
        if re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]+)?', contents):
            latest = contents
        else:
            check_error = 'Repository VERSION response was invalid'
    except (OSError, ValueError, UnicodeError) as error:
        check_error = 'Could not reach the GitHub VERSION endpoint'
    return {'installed': installed, 'repository_version': latest, 'check_error': check_error,
            'update_available': latest is not None and latest != installed,
            'channel': 'development', 'automatic_install_available': configured,
            'message': ('SSH update executor configured.' if configured else
                        'Configure the SSH Docker-host executor below to enable in-app installation.')}


@app.post('/api/update/install')
def update_install(body: UpdateInstall, request: Request, _=Depends(require_auth)):
    """Schedule a detached, explicitly authorized Compose upgrade on a configured SSH host.

    The executor never gets a local Docker socket. It updates exactly one
    operator-configured Compose project from the Switchyard Git origin.
    """
    verify_origin(request)
    asset_id = saved_setting('update_asset_id')
    project = saved_setting('update_project')
    directory = saved_setting('update_directory')
    if not asset_id or not project or not directory:
        raise HTTPException(409, 'Configure the update executor in Settings first')
    with dbconn() as db:
        if not check_admin_password(db, body.current_password):
            raise HTTPException(403, 'Administrator password is incorrect')
    asset = fetch_asset(asset_id)
    if asset['auth_type'] == 'interactive' and not saved_password('ssh', asset_id):
        raise HTTPException(409, 'Update host requires a saved SSH credential, managed key or Vaultwarden item')
    # Stored values are validated again, including when reading a restored DB.
    UpdateConfig(asset_id=asset_id, compose_project=project,
                 repository_directory=directory, current_password='validated')
    job = uuid.uuid4().hex
    log_path = '/tmp/switchyard-update-' + job + '.log'
    script = ('set -eu\n'
              'trap \'rc=$?; if [ \"$rc\" -ne 0 ]; then echo SWITCHYARD_UPDATE_FAILED:$rc; fi\' EXIT\n'
              f'cd {shlex.quote(directory)}\n'
              'test "$(git remote get-url origin)" = "https://github.com/gigabytegrove/switchyard.git"\n'
              'git fetch --quiet origin main\n'
              'git merge --ff-only FETCH_HEAD\n'
              f'docker compose -p {shlex.quote(project)} -f compose.yaml pull\n'
              f'docker compose -p {shlex.quote(project)} -f compose.yaml up -d --no-build --wait --remove-orphans\n'
              'echo SWITCHYARD_UPDATE_SUCCESS\n')
    # All descriptors detached, so the SSH channel may close when this app
    # container is recreated without terminating the remote update process.
    command = ('nohup sh -c ' + shlex.quote(script) +
               ' > ' + shlex.quote(log_path) + ' 2>&1 < /dev/null & echo SWITCHYARD_UPDATE_PID:$!')
    outcome = remote_command(asset, command)
    if 'SWITCHYARD_UPDATE_PID:' not in outcome:
        audit('update.schedule.failed', job, 'failed')
        raise HTTPException(502, 'Remote update executor did not acknowledge scheduling')
    with dbconn() as db:
        db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)', ('update_job', job))
    audit('update.scheduled', job)
    return {'job': job, 'status': 'scheduled', 'message': 'Update launched on the configured Docker host. Follow its remote log for the result.'}


@app.get('/api/update/job')
def update_job(_=Depends(require_auth)):
    job = saved_setting('update_job')
    if not job:
        return {'job': None, 'log': '', 'status': 'none'}
    if not re.fullmatch(r'[0-9a-f]{32}', job):
        raise HTTPException(503, 'Stored updater job identifier is invalid')
    asset_id = saved_setting('update_asset_id')
    asset = fetch_asset(asset_id)
    log_path = '/tmp/switchyard-update-' + job + '.log'
    try:
        output = remote_command(asset, 'tail -n 80 -- ' + shlex.quote(log_path))
    except HTTPException:
        return {'job': job, 'status': 'unavailable', 'log': 'Update log not yet available or SSH unreachable'}
    status = ('success' if 'SWITCHYARD_UPDATE_SUCCESS' in output else
              'failed' if 'SWITCHYARD_UPDATE_FAILED:' in output else 'running')
    return {'job': job, 'status': status, 'log': output[:16384]}


@app.get('/api/overview')
def overview(_=Depends(require_auth)):
    with dbconn() as db:
        count = db.execute('SELECT count(*) FROM assets').fetchone()[0]
        groups = db.execute('SELECT count(DISTINCT environment) FROM assets').fetchone()[0]
        audits = db.execute('SELECT count(*) FROM audit').fetchone()[0]
    with dbconn() as db:
        runbooks = db.execute('SELECT count(*) FROM runbooks').fetchone()[0]
    return {'assets': count, 'environments': groups, 'audit_events': audits, 'runbooks': runbooks}


def bw_run(*args: str, session: bool = False, input_text: str | None = None,
           env_extra: dict | None = None, timeout=25) -> str:
    env = os.environ.copy()
    env['BITWARDENCLI_APPDATA_DIR'] = str(DATA / 'bw')
    if env_extra:
        env.update(env_extra)
    if session:
        if not BW_SESSION:
            raise HTTPException(409, 'Vault is locked')
        env['BW_SESSION'] = BW_SESSION
    try:
        proc = subprocess.run(['bw', '--nointeraction', *args], input=input_text, text=True,
                              capture_output=True, timeout=timeout, env=env)
    except FileNotFoundError:
        raise HTTPException(503, 'Bitwarden CLI is not installed in this runtime')
    except subprocess.TimeoutExpired:
        raise HTTPException(504, 'Vaultwarden request timed out')
    if proc.returncode != 0:
        # Do not return CLI error detail: it may contain credentials or sensitive data.
        raise HTTPException(502, 'Vaultwarden CLI operation failed. Check account state and server connectivity.')
    return proc.stdout.strip()


class VaultConfig(BaseModel):
    server_url: str = Field(min_length=9, max_length=255)


@app.post('/api/vault/configure')
def vault_configure(body: VaultConfig, _=Depends(require_auth)):
    global BW_SESSION
    p = urlsplit(body.server_url)
    allow_http = saved_setting('allow_http_vault') == 'true'
    if (p.scheme != 'https' and not (allow_http and p.scheme == 'http')) or not p.netloc or p.username or p.password or p.path not in ('', '/') or p.query or p.fragment:
        raise HTTPException(422, 'Use a vault origin URL (HTTPS required by default)')
    with VAULT_LOCK:
        BW_SESSION = None
        bw_run('config', 'server', body.server_url.rstrip('/'))
    audit('vault.configured', p.hostname or '')
    return {'ok': True}


class VaultLogin(BaseModel):
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=255)


@app.post('/api/vault/login')
def vault_login(body: VaultLogin, _=Depends(require_auth)):
    with VAULT_LOCK:
        bw_run('login', '--apikey', env_extra={'BW_CLIENTID': body.client_id, 'BW_CLIENTSECRET': body.client_secret}, timeout=40)
    audit('vault.login')
    return {'ok': True}


class VaultUnlock(BaseModel):
    master_password: str = Field(min_length=1, max_length=4096)


@app.post('/api/vault/unlock')
def vault_unlock(body: VaultUnlock, _=Depends(require_auth)):
    global BW_SESSION
    with VAULT_LOCK:
        raw = bw_run('unlock', '--passwordenv', 'SWITCHYARD_VW_PASSWORD', '--raw',
                     env_extra={'SWITCHYARD_VW_PASSWORD': body.master_password})
        if len(raw) < 20 or '\n' in raw:
            raise HTTPException(502, 'Vault returned an invalid session')
        BW_SESSION = raw
    audit('vault.unlocked')
    return {'ok': True}


@app.post('/api/vault/lock')
def vault_lock(_=Depends(require_auth)):
    global BW_SESSION
    with VAULT_LOCK:
        if BW_SESSION:
            bw_run('lock', session=True)
        BW_SESSION = None
    audit('vault.locked')
    return {'ok': True}


@app.post('/api/vault/logout')
def vault_logout(_=Depends(require_auth)):
    global BW_SESSION
    with VAULT_LOCK:
        # Do not send session to CLI if this process is already locked.
        BW_SESSION = None
        bw_run('logout')
    audit('vault.logout')
    return {'ok': True}


@app.get('/api/vault/status')
def vault_status(_=Depends(require_auth)):
    with VAULT_LOCK:
        try:
            status = json.loads(bw_run('status'))
            return {'status': status.get('status', 'unknown'), 'server': status.get('serverUrl'), 'unlocked': bool(BW_SESSION)}
        except HTTPException:
            return {'status': 'unavailable', 'server': None, 'unlocked': False}


@app.post('/api/vault/sync')
def vault_sync(_=Depends(require_auth)):
    with VAULT_LOCK:
        bw_run('sync', session=True, timeout=60)
    audit('vault.synced')
    return {'ok': True}


@app.get('/api/vault/items')
def vault_items(_=Depends(require_auth)):
    with VAULT_LOCK:
        result = json.loads(bw_run('list', 'items', session=True))
    return [{'id': x.get('id'), 'name': x.get('name'), 'username': (x.get('login') or {}).get('username', '')}
            for x in result if x.get('type') == 1]


def vault_password(ref: str) -> str:
    if not ref:
        raise HTTPException(422, 'Vault item not configured')
    with VAULT_LOCK:
        item = json.loads(bw_run('get', 'item', ref, session=True))
    pwd = (item.get('login') or {}).get('password')
    if not pwd:
        raise HTTPException(422, 'Selected vault item has no login password')
    return pwd


def ssh_client(asset: dict, interactive_password: str | None = None):
    # Lazy import allows core API and tests to run before optional SSH lib is installed.
    import paramiko
    client = paramiko.SSHClient()
    keys = DATA / 'known_hosts'
    keys.touch(exist_ok=True, mode=0o600)
    os.chmod(keys, 0o600)
    client.load_host_keys(str(keys))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    password = vault_password(asset['credential_ref']) if asset['auth_type'] == 'vault' else ((interactive_password or saved_password('ssh', asset['id'])) if asset['auth_type'] == 'interactive' else None)
    key = None
    if asset['auth_type'] == 'key':
        name = asset['key_file']
        path = DATA / 'keys' / name
        if not name or not FILE_RE.fullmatch(name) or not path.is_file():
            raise HTTPException(422, 'SSH key file is missing')
        key = str(path)
    try:
        client.connect(hostname=asset['host'], port=asset['port'], username=asset['username'],
                       password=password, key_filename=key, allow_agent=False,
                       look_for_keys=False, timeout=12, auth_timeout=12, banner_timeout=12)
    except paramiko.BadHostKeyException as error:
        client.close()
        raise HTTPException(409, 'SSH host key changed. Review the machine in Host trust before reconnecting.') from error
    except paramiko.AuthenticationException as error:
        client.close()
        raise HTTPException(502, 'SSH authentication rejected. Check the saved password, key, or Vaultwarden item.') from error
    except paramiko.SSHException as error:
        client.close()
        message = str(error).lower()
        if 'not found in known_hosts' in message or 'not found in known hosts' in message or 'unknown server' in message:
            raise HTTPException(409, 'SSH host is not trusted. Discover and verify its fingerprint in Host trust first.') from error
        raise HTTPException(502, 'SSH protocol negotiation failed. Check the SSH service and supported algorithms.') from error
    except (TimeoutError, socket.timeout) as error:
        client.close()
        raise HTTPException(504, 'SSH connection timed out. Check the host address, port, and firewall.') from error
    except ConnectionRefusedError as error:
        client.close()
        raise HTTPException(502, 'SSH connection refused. Check the SSH service and port.') from error
    except socket.gaierror as error:
        client.close()
        raise HTTPException(502, 'SSH hostname could not be resolved. Check the machine address and DNS.') from error
    except OSError as error:
        client.close()
        raise HTTPException(502, 'SSH network connection failed. Check routing, firewall, and host availability.') from error
    except Exception as error:
        client.close()
        raise HTTPException(502, 'SSH connection failed unexpectedly. Inspect the server logs.') from error
    finally:
        password = None
    return client


class KnownHost(BaseModel):
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    key_type: str
    public_key: str


class HostTarget(BaseModel):
    host: str
    port: int = Field(default=22, ge=1, le=65535)


@app.post('/api/hosts/discover')
def discover_host(body: HostTarget, _=Depends(require_auth)):
    import base64
    import paramiko
    import socket
    if not HOST_RE.fullmatch(body.host):
        raise HTTPException(422, 'Invalid host')
    transport = None
    try:
        sock = socket.create_connection((body.host, body.port), timeout=6)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=8)
        key = transport.get_remote_server_key()
        return {'host': body.host, 'port': body.port, 'key_type': key.get_name(),
                'public_key': base64.b64encode(key.asbytes()).decode(),
                'fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')}
    except Exception:
        raise HTTPException(502, 'Could not retrieve the remote SSH host key')
    finally:
        if transport:
            transport.close()


@app.post('/api/hosts/scan')
def scan_host(body: KnownHost, _=Depends(require_auth)):
    # Admin explicitly provides host and key to stage; host key not trusted until separately verified.
    if not HOST_RE.fullmatch(body.host):
        raise HTTPException(422, 'Invalid host')
    try:
        import base64
        import paramiko
        blob = base64.b64decode(body.public_key, validate=True)
        key = paramiko.PKey.from_type_string(body.key_type, blob)
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        return {'fingerprint': fingerprint, 'key_type': key.get_name(), 'host': body.host, 'port': body.port}
    except Exception:
        raise HTTPException(422, 'Invalid public host key')


def save_host_keys(keys):
    # Write+replace instead of truncating the trusted-host list in place.
    with tempfile.NamedTemporaryFile(prefix='.known-hosts-', dir=DATA, delete=False) as handle:
        staged = Path(handle.name)
    try:
        keys.save(str(staged))
        os.chmod(staged, 0o600)
        with staged.open('rb') as handle:
            os.fsync(handle.fileno())
        os.replace(staged, DATA / 'known_hosts')
    finally:
        staged.unlink(missing_ok=True)


@app.post('/api/hosts/trust')
def trust_host(body: KnownHost, _=Depends(require_auth)):
    import base64
    import paramiko
    if not HOST_RE.fullmatch(body.host):
        raise HTTPException(422, 'Invalid host')
    try:
        key = paramiko.PKey.from_type_string(body.key_type, base64.b64decode(body.public_key, validate=True))
    except Exception:
        raise HTTPException(422, 'Invalid public host key')
    hostkeyname = body.host if body.port == 22 else f'[{body.host}]:{body.port}'
    with LOCK:
        file = DATA / 'known_hosts'
        hosts = paramiko.HostKeys()
        if file.exists():
            hosts.load(str(file))
        existing = hosts.lookup(hostkeyname)
        if existing and key.get_name() in existing and existing[key.get_name()].asbytes() != key.asbytes():
            raise HTTPException(409, 'Host key changed; revoke the old fingerprint first after verifying the change out of band')
        hosts.add(hostkeyname, key.get_name(), key)
        save_host_keys(hosts)
    audit('host.trusted', hostkeyname)
    return {'ok': True}


@app.get('/api/hosts')
def hosts(_=Depends(require_auth)):
    import paramiko
    file = DATA / 'known_hosts'
    keys = paramiko.HostKeys()
    if file.exists():
        keys.load(str(file))
    import base64
    return [{'host': host, 'algorithm': kind, 'fingerprint': 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')}
            for host, types in keys.items() for kind, key in types.items()]


class RevokeHost(BaseModel):
    host: str = Field(min_length=1, max_length=300)
    algorithm: str = Field(min_length=1, max_length=100)
    fingerprint: str = Field(min_length=1, max_length=100)


@app.post('/api/hosts/revoke')
def revoke_host(body: RevokeHost, _=Depends(require_auth)):
    import paramiko
    with LOCK:
        file = DATA / 'known_hosts'
        keys = paramiko.HostKeys()
        if file.exists():
            keys.load(str(file))
        known = keys.lookup(body.host)
        key = known.get(body.algorithm) if known else None
        if not key:
            raise HTTPException(404, 'Trusted key not found')
        fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if not hmac.compare_digest(fingerprint, body.fingerprint):
            raise HTTPException(409, 'Fingerprint changed; refresh trusted keys')
        # Paramiko's HostKeys.lookup returns a SubDict; deleting from that view
        # does not mutate the parent collection. Rebuild the host-key inventory.
        updated = paramiko.HostKeys()
        for hostname, algorithms in keys.items():
            for algorithm, old_key in algorithms.items():
                if hostname == body.host and algorithm == body.algorithm:
                    continue
                updated.add(hostname, algorithm, old_key)
        save_host_keys(updated)
    audit('host.revoked', body.host)
    return {'ok': True}


# SSH private keys live in the persistent volume, protected by the same 0700/0600 model
# as the existing mounted-key workflow. No private-key read or export endpoint exists.
class KeyName(BaseModel):
    name: str = Field(min_length=1, max_length=120)

    @field_validator('name')
    @classmethod
    def verify_name(cls, name):
        if not FILE_RE.fullmatch(name):
            raise ValueError('Invalid key name')
        return name


def key_directory():
    folder = DATA / 'keys'
    folder.mkdir(mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    return folder


def public_key_for_file(path: Path):
    # cryptography parses actual key material without relying on SSH network modules.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
    from cryptography.exceptions import UnsupportedAlgorithm
    content = path.read_bytes()
    try:
        try:
            key = serialization.load_ssh_private_key(content, password=None)
        except ValueError:
            key = serialization.load_pem_private_key(content, password=None)
        if not isinstance(key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ValueError('Unsupported key algorithm')
        return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                             serialization.PublicFormat.OpenSSH).decode()
    except (ValueError, TypeError, OSError, UnsupportedAlgorithm):
        raise HTTPException(422, 'Unsupported or encrypted SSH private key; use an unencrypted Ed25519, RSA, or ECDSA key')


@app.get('/api/keys')
def list_keys(_=Depends(require_auth)):
    result = []
    for file in sorted(key_directory().iterdir()):
        if not FILE_RE.fullmatch(file.name) or not file.is_file() or file.is_symlink():
            continue
        try:
            public = public_key_for_file(file)
        except HTTPException:
            continue
        with dbconn() as db:
            used = db.execute("SELECT COUNT(*) FROM assets WHERE auth_type='key' AND key_file=?", (file.name,)).fetchone()[0]
        result.append({'name': file.name, 'public_key': public, 'used_by': used})
    return result


@app.post('/api/keys/generate', status_code=201)
def generate_key(body: KeyName, _=Depends(require_auth)):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    from cryptography.hazmat.primitives.serialization import PublicFormat
    private = Ed25519PrivateKey.generate()
    content = private.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption())
    path = key_directory() / body.name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        raise HTTPException(409, 'Key name already exists')
    with os.fdopen(fd, 'wb') as handle:
        handle.write(content)
    os.chmod(path, 0o600)
    pub = private.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    audit('key.generated', body.name)
    return {'name': body.name, 'public_key': pub}


@app.post('/api/keys/import', status_code=201)
async def import_key(name: str, file: UploadFile = File(...), _=Depends(require_auth)):
    if not FILE_RE.fullmatch(name):
        raise HTTPException(422, 'Invalid key name')
    content = await file.read(16385)
    if not content or len(content) > 16384:
        raise HTTPException(413, 'SSH private key must be between 1 B and 16 KiB')
    path = key_directory() / name
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except FileExistsError:
        raise HTTPException(409, 'Key name already exists')
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
        public = public_key_for_file(path)
        os.chmod(path, 0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    audit('key.imported', name)
    return {'name': name, 'public_key': public}


@app.delete('/api/keys/{name}')
def delete_key(name: str, _=Depends(require_auth)):
    if not FILE_RE.fullmatch(name):
        raise HTTPException(422, 'Invalid key name')
    with dbconn() as db:
        if db.execute("SELECT 1 FROM assets WHERE auth_type='key' AND key_file=?", (name,)).fetchone():
            raise HTTPException(409, 'Key is assigned to an asset; reassign the asset first')
    target = key_directory() / name
    if not target.is_file() or target.is_symlink():
        raise HTTPException(404, 'Key not found')
    target.unlink()
    audit('key.deleted', name)
    return {'ok': True}


@app.websocket('/ws/terminal/{aid}')
async def terminal(ws: WebSocket, aid: str):
    if not session_from_ws(ws):
        await ws.close(code=4401)
        return
    asset = fetch_asset(aid)
    await ws.accept()
    client = None
    channel = None
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=30)
        if first.get('type') != 'auth':
            raise ValueError('Initial authentication message expected')
        password = first.get('password') if asset['auth_type'] == 'interactive' else None
        if password is not None and (not isinstance(password, str) or len(password) > 4096):
            raise ValueError('Invalid password')
        client = await asyncio.to_thread(ssh_client, asset, password)
        password = None
        channel = await asyncio.to_thread(client.invoke_shell, term='xterm-256color', width=100, height=30)
        await ws.send_json({'type': 'connected'})
        if asset['use_tmux']:
            # Name consists solely of UUID characters (not user-provided shell input).
            channel.send('tmux new-session -A -s sy_' + aid.replace('-', '')[:18] + '\n')
        audit('terminal.opened', aid)
        async def from_server():
            while channel and not channel.closed:
                if channel.recv_ready():
                    output = await asyncio.to_thread(channel.recv, 16384)
                    if not output:
                        break
                    await ws.send_json({'type': 'data', 'data': output.decode('utf-8', errors='replace')})
                elif channel.exit_status_ready():
                    break
                else:
                    await asyncio.sleep(0.025)
        async def from_browser():
            while True:
                msg = await ws.receive_json()
                typ = msg.get('type')
                if typ == 'input':
                    data = msg.get('data', '')
                    if isinstance(data, str) and len(data) <= 32768:
                        await asyncio.to_thread(channel.sendall, data.encode('utf-8'))
                elif typ == 'resize':
                    cols = max(20, min(int(msg.get('cols', 100)), 300))
                    rows = max(10, min(int(msg.get('rows', 30)), 120))
                    await asyncio.to_thread(channel.resize_pty, width=cols, height=rows)
        tasks = [asyncio.create_task(from_server()), asyncio.create_task(from_browser())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            if not task.cancelled():
                task.result()
    except HTTPException as error:
        try:
            detail = str(error.detail)
            if error.status_code == 409 and detail.startswith('SSH host is not trusted'):
                code = 'ssh_host_unknown'
            elif error.status_code == 409 and detail.startswith('SSH host key changed'):
                code = 'ssh_host_changed'
            elif error.status_code == 502 and detail.startswith('SSH authentication rejected'):
                code = 'ssh_auth_rejected'
            else:
                code = 'ssh_connection_error'
            await ws.send_json({'type': 'error', 'code': code, 'message': str(error.detail)})
        except Exception:
            pass
        audit('terminal.error', aid, 'failed')
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.send_json({'type': 'error', 'message': 'SSH session could not be established or was interrupted.'})
        except Exception:
            pass
        audit('terminal.error', aid, 'failed')
    finally:
        if channel:
            channel.close()
        if client:
            client.close()
        audit('terminal.closed', aid)
        try:
            await ws.close()
        except Exception:
            pass


@app.get('/api/assets/{aid}/files')
def file_listing(aid: str, path: str = '.', x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    client = ssh_client(asset, x_ssh_password)
    try:
        sftp = client.open_sftp()
        try:
            canonical = sftp.normalize(path)
            out = []
            for x in sftp.listdir_attr(canonical):
                out.append({'name': x.filename, 'directory': bool(x.st_mode and (x.st_mode & 0o170000) == 0o040000),
                            'size': x.st_size or 0, 'modified': x.st_mtime or 0,
                            'symlink': bool(x.st_mode and stat.S_ISLNK(x.st_mode)),
                            'permissions': format(stat.S_IMODE(x.st_mode), '03o') if x.st_mode is not None else '---'})
            return {'path': canonical, 'entries': sorted(out, key=lambda v: (not v['directory'], v['name'].lower()))}
        finally:
            sftp.close()
    finally:
        client.close()


@app.get('/api/assets/{aid}/download')
def download(aid: str, path: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    client = ssh_client(asset, x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            st = sftp.stat(path)
            if st.st_size > MAX_TRANSFER:
                raise HTTPException(413, 'Files larger than 64 MiB are not supported in this release')
            with sftp.file(path, 'rb') as f:
                content = f.read(MAX_TRANSFER + 1)
                if len(content) > MAX_TRANSFER:
                    raise HTTPException(413, 'File exceeded transfer limit')
    finally:
        client.close()
    audit('sftp.download', aid)
    import posixpath
    from urllib.parse import quote
    filename = posixpath.basename(path).replace('"', '_').replace('\r', '_').replace('\n', '_') or 'file'
    return Response(content, media_type='application/octet-stream',
                    headers={'Content-Disposition': f"attachment; filename*=UTF-8''{quote(filename)}", 'Cache-Control': 'no-store'})


@app.post('/api/assets/{aid}/upload')
async def upload(aid: str, path: str, file: UploadFile = File(...), x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    from posixpath import basename, join
    asset = fetch_asset(aid)
    filename = basename(file.filename or '')
    if filename in ('', '.', '..') or '\\' in filename or '\x00' in filename:
        raise HTTPException(422, 'Invalid file name')
    data = await file.read(MAX_TRANSFER + 1)
    if len(data) > MAX_TRANSFER:
        raise HTTPException(413, 'Files larger than 64 MiB are not supported')
    def send_file():
        client = ssh_client(asset, x_ssh_password)
        try:
            with client.open_sftp() as sftp:
                target = join(path, filename)
                # Exclusive create; do not silently overwrite an existing remote file.
                with sftp.file(target, 'wx') as f:
                    f.write(data)
        finally:
            client.close()
    await asyncio.to_thread(send_file)
    audit('sftp.upload', aid)
    return {'ok': True, 'filename': filename}


def remote_command(asset: dict, command: str, password: str | None = None):
    client = ssh_client(asset, password)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=20)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            out_future = pool.submit(stdout.read, 1024 * 1024 + 1)
            err_future = pool.submit(stderr.read, 32 * 1024 + 1)
            out = out_future.result(timeout=45)
            err = err_future.result(timeout=45)
        code = stdout.channel.recv_exit_status()
        if len(out) > 1024 * 1024 or len(err) > 32 * 1024:
            raise HTTPException(413, 'Remote command output exceeded limit')
        if code != 0:
            raise HTTPException(502, 'Remote Docker command failed: ' + err.decode('utf-8', errors='replace')[:180])
        return out.decode('utf-8', errors='replace')
    finally:
        client.close()


@app.get('/api/assets/{aid}/docker/containers')
def docker_containers(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    output = remote_command(asset, "docker ps --all --no-trunc --format '{{json .}}'", x_ssh_password)
    try:
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
    except (ValueError, TypeError):
        raise HTTPException(502, 'Remote Docker output could not be parsed')
    return [{'id': x.get('ID', ''), 'name': x.get('Names', ''), 'image': x.get('Image', ''),
             'status': x.get('Status', ''), 'state': x.get('State', ''),
             'ports': x.get('Ports', '')} for x in rows]


class DockerAction(BaseModel):
    action: Literal['start', 'stop', 'restart']
    container_id: str = Field(min_length=12, max_length=64, pattern='^[a-fA-F0-9]{12,64}$')


@app.post('/api/assets/{aid}/docker/action')
def docker_action(aid: str, body: DockerAction, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    # Docker container ID is constrained to hexadecimal, not a shell expression.
    remote_command(asset, f'docker {body.action} {body.container_id}', x_ssh_password)
    audit('docker.' + body.action, aid + ':' + body.container_id[:12])
    return {'ok': True}


CONTAINER_ID_RE = re.compile(r'^[a-fA-F0-9]{12,64}$')


def safe_container_id(container_id: str):
    if not CONTAINER_ID_RE.fullmatch(container_id):
        raise HTTPException(422, 'Expected a Docker container hexadecimal ID')
    return container_id


def docker_json(output: str):
    try:
        return json.loads(output)
    except (ValueError, TypeError):
        raise HTTPException(502, 'Remote Docker output could not be parsed')


@app.get('/api/assets/{aid}/docker/summary')
def docker_summary(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    info = docker_json(remote_command(asset, "docker info --format '{{json .}}'", x_ssh_password))
    # Do not return the daemon's full JSON: it may contain registry details or other secrets.
    return {'server_version': info.get('ServerVersion'), 'containers': info.get('Containers'),
            'running': info.get('ContainersRunning'), 'paused': info.get('ContainersPaused'),
            'stopped': info.get('ContainersStopped'), 'images': info.get('Images'),
            'name': info.get('Name'), 'operating_system': info.get('OperatingSystem'),
            'architecture': info.get('Architecture'), 'cpus': info.get('NCPU'),
            'memory_bytes': info.get('MemTotal')}


@app.get('/api/assets/{aid}/docker/containers/{container_id}/inspect')
def docker_inspect(aid: str, container_id: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    safe_container_id(container_id)
    asset = fetch_asset(aid)
    item = docker_json(remote_command(asset, f'docker container inspect {container_id}', x_ssh_password))
    if not isinstance(item, list) or len(item) != 1 or not isinstance(item[0], dict):
        raise HTTPException(502, 'Unexpected Docker inspect response')
    entry = item[0]
    config = entry.get('Config') or {}
    state = entry.get('State') or {}
    network = entry.get('NetworkSettings') or {}
    ports = network.get('Ports') or {}
    # Strong allowlist: NEVER expose Config.Env, mounts' private paths, labels or raw inspect JSON.
    return {'id': entry.get('Id'), 'name': entry.get('Name'), 'image': config.get('Image'),
            'created': entry.get('Created'), 'status': state.get('Status'),
            'started_at': state.get('StartedAt'), 'finished_at': state.get('FinishedAt'),
            'exit_code': state.get('ExitCode'), 'restart_count': entry.get('RestartCount'),
            'health': (state.get('Health') or {}).get('Status'),
            'restart_policy': (entry.get('HostConfig') or {}).get('RestartPolicy', {}).get('Name'),
            'ports': ports, 'networks': sorted((network.get('Networks') or {}).keys())}


@app.get('/api/assets/{aid}/docker/containers/{container_id}/logs')
def docker_logs(aid: str, container_id: str, tail: int = 200,
                x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    safe_container_id(container_id)
    tail = max(1, min(tail, 500))
    result = remote_command(fetch_asset(aid), f'docker logs --tail {tail} --timestamps {container_id} 2>&1', x_ssh_password)
    audit('docker.logs', aid + ':' + container_id[:12])
    return {'logs': result, 'tail': tail, 'truncated': len(result.encode()) >= 1024 * 1024}


@app.get('/api/assets/{aid}/docker/containers/{container_id}/stats')
def docker_stats(aid: str, container_id: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    safe_container_id(container_id)
    result = docker_json(remote_command(fetch_asset(aid),
        f"docker stats --no-stream --format '{{{{json .}}}}' {container_id}", x_ssh_password))
    return {field: result.get(field) for field in ('CPUPerc', 'MemUsage', 'MemPerc', 'NetIO', 'BlockIO', 'PIDs')}


@app.get('/api/assets/{aid}/docker/images')
def docker_images(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    result = remote_command(fetch_asset(aid), "docker images --no-trunc --format '{{json .}}'", x_ssh_password)
    try:
        items = [json.loads(line) for line in result.splitlines() if line.strip()]
    except ValueError:
        raise HTTPException(502, 'Remote image list could not be parsed')
    return [{'repository': i.get('Repository'), 'tag': i.get('Tag'), 'id': i.get('ID'),
             'size': i.get('Size'), 'created': i.get('CreatedSince')} for i in items]


@app.get('/api/assets/{aid}/docker/networks')
def docker_networks(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    result = remote_command(fetch_asset(aid), "docker network ls --no-trunc --format '{{json .}}'", x_ssh_password)
    try:
        items = [json.loads(line) for line in result.splitlines() if line.strip()]
    except ValueError:
        raise HTTPException(502, 'Remote network list could not be parsed')
    return [{'name': i.get('Name'), 'id': i.get('ID'), 'driver': i.get('Driver'), 'scope': i.get('Scope')}
            for i in items]


@app.get('/api/assets/{aid}/docker/volumes')
def docker_volumes(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    result = remote_command(fetch_asset(aid), "docker volume ls --format '{{json .}}'", x_ssh_password)
    try:
        items = [json.loads(line) for line in result.splitlines() if line.strip()]
    except ValueError:
        raise HTTPException(502, 'Remote volume list could not be parsed')
    return [{'name': i.get('Name'), 'driver': i.get('Driver')} for i in items]


class SftpPath(BaseModel):
    path: str = Field(min_length=1, max_length=2048)


class SftpRename(BaseModel):
    source: str = Field(min_length=1, max_length=2048)
    destination: str = Field(min_length=1, max_length=2048)


@app.post('/api/assets/{aid}/files/mkdir')
def sftp_mkdir(aid: str, body: SftpPath, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            sftp.mkdir(body.path)
    finally:
        client.close()
    audit('sftp.mkdir', aid)
    return {'ok': True}


@app.post('/api/assets/{aid}/files/rename')
def sftp_rename(aid: str, body: SftpRename, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    if body.source == body.destination:
        raise HTTPException(422, 'Source and destination must differ')
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            try:
                sftp.stat(body.destination)
            except FileNotFoundError:
                pass
            else:
                raise HTTPException(409, 'Destination exists; refusing overwrite')
            sftp.rename(body.source, body.destination)
    finally:
        client.close()
    audit('sftp.rename', aid)
    return {'ok': True}


@app.delete('/api/assets/{aid}/files')
def sftp_delete(aid: str, body: SftpPath, directory: bool = False,
                x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    # Directory removal is non-recursive and fails if the directory is not empty.
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            if directory:
                sftp.rmdir(body.path)
            else:
                sftp.remove(body.path)
    finally:
        client.close()
    audit('sftp.delete', aid)
    return {'ok': True}




class SftpChmod(BaseModel):
    path: str = Field(min_length=1, max_length=2048)
    mode: str = Field(pattern=r'^[0-7]{3}$')


@app.post('/api/assets/{aid}/files/chmod')
def sftp_chmod(aid: str, body: SftpChmod, x_ssh_password: str | None = Header(default=None),
               _=Depends(require_auth)):
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            current = sftp.lstat(body.path)
            if stat.S_ISLNK(current.st_mode):
                raise HTTPException(422, 'Changing symlink permissions is not supported')
            sftp.chmod(body.path, int(body.mode, 8))
    finally:
        client.close()
    audit('sftp.chmod', aid)
    return {'ok': True, 'mode': body.mode}


@app.post('/api/assets/{aid}/files/copy')
def sftp_copy(aid: str, body: SftpRename, x_ssh_password: str | None = Header(default=None),
              _=Depends(require_auth)):
    if posixpath.normpath(body.source) == posixpath.normpath(body.destination):
        raise HTTPException(422, 'Source and destination must differ')
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            info = sftp.lstat(body.source)
            if not stat.S_ISREG(info.st_mode):
                raise HTTPException(422, 'Only regular files may be copied; directories and symlinks are excluded')
            if info.st_size is None or info.st_size > MAX_TRANSFER:
                raise HTTPException(413, 'File exceeds the 64 MiB remote copy limit')
            try:
                sftp.lstat(body.destination)
            except FileNotFoundError:
                pass
            else:
                raise HTTPException(409, 'Destination exists; refusing overwrite')
            created = False
            total = 0
            try:
                with sftp.file(body.source, 'rb') as source:
                    with sftp.file(body.destination, 'wx') as dest:
                        created = True
                        while True:
                            chunk = source.read(65536)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_TRANSFER:
                                raise HTTPException(413, 'File exceeds the 64 MiB remote copy limit')
                            dest.write(chunk)
                sftp.chmod(body.destination, stat.S_IMODE(info.st_mode))
            except Exception:
                if created:
                    try:
                        sftp.remove(body.destination)
                    except OSError:
                        pass
                raise
    finally:
        client.close()
    audit('sftp.copy', aid)
    return {'ok': True, 'bytes_copied': total}




SERVICE_UNIT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,124}\.service$')


class ServiceAction(BaseModel):
    unit: str = Field(min_length=9, max_length=133)
    action: Literal['start', 'stop', 'restart']
    confirmed: bool = False

    @field_validator('unit')
    @classmethod
    def valid_unit(cls, name: str) -> str:
        if not SERVICE_UNIT_RE.fullmatch(name):
            raise ValueError('Service name must be a single systemd service unit')
        return name


def systemd_command(aid: str, command: str, password: str | None, timeout: int = 20):
    result = execute_runbook_ssh(fetch_asset(aid), command, password, limit_seconds=timeout)
    if result['exit_code'] != 0:
        message = str(result['stderr'] or result['stdout'])[:180].strip()
        raise HTTPException(502, 'Remote systemd command failed: ' + (message or 'permission denied or service unavailable'))
    return result['stdout']


@app.get('/api/assets/{aid}/services')
def list_systemd_services(aid: str, x_ssh_password: str | None = Header(default=None),
                          _=Depends(require_auth)):
    output = systemd_command(aid,
        'systemctl --no-pager --plain --all list-units --type=service --no-legend',
        x_ssh_password)
    services = []
    for raw in output.splitlines():
        line = raw.strip().lstrip('●').strip()
        pieces = line.split(None, 4)
        if len(pieces) < 4 or not SERVICE_UNIT_RE.fullmatch(pieces[0]):
            continue
        services.append({'unit': pieces[0], 'load': pieces[1],
                         'active': pieces[2], 'sub': pieces[3],
                         'description': pieces[4][:280] if len(pieces)>4 else ''})
        if len(services) >= 500:
            break
    audit('service.list', aid)
    return {'host_id': aid, 'services': services, 'count': len(services),
            'limited': len(services) >= 500}


@app.post('/api/assets/{aid}/services/action')
def operate_systemd_service(aid: str, body: ServiceAction,
                            x_ssh_password: str | None = Header(default=None),
                            _=Depends(require_auth)):
    if not body.confirmed:
        raise HTTPException(422, 'Confirm this service operation before proceeding')
    command = 'systemctl ' + body.action + ' ' + shlex.quote(body.unit)
    try:
        systemd_command(aid, command, x_ssh_password, timeout=30)
    except Exception:
        audit('service.' + body.action, aid + ':' + body.unit, 'failed')
        raise
    audit('service.' + body.action, aid + ':' + body.unit)
    return {'ok': True, 'unit': body.unit, 'action': body.action}


@app.get('/api/assets/{aid}/services/{unit}/logs')
def systemd_service_logs(aid: str, unit: str, x_ssh_password: str | None = Header(default=None),
                         _=Depends(require_auth)):
    if not SERVICE_UNIT_RE.fullmatch(unit):
        raise HTTPException(422, 'Invalid systemd service unit')
    output = systemd_command(
        aid, 'journalctl --no-pager --lines=100 --output=short-iso --unit ' + shlex.quote(unit),
        x_ssh_password)
    audit('service.logs', aid + ':' + unit)
    return {'unit': unit, 'lines': output[-256*1024:]}


# Operations release v0.3: commands are explicit administrator-approved remote actions.
# Commands and descriptions are persisted; stdout/stderr and interactive passwords are NOT.
class RunbookModel(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default='', max_length=500)
    command: str = Field(min_length=1, max_length=8192)
    requires_confirmation: bool = True

    @field_validator('command')
    @classmethod
    def validate_command(cls, value):
        if '\x00' in value or '\r' in value:
            raise ValueError('Command contains invalid control characters')
        if not value.strip():
            raise ValueError('Command must not be empty')
        return value


@app.get('/api/runbooks')
def runbook_list(_=Depends(require_auth)):
    with dbconn() as db:
        return [dict(row) for row in db.execute('SELECT * FROM runbooks ORDER BY name COLLATE NOCASE')]


@app.post('/api/runbooks', status_code=201)
def runbook_create(body: RunbookModel, _=Depends(require_auth)):
    rid = str(uuid.uuid4())
    now = int(time.time())
    with dbconn() as db:
        db.execute("""INSERT INTO runbooks(id,name,description,command,requires_confirmation,created_at,updated_at)
                      VALUES(?,?,?,?,?,?,?)""", (rid, body.name, body.description, body.command,
                      int(body.requires_confirmation), now, now))
    audit('runbook.created', rid)
    return {'id': rid}


@app.put('/api/runbooks/{rid}')
def runbook_update(rid: str, body: RunbookModel, _=Depends(require_auth)):
    with dbconn() as db:
        row = db.execute("""UPDATE runbooks SET name=?,description=?,command=?,
                        requires_confirmation=?,updated_at=? WHERE id=?""",
                        (body.name, body.description, body.command, int(body.requires_confirmation), int(time.time()), rid))
        if not row.rowcount:
            raise HTTPException(404, 'Runbook not found')
    audit('runbook.updated', rid)
    return {'ok': True}


@app.delete('/api/runbooks/{rid}')
def runbook_delete(rid: str, _=Depends(require_auth)):
    with dbconn() as db:
        row = db.execute('DELETE FROM runbooks WHERE id=?', (rid,))
        if not row.rowcount:
            raise HTTPException(404, 'Runbook not found')
    audit('runbook.deleted', rid)
    return {'ok': True}


def execute_runbook_ssh(asset: dict, command: str, password: str | None = None,
                        limit_seconds: int = 30):
    """Drain both SSH streams without deadlocking, bound memory and execution time."""
    client = ssh_client(asset, password)
    channel = None
    max_output = 256 * 1024
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise HTTPException(502, 'SSH transport unavailable')
        channel = transport.open_session(timeout=10)
        channel.settimeout(1)
        channel.exec_command(command)
        stdout = bytearray()
        stderr = bytearray()
        until = time.monotonic() + limit_seconds
        while True:
            if time.monotonic() >= until:
                raise HTTPException(504, 'Remote command exceeded its execution deadline')
            available = False
            if channel.recv_ready():
                available = True
                chunk = channel.recv(16384)
                stdout.extend(chunk)
            if channel.recv_stderr_ready():
                available = True
                chunk = channel.recv_stderr(16384)
                stderr.extend(chunk)
            if len(stdout) + len(stderr) > max_output:
                raise HTTPException(413, 'Remote output exceeded the 256 KiB limit')
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return {'exit_code': channel.recv_exit_status(), 'stdout': stdout.decode('utf-8', 'replace'),
                        'stderr': stderr.decode('utf-8', 'replace')}
            if not available:
                time.sleep(0.025)
    finally:
        if channel:
            channel.close()
        client.close()


class RunRequest(BaseModel):
    asset_id: str
    confirm: bool = False


@app.post('/api/runbooks/{rid}/execute')
def runbook_execute(rid: str, body: RunRequest, x_ssh_password: str | None = Header(default=None),
                    _=Depends(require_auth)):
    with dbconn() as db:
        book = db.execute('SELECT * FROM runbooks WHERE id=?', (rid,)).fetchone()
    if book is None:
        raise HTTPException(404, 'Runbook not found')
    if book['requires_confirmation'] and not body.confirm:
        raise HTTPException(409, 'Explicit execution confirmation is required')
    asset = fetch_asset(body.asset_id)
    started = time.monotonic()
    outcome = 'failed'
    exit_code = None
    try:
        result = execute_runbook_ssh(asset, book['command'], x_ssh_password)
        exit_code = result['exit_code']
        outcome = 'ok' if exit_code == 0 else 'nonzero'
        return result
    finally:
        with dbconn() as db:
            db.execute("""INSERT INTO run_history(runbook_id,runbook_name,asset_id,asset_name,started_at,
                          duration_ms,outcome,exit_code) VALUES(?,?,?,?,?,?,?,?)""",
                       (rid, book['name'], body.asset_id, asset['label'], int(time.time()),
                        int((time.monotonic() - started) * 1000), outcome, exit_code))
        audit('runbook.executed', f'{rid}:{body.asset_id}', outcome)


@app.get('/api/runbooks/history')
def runbook_history(limit: int = 100, before: int | None = None, _=Depends(require_auth)):
    q = 'SELECT * FROM run_history WHERE 1=1'
    args = []
    if before is not None:
        q += ' AND id<?'
        args.append(max(1, before))
    q += ' ORDER BY id DESC LIMIT ?'
    args.append(max(1, min(limit, 200)))
    with dbconn() as db:
        return [dict(row) for row in db.execute(q, args)]


# /proc-backed Linux health; no agent, privileged daemon access or external package required.
HEALTH_COMMAND = """sh -c 'printf "SYHOST\\n"; hostname; printf "SYKERNEL\\n"; uname -sr; printf "SYUPTIME\\n"; cat /proc/uptime; printf "SYLOAD\\n"; cat /proc/loadavg; printf "SYMEMORY\\n"; grep -E "^(MemTotal|MemAvailable):" /proc/meminfo; printf "SYDISK\\n"; df -P -B1 /'"""


def parse_linux_health(output: str) -> dict:
    labels = ('SYHOST', 'SYKERNEL', 'SYUPTIME', 'SYLOAD', 'SYMEMORY', 'SYDISK')
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line in labels:
            current = line
            sections[current] = []
        elif current:
            sections[current].append(line)
    try:
        uptime = max(0, int(float(sections['SYUPTIME'][0].split()[0])))
        loads = [float(v) for v in sections['SYLOAD'][0].split()[:3]]
        if len(loads) != 3 or not all(0 <= v < 100000 for v in loads):
            raise ValueError('Invalid loads')
        memory: dict[str, int] = {}
        for line in sections['SYMEMORY']:
            match = re.match(r'^(MemTotal|MemAvailable):\s+(\d+)\s+kB$', line.strip())
            if match:
                memory[match[1]] = int(match[2]) * 1024
        disk_parts = sections['SYDISK'][-1].split()
        disk_total, disk_used = int(disk_parts[1]), int(disk_parts[2])
        if not 0 <= disk_used <= disk_total or not 0 <= memory['MemAvailable'] <= memory['MemTotal']:
            raise ValueError('Invalid capacity')
        return {'hostname': sections['SYHOST'][0][:200], 'kernel': sections['SYKERNEL'][0][:200],
                'uptime_seconds': uptime, 'load1': loads[0], 'load5': loads[1], 'load15': loads[2],
                'memory_total': memory['MemTotal'], 'memory_available': memory['MemAvailable'],
                'disk_total': disk_total, 'disk_used': disk_used}
    except (ValueError, KeyError, IndexError, TypeError):
        raise HTTPException(502, 'Linux host health output was incomplete or unsupported')


@app.get('/api/assets/{aid}/health')
def host_health(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    asset = fetch_asset(aid)
    at = int(time.time())
    status = 'offline'
    result = None
    try:
        result = parse_linux_health(remote_command(asset, HEALTH_COMMAND, x_ssh_password))
        status = 'online'
        return {'asset_id': aid, 'at': at, 'status': status, **result}
    finally:
        # Record failure without copying exception details/credentials into persistence.
        values = result or {}
        with dbconn() as db:
            db.execute("""INSERT INTO host_snapshots(asset_id,at,status,uptime_seconds,load1,load5,load15,
                       memory_total,memory_available,disk_total,disk_used) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                       (aid, at, status, *(values.get(v) for v in ('uptime_seconds', 'load1', 'load5', 'load15',
                               'memory_total', 'memory_available', 'disk_total', 'disk_used'))))
            db.execute("""DELETE FROM host_snapshots WHERE asset_id=? AND id NOT IN
                          (SELECT id FROM host_snapshots WHERE asset_id=? ORDER BY id DESC LIMIT 500)""", (aid, aid))
        audit('host.health', aid, status)


@app.get('/api/assets/{aid}/health/history')
def host_health_history(aid: str, limit: int = 50, _=Depends(require_auth)):
    fetch_asset(aid)
    with dbconn() as db:
        return [dict(row) for row in db.execute("""SELECT * FROM host_snapshots WHERE asset_id=?
                       ORDER BY id DESC LIMIT ?""", (aid, max(1, min(limit, 500))))]


class FileEditModel(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    original_sha256: str = Field(min_length=64, max_length=64, pattern=r'^[a-f0-9]{64}$')
    content: str = Field(max_length=262144)


MAX_EDIT = 256 * 1024


def check_edit_path(path: str):
    if not path or '\x00' in path or '\r' in path or '\n' in path or posixpath.basename(path) in ('', '.', '..'):
        raise HTTPException(422, 'Invalid remote file path')
    return path


def read_remote_text(sftp, path: str) -> tuple[str, str, int]:
    check_edit_path(path)
    info = sftp.stat(path)
    if not stat.S_ISREG(info.st_mode):
        raise HTTPException(422, 'Only regular files can be edited')
    if info.st_size > MAX_EDIT:
        raise HTTPException(413, 'Text editor supports files up to 256 KiB')
    with sftp.file(path, 'rb') as src:
        content = src.read(MAX_EDIT + 1)
    if len(content) > MAX_EDIT:
        raise HTTPException(413, 'Text editor supports files up to 256 KiB')
    if b'\x00' in content:
        raise HTTPException(415, 'Binary files cannot be edited')
    try:
        text = content.decode('utf-8', 'strict')
    except UnicodeDecodeError:
        raise HTTPException(415, 'File is not valid UTF-8 text')
    return text, hashlib.sha256(content).hexdigest(), info.st_mode & 0o777


@app.get('/api/assets/{aid}/files/edit')
def file_edit_read(aid: str, path: str, x_ssh_password: str | None = Header(default=None),
                   _=Depends(require_auth)):
    check_edit_path(path)
    client = ssh_client(fetch_asset(aid), x_ssh_password)
    try:
        with client.open_sftp() as sftp:
            content, sha256, mode = read_remote_text(sftp, path)
    finally:
        client.close()
    audit('sftp.edit.opened', aid)
    return {'path': path, 'content': content, 'sha256': sha256, 'mode': oct(mode)}


@app.put('/api/assets/{aid}/files/edit')
def file_edit_save(aid: str, body: FileEditModel, x_ssh_password: str | None = Header(default=None),
                   _=Depends(require_auth)):
    check_edit_path(body.path)
    content = body.content.encode('utf-8')
    if len(content) > MAX_EDIT or b'\x00' in content:
        raise HTTPException(413, 'Edited text exceeds 256 KiB or contains binary data')
    asset = fetch_asset(aid)
    client = ssh_client(asset, x_ssh_password)
    tmp_path = posixpath.join(posixpath.dirname(body.path), '.switchyard-edit-' + uuid.uuid4().hex)
    try:
        with client.open_sftp() as sftp:
            _, current_hash, mode = read_remote_text(sftp, body.path)
            if not hmac.compare_digest(current_hash, body.original_sha256):
                raise HTTPException(409, 'Remote file changed since opening; reload before saving')
            # OpenSSH posix-rename extension is required to replace the target atomically.
            # Check support prior to staging the file; preserve original permissions.
            if not callable(getattr(sftp, 'posix_rename', None)):
                raise HTTPException(501, 'Remote server does not support atomic file replacement')
            try:
                with sftp.file(tmp_path, 'wx') as temp:
                    temp.write(content)
                    temp.flush()
                sftp.chmod(tmp_path, mode)
                # A final optimistic-content check narrows (but cannot eliminate) TOCTOU races.
                _, latest_hash, _ = read_remote_text(sftp, body.path)
                if not hmac.compare_digest(latest_hash, body.original_sha256):
                    raise HTTPException(409, 'Remote file changed before replacement; reload before saving')
                try:
                    sftp.posix_rename(tmp_path, body.path)
                except OSError:
                    raise HTTPException(501, 'Remote server rejected atomic replacement; original file retained')
            finally:
                try:
                    sftp.remove(tmp_path)
                except OSError:
                    pass
    finally:
        client.close()
    audit('sftp.edit.saved', aid)
    return {'ok': True, 'sha256': hashlib.sha256(content).hexdigest()}


@app.get('/api/assets/{aid}/docker/stacks')
def docker_stacks(aid: str, x_ssh_password: str | None = Header(default=None), _=Depends(require_auth)):
    result = remote_command(fetch_asset(aid), 'docker compose ls --all --format json', x_ssh_password)
    try:
        items = json.loads(result)
        if not isinstance(items, list):
            raise ValueError('Unexpected response')
        return [{'name': str(v.get('Name', ''))[:180], 'status': str(v.get('Status', ''))[:180],
                 'config_files': str(v.get('ConfigFiles', ''))[:2048]}
                for v in items if isinstance(v, dict)]
    except (ValueError, TypeError):
        raise HTTPException(502, 'Docker Compose project listing could not be parsed')


class StackAction(BaseModel):
    project: str = Field(min_length=1, max_length=128, pattern=r'^[a-z0-9][a-z0-9_-]*$')
    action: Literal['start', 'stop', 'restart']


@app.post('/api/assets/{aid}/docker/stacks/action')
def docker_stack_action(aid: str, body: StackAction, x_ssh_password: str | None = Header(default=None),
                        _=Depends(require_auth)):
    asset = fetch_asset(aid)
    projects = docker_stacks(aid, x_ssh_password, _)
    matches = [p for p in projects if p['name'] == body.project]
    if len(matches) != 1:
        raise HTTPException(404, 'Docker Compose project not found in remote inventory')
    configs = matches[0]['config_files'].split(',')
    if not configs or len(configs) > 8 or any(not c.strip().startswith('/') or '\x00' in c or '\n' in c for c in configs):
        raise HTTPException(422, 'Compose project has no usable absolute configuration path')
    flags = ' '.join('-f ' + shlex.quote(p.strip()) for p in configs)
    command = f'docker compose {flags} -p {shlex.quote(body.project)} {body.action}'
    remote_command(asset, command, x_ssh_password)
    audit('compose.' + body.action, f'{aid}:{body.project}')
    return {'ok': True}


@app.get('/')
def homepage():
    return FileResponse(ROOT / 'static' / 'index.html', media_type='text/html',
                        headers={'Cache-Control': 'no-store'})


# Serve the packaged Guacamole and Debian SPICE browser modules (including
# relative ES module imports) without exposing application persistence.
app.mount('/static', StaticFiles(directory=str(ROOT / 'static')), name='static')


@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    spice_viewer = request.url.path == '/static/spice-view.html'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN' if spice_viewer else 'DENY'
    response.headers['Cache-Control'] = 'no-store' if request.url.path.startswith('/api/') else response.headers.get('Cache-Control', 'no-cache')
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; img-src 'self' data: blob:; "
        "frame-src 'self'; object-src 'none'; base-uri 'none'; "
        + ("frame-ancestors 'self'; " if spice_viewer else "frame-ancestors 'none'; ")
        + "form-action 'self'"
    )
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# Remote desktops use the same session, origin, Vaultwarden and audit controls.
desktops.install_desktops(app, dbconn, require_auth, session_from_ws, vault_password, audit, saved_password, put_saved_password)
