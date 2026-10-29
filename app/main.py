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
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Cookie, Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.getenv('SWITCHYARD_DATA', '/data'))
DB_FILE = DATA / 'switchyard.sqlite3'
HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'true').lower() == 'true'
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


app = FastAPI(title='Switchyard', version='0.4.0', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


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
        existing = db.execute('SELECT 1 FROM users LIMIT 1').fetchone()
        if not existing:
            pfile = os.getenv('ADMIN_PASSWORD_FILE', '')
            if not pfile:
                raise RuntimeError('ADMIN_PASSWORD_FILE is mandatory on first boot')
            password = Path(pfile).read_text().strip('\r\n')
            if len(password) < 14:
                raise RuntimeError('Admin bootstrap password must be at least 14 characters')
            db.execute('INSERT INTO users(id,username,password_hash,created_at) VALUES(1,?,?,?)', ('admin', HASHER.hash(password), int(time.time())))
        db.execute('DELETE FROM sessions WHERE expires_at < ?', (int(time.time()),))
    desktops.initialize(dbconn)
    keys = DATA / 'keys'
    keys.mkdir(exist_ok=True, mode=0o700)
    os.chmod(keys, 0o700)
    bw = DATA / 'bw'
    bw.mkdir(exist_ok=True, mode=0o700)
    os.chmod(bw, 0o700)


def audit(action: str, target: str = '', outcome: str = 'ok'):
    with dbconn() as db:
        db.execute('INSERT INTO audit(at, actor, action, target, outcome) VALUES(?,?,?,?,?)',
                   (int(time.time()), 'admin', action[:80], target[:255], outcome[:100]))


def session_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def configured_remote_origin() -> str:
    return os.getenv('PUBLIC_ORIGIN', '').strip().rstrip('/')


def browser_origin(scope) -> tuple[str, bool]:
    """Require an explicitly trusted hostname. Never trust forwarded IP headers."""
    host = (scope.headers.get('host') or '').lower()
    if not host or '/' in host or '@' in host or ',' in host or '\\' in host:
        raise HTTPException(403, 'Untrusted host')
    remote = configured_remote_origin()
    if remote:
        parsed = urlsplit(remote)
        if parsed.scheme == 'http' and parsed.netloc.lower() == host:
            # Legacy test/development origin only; production deploy script disallows HTTP.
            return remote, False
        if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
            raise HTTPException(503, 'Invalid PUBLIC_ORIGIN configuration')
        if host == parsed.netloc.lower():
            return remote, True
    lan_hosts = [item.strip().rstrip('/') for item in os.getenv('LAN_ORIGINS', '').split(',') if item.strip()]
    for lan in lan_hosts:
        parsed = urlsplit(lan)
        if parsed.scheme not in ('http', 'https') or parsed.path or parsed.query or parsed.fragment:
            raise HTTPException(503, 'Invalid LAN_ORIGINS configuration')
        if host == parsed.netloc.lower():
            return lan, False
    # Bare private/link-local addresses (and localhost) can be reached on the LAN.
    address = host
    if address.startswith('['):
        address = address[1:].split(']', 1)[0]
    else:
        address = address.rsplit(':', 1)[0] if ':' in address else address
    try:
        ip = ipaddress.ip_address(address)
        trusted = any(ip in network for network in (
            ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'), ipaddress.ip_network('fc00::/7'),
            ipaddress.ip_network('fe80::/10'), ipaddress.ip_network('::1/128'))) 
    except ValueError:
        trusted = address == 'localhost'
    if trusted:
        # The network layer (firewall) must actually limit this endpoint to LAN.
        scheme = 'https' if scope.url.scheme in ('https', 'wss') else 'http'
        return f'{scheme}://{host}', False
    # Preserve existing configured HTTP development test origins, but never
    # mistake them for an external MFA-optional public deployment.
    if remote.startswith('http://') and urlsplit(remote).netloc.lower() == host:
        return remote, False
    raise HTTPException(403, 'Host is not permitted. Configure LAN_ORIGINS or PUBLIC_ORIGIN.')


def valid_session(token: str | None, require_mfa: bool = False) -> bool:
    if not token or len(token) != 64:
        return False
    with dbconn() as db:
        row = db.execute('SELECT mfa_verified FROM sessions WHERE token_hash=? AND expires_at>?',
                         (session_hash(token), int(time.time()))).fetchone()
        return bool(row and (not require_mfa or row['mfa_verified']))


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
    key_path = os.getenv('MFA_KEY_FILE', '')
    try:
        if not key_path:
            raise OSError('MFA_KEY_FILE not configured')
        return Fernet(Path(key_path).read_bytes().strip())
    except (OSError, ValueError) as exc:
        raise HTTPException(503, 'MFA encryption key not available') from exc


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


@app.get('/healthz')
def health():
    return {'status': 'ok', 'version': '0.4.0'}


@app.post('/api/login')
def login(body: Credentials, request: Request, response: Response):
    verify_origin(request)
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
            if not stored['mfa_secret']:
                raise HTTPException(403, 'Set up authenticator MFA in Settings from the LAN before remote access')
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
    return {'username': 'admin', 'role': 'administrator'}


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
    from urllib.parse import quote
    issuer = 'Switchyard'
    uri = f'otpauth://totp/{issuer}:admin?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30'
    audit('mfa.enrollment.started')
    return {'secret': secret, 'otpauth_uri': uri, 'expires_seconds': 600}


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
    return dict(row)


@app.get('/api/assets')
def list_assets(_=Depends(require_auth)):
    with dbconn() as db:
        return [asset_as_dict(x) for x in db.execute('SELECT * FROM assets ORDER BY environment,label')]


@app.post('/api/assets', status_code=201)
def create_asset(body: AssetModel, _=Depends(require_auth)):
    aid = str(uuid.uuid4())
    now = int(time.time())
    with dbconn() as db:
        db.execute('''INSERT INTO assets(id,label,host,port,username,environment,auth_type,
                      credential_ref,key_file,use_tmux,note,created_at,updated_at)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                   (aid, body.label, body.host, body.port, body.username, body.environment,
                    body.auth_type, body.credential_ref, body.key_file, int(body.use_tmux),
                    body.note, now, now))
    audit('asset.created', aid)
    return {'id': aid}


@app.put('/api/assets/{aid}')
def update_asset(aid: str, body: AssetModel, _=Depends(require_auth)):
    with dbconn() as db:
        cur = db.execute('''UPDATE assets SET label=?,host=?,port=?,username=?,environment=?,
                auth_type=?,credential_ref=?,key_file=?,use_tmux=?,note=?,updated_at=? WHERE id=?''',
                (body.label, body.host, body.port, body.username, body.environment,
                 body.auth_type, body.credential_ref, body.key_file, int(body.use_tmux),
                 body.note, int(time.time()), aid))
        if cur.rowcount != 1:
            raise HTTPException(404, 'Asset not found')
    audit('asset.updated', aid)
    return {'ok': True}


@app.delete('/api/assets/{aid}')
def delete_asset(aid: str, _=Depends(require_auth)):
    with dbconn() as db:
        cur = db.execute('DELETE FROM assets WHERE id=?', (aid,))
        if not cur.rowcount:
            raise HTTPException(404, 'Asset not found')
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
        manifest = {
            'application': 'Switchyard', 'format': 1, 'version': '0.4.0',
            'created_utc': datetime.now(timezone.utc).isoformat(),
            'files': {'switchyard.sqlite3': hashlib.sha256(content).hexdigest(),
                      'known_hosts': hashlib.sha256(hosts).hexdigest()},
            'excluded': ['sessions', 'SSH private keys', 'Vaultwarden CLI state', 'admin bootstrap secret'],
        }
        output = _io.BytesIO()
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', json.dumps(manifest, indent=2))
            archive.writestr('switchyard.sqlite3', content)
            archive.writestr('known_hosts', hosts)
    return Response(output.getvalue(), media_type='application/zip',
                    headers={'Content-Disposition': 'attachment; filename="switchyard-backup.zip"', 'Cache-Control': 'no-store'})


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
    allow_http = os.getenv('ALLOW_HTTP_VAULT', 'false').lower() == 'true'
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
    password = vault_password(asset['credential_ref']) if asset['auth_type'] == 'vault' else (interactive_password if asset['auth_type'] == 'interactive' else None)
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
    except Exception:
        client.close()
        raise HTTPException(502, 'SSH connection failed. Verify host trust, credentials and network access.')
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
                            'size': x.st_size or 0, 'modified': x.st_mtime or 0})
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
                with sftp.file(target, 'x') as f:
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
                with sftp.file(tmp_path, 'x') as temp:
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
desktops.install_desktops(app, dbconn, require_auth, session_from_ws, vault_password, audit)
