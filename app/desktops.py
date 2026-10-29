"""Persistent RDP/VNC inventory and authenticated private guacd bridge."""
from __future__ import annotations

import asyncio
import codecs
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Literal

from fastapi import Depends, HTTPException, WebSocket, WebSocketDisconnect, Response, Request
from pydantic import BaseModel, Field, field_validator, model_validator

from .guac import DesktopSettings, ProtocolError, frame, handshake
from .spice import connect_spice, relay_spice, parse_virt_viewer
from .probes import probe
from . import desktop_history

NAME_RE = re.compile(r'^[\w][\w .:@/()-]{0,119}$', re.UNICODE)
HOST_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$')
MAX_DESKTOPS = 500
MAX_LIVE_SESSIONS = 8
TICKET_TTL = 30.0
TICKETS: dict[str, 'Ticket'] = {}
SPICE_GROUPS: dict[str, 'SpiceGroup'] = {}
MAX_SPICE_CHANNELS = 16
SPICE_GRACE = 25.0
SPICE_MAX_AGE = 8 * 3600.0
ACTIVE: dict[str, dict] = {}
ACTIVE_TASKS: dict[str, set[asyncio.Task]] = {}
GUARD = threading.RLock()


@dataclass
class Ticket:
    desktop_id: str
    name: str
    settings: DesktopSettings
    expires: float
    session_hash: str


@dataclass
class SpiceGroup:
    session_id: str
    desktop_id: str
    settings: DesktopSettings
    created: float
    channels: int = 0
    idle_deadline: float = 0.0
    session_hash: str = ''


class DesktopInput(BaseModel):
    label: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal['rdp', 'vnc', 'spice']
    username: str = Field(default='', max_length=128)
    domain: str = Field(default='', max_length=128)
    environment: str = Field(default='', max_length=80)
    note: str = Field(default='', max_length=500)
    auth_type: Literal['interactive', 'vault', 'none'] = 'interactive'
    credential_ref: str = Field(default='', max_length=120)
    password: str | None = Field(default=None, max_length=4096, exclude=True, repr=False)
    clear_password: bool = Field(default=False, exclude=True)
    security: Literal['nla', 'tls', 'rdp', 'any'] = 'nla'
    ignore_cert: bool = False
    spice_tls: bool = False
    read_only: bool = False
    favorite: bool = False
    width: int = Field(default=1366, ge=640, le=3840)
    height: int = Field(default=768, ge=480, le=2160)
    dpi: int = Field(default=96, ge=72, le=192)

    @field_validator('label')
    @classmethod
    def label_valid(cls, value: str) -> str:
        if not NAME_RE.fullmatch(value) or not value.strip():
            raise ValueError('Invalid display name')
        return value.strip()

    @field_validator('host')
    @classmethod
    def host_valid(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if not HOST_RE.fullmatch(value) or '..' in value:
                raise ValueError('Invalid DNS hostname or IP address')
            return value.lower()

    @model_validator(mode='after')
    def check_auth(self):
        if self.auth_type == 'vault' and not self.credential_ref:
            raise ValueError('Vaultwarden item ID required for vault authentication')
        if self.protocol == 'vnc' and (self.domain or self.security != 'nla' or self.ignore_cert):
            # VNC does not support RDP domain/security configuration.
            raise ValueError('RDP security settings are not available for VNC')
        if self.protocol == 'spice':
            if self.domain or self.security != 'nla':
                raise ValueError('RDP security and domain settings do not apply to SPICE')
            if self.read_only:
                raise ValueError('Read-only SPICE sessions cannot be enforced by this HTML5 client')
            if self.ignore_cert and not self.spice_tls:
                raise ValueError('Certificate bypass requires SPICE TLS')
        elif self.spice_tls:
            raise ValueError('SPICE TLS option is only available to SPICE connections')
        return self


class InventoryImport(BaseModel):
    format: Literal['switchyard-desktops-v1']
    connections: list[DesktopInput] = Field(min_length=1, max_length=MAX_DESKTOPS)

    @model_validator(mode='before')
    @classmethod
    def reject_credential_material(cls, value):
        if isinstance(value, dict) and isinstance(value.get('connections'), list):
            allowed = set(DesktopInput.model_fields) - {'password', 'clear_password'}
            for conn in value['connections']:
                if isinstance(conn, dict) and set(conn) - allowed:
                    raise ValueError('Connection export contains unknown fields; credentials not imported')
        return value


class VirtViewerInput(BaseModel):
    contents: str = Field(min_length=1, max_length=16384)


class BatchProbeInput(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=20)

    @field_validator('ids')
    @classmethod
    def unique_targets(cls, value):
        if len(set(value)) != len(value):
            raise ValueError('Duplicate desktop IDs are not allowed')
        return value


class TicketInput(BaseModel):
    password: str | None = Field(default=None, max_length=4096)
    width: int = Field(default=1366, ge=640, le=3840)
    height: int = Field(default=768, ge=480, le=2160)
    dpi: int = Field(default=96, ge=72, le=192)


def desktop_row(row) -> dict:
    result = dict(row)
    for key in ('ignore_cert', 'read_only', 'spice_tls', 'favorite'):
        result[key] = bool(result[key])
    return result


def initialize(dbconn):
    desktop_history.initialize(dbconn)
    with dbconn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS desktop_connections (
          id TEXT PRIMARY KEY, label TEXT NOT NULL, protocol TEXT NOT NULL
          CHECK(protocol IN ('rdp','vnc','spice')),
          host TEXT NOT NULL, port INTEGER NOT NULL,
          username TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
          environment TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
          auth_type TEXT NOT NULL CHECK(auth_type IN ('interactive','vault','none')),
          credential_ref TEXT NOT NULL DEFAULT '',
          security TEXT NOT NULL DEFAULT 'nla', ignore_cert INTEGER NOT NULL DEFAULT 0,
          read_only INTEGER NOT NULL DEFAULT 0,
          spice_tls INTEGER NOT NULL DEFAULT 0, favorite INTEGER NOT NULL DEFAULT 0,
          width INTEGER NOT NULL DEFAULT 1366, height INTEGER NOT NULL DEFAULT 768,
          dpi INTEGER NOT NULL DEFAULT 96,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS desktop_environment_idx
          ON desktop_connections(environment, label);
        ''')
        # The 0.4.0 desktop table may already exist after an RDP/VNC alpha install.
        columns = {row['name'] for row in db.execute('PRAGMA table_info(desktop_connections)')}
        if 'spice_tls' not in columns:
            db.execute('ALTER TABLE desktop_connections ADD COLUMN spice_tls INTEGER NOT NULL DEFAULT 0')
        if 'favorite' not in columns:
            db.execute('ALTER TABLE desktop_connections ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0')
        # SQLite cannot alter an existing table CHECK constraint in place.
        # Newly created 0.4.0 tables permit SPICE; older tables are upgraded below.
        ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='desktop_connections'").fetchone()[0]
        if "'spice'" not in ddl:
            db.executescript('''
            ALTER TABLE desktop_connections RENAME TO desktop_connections_old;
            CREATE TABLE desktop_connections (
              id TEXT PRIMARY KEY, label TEXT NOT NULL, protocol TEXT NOT NULL
              CHECK(protocol IN ('rdp','vnc','spice')),
              host TEXT NOT NULL, port INTEGER NOT NULL,
              username TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
              environment TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
              auth_type TEXT NOT NULL CHECK(auth_type IN ('interactive','vault','none')),
              credential_ref TEXT NOT NULL DEFAULT '',
              security TEXT NOT NULL DEFAULT 'nla', ignore_cert INTEGER NOT NULL DEFAULT 0,
              read_only INTEGER NOT NULL DEFAULT 0, spice_tls INTEGER NOT NULL DEFAULT 0,
              favorite INTEGER NOT NULL DEFAULT 0, width INTEGER NOT NULL DEFAULT 1366, height INTEGER NOT NULL DEFAULT 768,
              dpi INTEGER NOT NULL DEFAULT 96,
              created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );
            INSERT INTO desktop_connections (
              id,label,protocol,host,port,username,domain,environment,note,
              auth_type,credential_ref,security,ignore_cert,read_only,
              spice_tls,favorite,width,height,dpi,created_at,updated_at)
            SELECT id,label,protocol,host,port,username,domain,environment,note,
              auth_type,credential_ref,security,ignore_cert,read_only,
              spice_tls,favorite,width,height,dpi,created_at,updated_at
            FROM desktop_connections_old;
            DROP TABLE desktop_connections_old;
            CREATE INDEX IF NOT EXISTS desktop_environment_idx
              ON desktop_connections(environment, label);
            ''')


def cleanup_tickets():
    now = time.monotonic()
    for key in list(TICKETS):
        if TICKETS[key].expires <= now:
            del TICKETS[key]


def cleanup_spice_groups():
    now = time.monotonic()
    for token, group in list(SPICE_GROUPS.items()):
        if group.channels == 0 and (group.idle_deadline <= now or now - group.created > SPICE_MAX_AGE):
            SPICE_GROUPS.pop(token, None)
            ACTIVE.pop(group.session_id, None)
            ACTIVE_TASKS.pop(group.session_id, None)


def session_fingerprint(cookie: str) -> str:
    return hashlib.sha256(cookie.encode('utf-8')).hexdigest() if cookie else ''


def acquire_spice_channel(token: str, cookie: str = '') -> SpiceGroup | None:
    with GUARD:
        cleanup_tickets()
        cleanup_spice_groups()
        group = SPICE_GROUPS.get(token)
        now = time.monotonic()
        fingerprint = session_fingerprint(cookie)
        if group is not None and not hmac.compare_digest(group.session_hash, fingerprint):
            return None
        if group is None:
            ticket = TICKETS.get(token)
            if (ticket is None or ticket.settings.protocol != 'spice'
                    or not hmac.compare_digest(ticket.session_hash, fingerprint)
                    or len(ACTIVE) >= MAX_LIVE_SESSIONS):
                return None
            TICKETS.pop(token)
            session_id = uuid.uuid4().hex
            # Password authentication is performed in the browser; the transport
            # need only remember the target, not the resolved vault credential.
            group = SpiceGroup(session_id, ticket.desktop_id,
                               replace(ticket.settings, password=''), now, session_hash=fingerprint)
            SPICE_GROUPS[token] = group
            ACTIVE[session_id] = {'desktop_id': ticket.desktop_id, 'label': ticket.name,
                                  'protocol': 'spice', 'started_at': int(time.time())}
        if now - group.created > SPICE_MAX_AGE or group.channels >= MAX_SPICE_CHANNELS:
            return None
        group.channels += 1
        group.idle_deadline = 0
        return group


def release_spice_channel(token: str):
    with GUARD:
        group = SPICE_GROUPS.get(token)
        if group:
            group.channels = max(0, group.channels - 1)
            if not group.channels:
                group.idle_deadline = time.monotonic() + SPICE_GRACE


def consume_ticket(token: str, cookie: str = '') -> Ticket | None:
    with GUARD:
        cleanup_tickets()
        ticket = TICKETS.get(token)
        if ticket is None or not hmac.compare_digest(ticket.session_hash, session_fingerprint(cookie)):
            return None
        return TICKETS.pop(token)


def resolve_settings(row: dict, payload: TicketInput, vault_password, saved_password=lambda *_: None) -> DesktopSettings:
    password = ''
    if row['auth_type'] == 'vault':
        password = vault_password(row['credential_ref'])
    elif row['auth_type'] == 'interactive':
        password = payload.password or saved_password('desktop', row['id']) or ''
    return DesktopSettings(
        protocol=row['protocol'], host=row['host'], port=row['port'],
        username=row['username'], password=password, domain=row['domain'],
        security=row['security'], ignore_cert=bool(row['ignore_cert']),
        read_only=bool(row['read_only']), width=payload.width,
        height=payload.height, dpi=payload.dpi,
        spice_tls=bool(row.get('spice_tls', False)),
    )


async def connect_guacd():
    return await asyncio.open_connection('guacd',
                                         4822)


def install_desktops(app, dbconn, require_auth, session_from_ws, vault_password, audit, saved_password=None, put_saved_password=None):
    def fetch(did: str) -> dict:
        with dbconn() as db:
            row = db.execute('SELECT * FROM desktop_connections WHERE id=?', (did,)).fetchone()
        if not row:
            raise HTTPException(404, 'Desktop connection not found')
        result = desktop_row(row)
        with dbconn() as db:
            result['has_saved_password'] = bool(db.execute(
                "SELECT 1 FROM saved_passwords WHERE kind='desktop' AND entity_id=?", (did,)).fetchone())
        return result

    @app.get('/api/desktops')
    def desktop_list(_=Depends(require_auth)):
        with dbconn() as db:
            records = [desktop_row(row) for row in db.execute(
                'SELECT * FROM desktop_connections ORDER BY favorite DESC, environment, label COLLATE NOCASE')]
            saved = {row['entity_id'] for row in db.execute("SELECT entity_id FROM saved_passwords WHERE kind='desktop'")}
            for record in records:
                record['has_saved_password'] = record['id'] in saved
            return records

    @app.get('/api/desktops/export')
    def desktop_export(_=Depends(require_auth)):
        fields = tuple(field for field in DesktopInput.model_fields if field not in ('password','clear_password'))
        with dbconn() as db:
            records = [{key: desktop_row(row)[key] for key in fields} for row in db.execute(
                'SELECT * FROM desktop_connections ORDER BY label COLLATE NOCASE LIMIT ?',
                (MAX_DESKTOPS,))]
        audit('desktop.inventory.exported', str(len(records)))
        return Response(__import__('json').dumps({'format':'switchyard-desktops-v1',
                         'connections':records}, ensure_ascii=False),
                        media_type='application/json',
                        headers={'Content-Disposition':'attachment; filename="switchyard-desktops.json"',
                                 'Cache-Control':'no-store'})

    @app.post('/api/desktops/import')
    def desktop_import(body: InventoryImport, _=Depends(require_auth)):
        now = int(time.time())
        imported_ids = []
        with dbconn() as db:
            count = db.execute('SELECT count(*) FROM desktop_connections').fetchone()[0]
            if count + len(body.connections) > MAX_DESKTOPS:
                raise HTTPException(409, 'Import exceeds desktop inventory limit')
            # The entire import commits atomically, or fails without partial records.
            for item in body.connections:
                row = item.model_dump()
                if row['port'] is None:
                    row['port'] = {'rdp':3389,'vnc':5900,'spice':5901}[row['protocol']]
                did = str(uuid.uuid4())
                db.execute("""INSERT INTO desktop_connections
                    (id,label,protocol,host,port,username,domain,environment,note,
                     auth_type,credential_ref,security,ignore_cert,read_only,
                     width,height,dpi,spice_tls,favorite,created_at,updated_at)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (did, *(row[k] for k in (
                      'label','protocol','host','port','username','domain','environment','note',
                      'auth_type','credential_ref','security','ignore_cert','read_only',
                      'width','height','dpi','spice_tls','favorite')),now,now))
                imported_ids.append(did)
        audit('desktop.inventory.imported', str(len(imported_ids)))
        return {'created':len(imported_ids), 'ids':imported_ids}

    @app.post('/api/desktops', status_code=201)
    def desktop_create(body: DesktopInput, _=Depends(require_auth)):
        record = body.model_dump()
        if record['port'] is None:
            record['port'] = {'rdp': 3389, 'vnc': 5900, 'spice': 5901}[record['protocol']]
        did = str(uuid.uuid4()); now = int(time.time())
        with dbconn() as db:
            if db.execute('SELECT count(*) FROM desktop_connections').fetchone()[0] >= MAX_DESKTOPS:
                raise HTTPException(409, 'Desktop connection inventory limit reached')
            db.execute('''INSERT INTO desktop_connections
                (id,label,protocol,host,port,username,domain,environment,note,
                 auth_type,credential_ref,security,ignore_cert,read_only,width,height,dpi,spice_tls,favorite,
                 created_at,updated_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                 (did, *(record[k] for k in (
                   'label','protocol','host','port','username','domain','environment','note',
                   'auth_type','credential_ref','security','ignore_cert','read_only',
                   'width','height','dpi','spice_tls','favorite')), now, now))
        if put_saved_password:
            with dbconn() as db:
                put_saved_password(db, 'desktop', did, body.password, body.clear_password)
        audit('desktop.created', did)
        return fetch(did)

    @app.put('/api/desktops/{did}')
    def desktop_update(did: str, body: DesktopInput, _=Depends(require_auth)):
        old = fetch(did)
        values = body.model_dump()
        if values['port'] is None:
            values['port'] = {'rdp': 3389, 'vnc': 5900, 'spice': 5901}[values['protocol']]
        with dbconn() as db:
            db.execute('''UPDATE desktop_connections SET
                label=?,protocol=?,host=?,port=?,username=?,domain=?,environment=?,
                note=?,auth_type=?,credential_ref=?,security=?,ignore_cert=?,read_only=?,
                width=?,height=?,dpi=?,spice_tls=?,favorite=?,updated_at=? WHERE id=?''',
                (*(values[k] for k in (
                  'label','protocol','host','port','username','domain','environment','note',
                  'auth_type','credential_ref','security','ignore_cert','read_only',
                  'width','height','dpi','spice_tls','favorite')), int(time.time()), did))
        if put_saved_password:
            with dbconn() as db:
                put_saved_password(db, 'desktop', did, body.password, body.clear_password)
        audit('desktop.updated', did)
        return fetch(did)

    @app.post('/api/desktops/{did}/duplicate', status_code=201)
    def desktop_duplicate(did: str, _=Depends(require_auth)):
        original = fetch(did)
        new_id = str(uuid.uuid4())
        now = int(time.time())
        with dbconn() as db:
            if db.execute('SELECT count(*) FROM desktop_connections').fetchone()[0] >= MAX_DESKTOPS:
                raise HTTPException(409, 'Desktop connection inventory limit reached')
            db.execute("""INSERT INTO desktop_connections
                (id,label,protocol,host,port,username,domain,environment,note,
                 auth_type,credential_ref,security,ignore_cert,read_only,spice_tls,
                 favorite,width,height,dpi,created_at,updated_at)
                SELECT ?, ?, protocol,host,port,username,domain,environment,note,
                 auth_type,credential_ref,security,ignore_cert,read_only,spice_tls,
                 0,width,height,dpi,?,? FROM desktop_connections WHERE id=?""",
                 (new_id, original['label'][:110]+' (copy)',now,now,did))
        audit('desktop.duplicated', did)
        return fetch(new_id)

    @app.delete('/api/desktops/{did}')
    def desktop_delete(did: str, _=Depends(require_auth)):
        fetch(did)
        with GUARD:
            cleanup_spice_groups()
            if any(session['desktop_id'] == did for session in ACTIVE.values()):
                raise HTTPException(409, 'Disconnect active desktop sessions before deletion')
            for token in [k for k,v in TICKETS.items() if v.desktop_id == did]:
                TICKETS.pop(token, None)
        with dbconn() as db:
            db.execute('DELETE FROM desktop_connections WHERE id=?', (did,))
        with dbconn() as db:
            db.execute("DELETE FROM saved_passwords WHERE kind='desktop' AND entity_id=?", (did,))
        audit('desktop.deleted', did)
        return {'ok': True}

    @app.post('/api/desktops/{did}/ticket')
    def desktop_ticket(did: str, payload: TicketInput, response: Response, request: Request, _=Depends(require_auth)):
        record = fetch(did)
        settings = resolve_settings(record, payload, vault_password, saved_password or (lambda *_: None))
        with GUARD:
            cleanup_tickets()
            cleanup_spice_groups()
            if len(TICKETS) >= 40 or len(ACTIVE) >= MAX_LIVE_SESSIONS:
                raise HTTPException(429, 'Desktop connection capacity reached')
            token = secrets.token_urlsafe(32)
            TICKETS[token] = Ticket(did, record['label'], settings, time.monotonic() + TICKET_TTL,
                                     session_fingerprint(request.cookies.get('switchyard_session','')))
        audit('desktop.ticket', did)
        response.headers['Cache-Control'] = 'no-store'
        result = {'ticket': token, 'expires_in': 30, 'protocol': record['protocol']}
        # The official HTML5 SPICE library must calculate its own password
        # challenge in browser memory; unlike guacd it cannot keep this secret
        # entirely server-side. This field must never be persisted or URL-encoded.
        if record['protocol'] == 'spice':
            result['spice_password'] = settings.password
        return result

    @app.post('/api/desktops/{did}/probe')
    async def desktop_probe(did: str, _=Depends(require_auth)):
        row = fetch(did)
        result = await probe(row['host'], row['port'],
                             row['protocol'] == 'spice' and bool(row['spice_tls']))
        audit('desktop.probe', did, 'success' if result['reachable'] else 'failed')
        return result

    @app.post('/api/desktops/probes')
    async def desktop_batch_probes(body: BatchProbeInput, _=Depends(require_auth)):
        records = [fetch(did) for did in body.ids]
        semaphore = asyncio.Semaphore(4)
        async def check(row):
            async with semaphore:
                try:
                    result = await probe(row['host'], row['port'],
                       row['protocol'] == 'spice' and bool(row['spice_tls']))
                except (OSError, asyncio.TimeoutError, ValueError, ssl.SSLError):
                    # One broken host must not discard useful results for others.
                    result = {'reachable':False,'tls_validated':False,
                              'elapsed_ms':None,'message':'Probe failed'}
                return {'id':row['id'], 'label':row['label'], **result}
        results = await asyncio.gather(*(check(row) for row in records))
        audit('desktop.probe.batch', str(len(results)))
        return {'count':len(results), 'results':results}

    @app.post('/api/desktops/spice/import-vv')
    def import_virt_viewer(payload: VirtViewerInput, response: Response, request: Request, _=Depends(require_auth)):
        try:
            label, settings = parse_virt_viewer(payload.contents)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        with GUARD:
            cleanup_tickets()
            cleanup_spice_groups()
            if len(TICKETS) >= 40 or len(ACTIVE) >= MAX_LIVE_SESSIONS:
                raise HTTPException(429, 'Desktop connection capacity reached')
            token = secrets.token_urlsafe(32)
            TICKETS[token] = Ticket('one-time:'+uuid.uuid4().hex, label,
                                     settings, time.monotonic()+TICKET_TTL,
                                     session_fingerprint(request.cookies.get('switchyard_session','')))
        response.headers['Cache-Control'] = 'no-store'
        audit('desktop.spice.vv_ticket', 'one-time')
        return {'ticket': token, 'expires_in': 30, 'protocol': 'spice',
                'label': label, 'spice_password': settings.password}

    @app.get('/api/desktops/gateway/status')
    async def desktop_gateway_status(_=Depends(require_auth)):
        """Non-credentialed, bounded readiness check for the private guacd gateway."""
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(connect_guacd(), timeout=3)
            return {'ready': True, 'transport': 'private-tcp', 'protocols': ['rdp', 'vnc']}
        except (OSError, asyncio.TimeoutError, ValueError):
            return {'ready': False, 'transport': 'private-tcp',
                    'protocols': ['rdp', 'vnc'],
                    'message': 'Private desktop gateway unreachable'}
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2)
                except (OSError, asyncio.TimeoutError):
                    pass

    @app.get('/api/desktops/sessions/history')
    def desktop_sessions_history(limit: int = 50,
                                 protocol: Literal['rdp','vnc','spice'] | None = None,
                                 outcome: Literal['opening','open','closed','failed'] | None = None,
                                 _=Depends(require_auth)):
        return desktop_history.list_recent(dbconn, limit, protocol, outcome)

    @app.get('/api/desktops/sessions/export')
    def desktop_sessions_export(_=Depends(require_auth)):
        audit('desktop.sessions.exported', 'csv')
        return Response(desktop_history.export_csv(dbconn),
            media_type='text/csv; charset=utf-8',
            headers={'Content-Disposition':'attachment; filename="switchyard-desktop-sessions.csv"',
                     'Cache-Control':'no-store'})

    @app.get('/api/desktops/sessions/active')
    def desktop_sessions(_=Depends(require_auth)):
        with GUARD:
            return [{'id': k, **v} for k,v in ACTIVE.items()]

    @app.post('/api/desktops/sessions/{sid}/disconnect')
    async def desktop_force_disconnect(sid: str, _=Depends(require_auth)):
        with GUARD:
            pending = list(ACTIVE_TASKS.get(sid, ()))
        if not pending:
            raise HTTPException(404, 'Active desktop session not found')
        for task in pending:
            task.cancel()
        audit('desktop.session.disconnected', sid)
        return {'ok':True, 'channels_terminated':len(pending)}

    @app.websocket('/ws/desktop/{token}')
    async def desktop_socket(ws: WebSocket, token: str):
        if not session_from_ws(ws):
            await ws.close(code=4401)
            return
        ticket = consume_ticket(token, ws.cookies.get('switchyard_session',''))
        if ticket is None or ticket.settings.protocol == 'spice':
            await ws.close(code=4404)
            return
        with GUARD:
            if len(ACTIVE) >= MAX_LIVE_SESSIONS:
                await ws.close(code=4429)
                return
            session_id = uuid.uuid4().hex
            ACTIVE[session_id] = {
                'desktop_id': ticket.desktop_id, 'label': ticket.name,
                'protocol': ticket.settings.protocol, 'started_at': int(time.time())}
        reader = None; writer = None
        with GUARD:
            ACTIVE_TASKS[session_id] = {asyncio.current_task()}
        desktop_history.started(dbconn, session_id, ticket.desktop_id, ticket.name, ticket.settings.protocol)
        failed = False
        await ws.accept()
        try:
            reader, writer = await asyncio.wait_for(connect_guacd(), timeout=8)
            ready = await handshake(reader, writer, ticket.settings)
            # A ready frame gives Guacamole.Client its negotiated connection ID.
            await ws.send_text(frame(*ready).decode('utf-8'))
            desktop_history.opened(dbconn, session_id)
            audit('desktop.opened', ticket.desktop_id)
            # Drop strong reference to the resolved password after the handshake.
            ticket = None

            async def from_guacd():
                decoder = codecs.getincrementaldecoder('utf-8')('strict')
                while True:
                    chunk = await reader.read(32768)
                    if not chunk:
                        break
                    part = decoder.decode(chunk, final=False)
                    if part:
                        await ws.send_text(part)
                final = decoder.decode(b'', final=True)
                if final:
                    await ws.send_text(final)

            async def from_browser():
                while True:
                    message = await ws.receive_text()
                    if len(message.encode('utf-8')) > 1024 * 1024:
                        raise ProtocolError('Client frame exceeded size limit')
                    writer.write(message.encode('utf-8'))
                    await asyncio.wait_for(writer.drain(), timeout=8)

            tasks = [asyncio.create_task(from_guacd()), asyncio.create_task(from_browser())]
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if not task.cancelled():
                        task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except (OSError, asyncio.TimeoutError, ProtocolError, UnicodeDecodeError, ValueError) as exc:
            failed = True
            audit('desktop.error', session_id, 'failed')
            try:
                await ws.send_text(frame('error', 'Remote desktop connection failed', '519').decode('utf-8'))
            except Exception:
                pass
        finally:
            with GUARD:
                ACTIVE.pop(session_id, None)
                ACTIVE_TASKS.pop(session_id, None)
            ticket = None
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=4)
                except (OSError, asyncio.TimeoutError):
                    pass
            desktop_history.finished(dbconn, session_id, failed)
            audit('desktop.closed', session_id)
            try:
                await ws.close()
            except Exception:
                pass

    @app.websocket('/ws/spice/{token}')
    async def spice_socket(ws: WebSocket, token: str):
        if not session_from_ws(ws):
            await ws.close(code=4401)
            return
        group = acquire_spice_channel(token, ws.cookies.get('switchyard_session',''))
        if group is None:
            await ws.close(code=4404)
            return
        reader = None; writer = None
        failed = False
        if group.channels == 1:
            desktop_history.started(dbconn, group.session_id, group.desktop_id, ACTIVE[group.session_id]['label'], 'spice')
        await ws.accept()
        with GUARD:
            ACTIVE_TASKS.setdefault(group.session_id, set()).add(asyncio.current_task())
        try:
            reader, writer = await connect_spice(group.settings)
            desktop_history.opened(dbconn, group.session_id)
            audit('desktop.spice.channel_opened', group.session_id)
            await relay_spice(ws, reader, writer)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        except (OSError, ConnectionError, asyncio.TimeoutError, asyncio.LimitOverrunError, ssl.SSLError, ValueError):
            failed = True
            audit('desktop.spice.error', group.session_id, 'failed')
            try:
                await ws.close(code=1011, reason='SPICE transport could not be established')
            except Exception:
                pass
        finally:
            with GUARD:
                tasks = ACTIVE_TASKS.get(group.session_id)
                if tasks is not None:
                    tasks.discard(asyncio.current_task())
                    if not tasks:
                        ACTIVE_TASKS.pop(group.session_id, None)
            release_spice_channel(token)
            if group.channels == 0:
                desktop_history.finished(dbconn, group.session_id, failed)
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=4)
                except (OSError, asyncio.TimeoutError):
                    pass
            audit('desktop.spice.channel_closed', group.session_id)
            try:
                await ws.close()
            except Exception:
                pass
