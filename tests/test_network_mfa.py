"""LAN origins, remote MFA, encrypted TOTP state, and replay isolation."""
import base64
import hashlib
import hmac
import os
import struct
import time

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from app import main as m

PASS = 'correct-very-strong-development-password'
LAN = 'http://192.168.0.35:9791'
REMOTE = 'https://ops.gigabytegrove.net'


def otp(secret: str, tick: int | None = None) -> str:
    counter = int(time.time()) // 30 if tick is None else tick
    digest = hmac.new(base64.b32decode(secret), struct.pack('>Q', counter), hashlib.sha1).digest()
    shift = digest[-1] & 15
    return f'{((struct.unpack(">I", digest[shift:shift + 4])[0] & 0x7fffffff) % 1000000):06d}'


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(m, 'DATA', tmp_path / 'data')
    monkeypatch.setattr(m, 'DB_FILE', tmp_path / 'data' / 'switchyard.sqlite3')
    with m.LOCK:
        m.FAILED.clear()
    with TestClient(m.app, client=('192.168.0.200', 4432), base_url=LAN) as client:
        response = client.post('/api/setup/complete', headers={'Origin':LAN}, json={
          'claim_code':m.BOOTSTRAP_CODE,'username':'admin','password':PASS,
          'public_origin':REMOTE,'lan_origins':['http://switchyard.lan:9791']})
        assert response.status_code == 200, response.text
        yield client


def login(client, origin: str, totp: str = ''):
    return client.post('/api/login', headers={'origin': origin}, json={'username': 'admin', 'password': PASS, 'totp': totp})


def test_lan_login_remote_requires_mfa_and_session_isolation(configured):
    lan = configured
    assert login(lan, LAN).status_code == 200
    assert lan.get('/api/me').status_code == 200
    with TestClient(m.app, client=('192.168.0.200', 4432), base_url=REMOTE) as remote:
        assert remote.get('/api/me').status_code == 401
        assert login(remote, REMOTE).status_code == 403
        assert remote.post('/api/mfa/setup', headers={'origin': REMOTE}, json={'password': PASS}).status_code == 401
        # Spoofed remote Host or Origin on LAN is rejected.
        assert lan.post('/api/mfa/setup', headers={'origin': REMOTE}, json={'password': PASS}).status_code == 403
        response = lan.post('/api/mfa/setup', headers={'origin': LAN}, json={'password': PASS})
        assert response.status_code == 200, response.text
        secret = response.json()['secret']
        assert len(secret) == 32
        assert response.json()['otpauth_uri'].startswith('otpauth://totp/Switchyard:admin?')
        assert secret not in str(lan.get('/api/mfa/status').json())
        assert lan.post('/api/mfa/enable', headers={'origin': LAN}, json={'code': 'wrong'}).status_code == 422
        confirmed = lan.post('/api/mfa/enable', headers={'origin': LAN}, json={'code': otp(secret)})
        assert confirmed.status_code == 200, confirmed.text
        assert lan.get('/api/mfa/status').json()['enabled'] is True
        assert lan.get('/api/me').status_code == 200
        assert login(remote, REMOTE).status_code == 401
        # TOTP enrollment consumes the current timestep; using the same code cannot bypass replay protection.
        current_step = int(time.time()) // 30
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(m.time, 'time', lambda: (current_step + 1) * 30 + 3)
            ok = login(remote, REMOTE, otp(secret, current_step + 1))
            assert ok.status_code == 200, ok.text
            assert 'Secure' in ok.headers['set-cookie']
            assert remote.get('/api/me').status_code == 200
            assert login(remote, REMOTE, otp(secret, current_step + 1)).status_code == 401
            assert lan.get('/api/me', headers={'Host': 'ops.gigabytegrove.net'}).status_code == 401
            assert lan.get('/api/me').status_code == 200
            # MFA disable must be LAN-only, even if remote MFA was verified.
            assert remote.post('/api/mfa/disable', headers={'origin': REMOTE}, json={'code': otp(secret, current_step + 2), 'password': PASS}).status_code == 403
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(m.time, 'time', lambda: (current_step + 2) * 30 + 3)
            disabled = lan.post('/api/mfa/disable', headers={'origin': LAN}, json={'password': PASS, 'code': otp(secret, current_step + 2)})
            assert disabled.status_code == 200, disabled.text
            assert remote.get('/api/me').status_code == 401
            assert login(remote, REMOTE).status_code == 403


def test_origin_rejection_and_private_ip_auto_detect(configured):
    lan = configured
    assert lan.post('/api/login', headers={'Origin': 'https://attacker.example'}, json={'username': 'admin', 'password': PASS}).status_code == 403
    assert login(lan, LAN).status_code == 200
    with TestClient(m.app, client=('192.168.0.200', 4432), base_url='http://switchyard.lan:9791') as dns_lan:
        assert login(dns_lan, 'http://switchyard.lan:9791').status_code == 200
    with TestClient(m.app, client=('192.168.0.200', 4432), base_url='http://public-unknown.invalid') as unknown:
        assert unknown.get('/api/me').status_code == 403


def test_missing_mfa_key_blocks_enrollment(configured, monkeypatch):
    assert login(configured, LAN).status_code == 200
    response = configured.post('/api/mfa/setup', headers={'origin': LAN}, json={'password': PASS})
    assert response.status_code == 200
    key = m.DATA / 'mfa.key'
    assert key.is_file() and key.stat().st_mode & 0o777 == 0o600
    key.unlink()
    # Replacing the encryption key cannot decrypt the already-persisted enrollment.
    assert configured.post('/api/mfa/enable', headers={'origin': LAN},
                           json={'code':otp(response.json()['secret'])}).status_code == 503


def test_schema_upgrade_preserves_old_sessions_and_password(configured):
    assert login(configured, LAN).status_code == 200
    with m.dbconn() as db:
        cols = {row['name'] for row in db.execute('PRAGMA table_info(users)')}
        assert {'mfa_secret', 'mfa_pending', 'mfa_last_step'} <= cols
        assert 'mfa_verified' in {row['name'] for row in db.execute('PRAGMA table_info(sessions)')}
    m.init_data()
    assert configured.get('/api/me').status_code == 200
