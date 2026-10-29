"""First-run claim, persistent configuration, and remote/LAN separation."""
import io
import json
import re
import zipfile

import pytest
from fastapi.testclient import TestClient
from app import main as m

LAN = 'http://192.168.0.35:9791'
PUBLIC = 'https://switchyard.example.net'
PW = 'correct-horse-battery-staple-2026'


@pytest.fixture
def fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(m, 'DATA', tmp_path / 'data')
    monkeypatch.setattr(m, 'DB_FILE', tmp_path / 'data' / 'switchyard.sqlite3')
    with m.LOCK:
        m.FAILED.clear()
    with TestClient(m.app, base_url=LAN) as client:
        yield client


def submit(client, **overrides):
    data = {'claim_code':m.BOOTSTRAP_CODE, 'username':'operator', 'password':PW,
            'lan_origins':['http://switchyard.lan:9791'], 'public_origin':PUBLIC}
    data.update(overrides)
    return client.post('/api/setup/complete', headers={'Origin':LAN}, json=data)


def auth(client):
    r = client.post('/api/login', headers={'Origin':LAN}, json={'username':'operator', 'password':PW})
    assert r.status_code == 200, r.text


def test_first_run_needs_claim_and_cannot_be_reclaimed(fresh):
    assert fresh.get('/api/setup/status').json()['setup_required']
    assert fresh.get('/api/me').status_code == 401
    assert fresh.post('/api/login', headers={'Origin':LAN},json={'username':'operator','password':PW}).status_code == 409
    assert submit(fresh, claim_code='AAAA0000-AAAA0000-AAAA0000').status_code == 403
    assert fresh.post('/api/setup/complete', headers={'Origin':'https://wrong.example'},json={'claim_code':m.BOOTSTRAP_CODE,'username':'operator','password':PW}).status_code == 403
    assert submit(fresh).status_code == 200
    assert fresh.get('/api/setup/status').json()['setup_required'] is False
    assert submit(fresh, claim_code='AAAA0000-AAAA0000-AAAA0000').status_code == 409
    auth(fresh)
    assert fresh.get('/api/me').json()['username'] == 'operator'
    assert fresh.get('/api/network').json() == {'public_origin':PUBLIC,'lan_origins':['http://switchyard.lan:9791'],'allow_http_vault':False}
    m.init_data()
    assert fresh.get('/api/me').status_code == 200
    assert m.BOOTSTRAP_CODE is None
    assert m.configured_remote_origin() == PUBLIC


@pytest.mark.parametrize('bad', [
    'http://public.example.net', 'https://public.example.net/path',
    'https://public.example.net?x=1', 'https://operator:password@public.example.net',
    'https://public.example.net:8443', 'https://public.example.net/#fragment',
])
def test_reject_bad_proxy_origins(fresh, bad):
    assert submit(fresh, public_origin=bad).status_code == 422
    assert fresh.get('/api/setup/status').json()['setup_required']


def test_public_hostname_cannot_become_password_only_lan_alias(fresh):
    assert submit(fresh, lan_origins=['https://public.example.net']).status_code == 422
    assert submit(fresh, lan_origins=[PUBLIC]).status_code == 422
    assert submit(fresh, lan_origins=['http://valid.lan:9791']).status_code == 200


def test_update_settings_requires_password_and_lan_authority(fresh):
    assert submit(fresh).status_code == 200
    auth(fresh)
    changed = {'current_password':'wrong','public_origin':'','lan_origins':[],'allow_http_vault':True}
    assert fresh.put('/api/network',headers={'Origin':LAN},json=changed).status_code == 403
    assert fresh.get('/api/network').json()['public_origin'] == PUBLIC
    changed['current_password'] = PW
    assert fresh.put('/api/network',headers={'Origin':PUBLIC},json=changed).status_code == 403
    assert fresh.put('/api/network',headers={'Origin':LAN},json=changed).status_code == 200
    assert fresh.get('/api/network').json()['public_origin'] == ''
    assert fresh.get('/api/network').json()['allow_http_vault'] is True
    m.init_data()
    assert m.configured_remote_origin() == ''


def test_untrusted_dns_host_rejected_without_explicit_alias(fresh):
    assert submit(fresh).status_code == 200
    with TestClient(m.app, base_url='http://rogue.internal-domain.example') as unknown:
        assert unknown.get('/api/setup/status').status_code == 403
    with TestClient(m.app, base_url='http://switchyard.lan:9791') as alias:
        assert alias.get('/api/setup/status').status_code == 200


def test_backup_includes_recoverable_mfa_key(fresh):
    assert submit(fresh).status_code == 200
    auth(fresh)
    started = fresh.post('/api/mfa/setup', headers={'Origin':LAN},json={'password':PW})
    assert started.status_code == 200
    key = (m.DATA / 'mfa.key').read_bytes()
    with zipfile.ZipFile(io.BytesIO(fresh.get('/api/backup').content)) as archive:
        assert archive.read('mfa.key') == key
        metadata = json.loads(archive.read('manifest.json'))
        assert metadata['format'] == 2
        assert 'SENSITIVE' in metadata['warning']
    (m.DATA / 'mfa.key').unlink()
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        m.mfa_cipher()
    assert exc.value.status_code == 503
    assert not (m.DATA / 'mfa.key').exists(), 'must not replace key for enrolled MFA'
