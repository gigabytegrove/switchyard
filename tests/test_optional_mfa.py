"""Opt-in MFA and browser UI policy regressions."""
import base64
from fastapi.testclient import TestClient
from app import main as m
from test_network_mfa import configured, login, otp, LAN, REMOTE, PASS


def test_remote_password_login_is_allowed_without_mfa(configured):
    with TestClient(m.app, client=('192.168.0.201', 4432), base_url=REMOTE) as remote:
        response = login(remote, REMOTE)
        assert response.status_code == 200, response.text
        assert remote.get('/api/me').status_code == 200
        assert 'Secure' in response.headers['set-cookie']
        assert configured.get('/api/me').status_code == 401


def test_scannable_qr_is_issued_only_after_explicit_enrollment(configured):
    assert login(configured, LAN).status_code == 200
    state = configured.get('/api/mfa/status').json()
    assert state['enabled'] is False
    data = configured.post('/api/mfa/setup', headers={'Origin': LAN}, json={'password':PASS}).json()
    svg = base64.b64decode(data['qr_data_uri'].split(',', 1)[1])
    assert b'<svg' in svg and b'<path' in svg
    assert data['secret'].encode() not in svg
    assert configured.get('/api/mfa/status').json()['enabled'] is False
    assert configured.post('/api/mfa/enable', headers={'Origin': LAN}, json={'code':otp(data['secret'])}).status_code == 200
    assert configured.get('/api/mfa/status').json()['enabled'] is True
    with TestClient(m.app, client=('192.168.0.201', 4432), base_url=REMOTE) as remote:
        assert login(remote, REMOTE).status_code == 401


def test_mfa_ui_exposes_scan_and_does_not_require_otp_by_default():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'static' / 'index.html').read_text()
    assert 'id="mfaQr"' in source
    assert 'id="loginTotpGroup" class="hidden"' in source
    assert 'Remote sessions will remain blocked' not in source
