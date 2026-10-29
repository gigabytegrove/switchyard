import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app import main as m


@pytest.fixture
def client(monkeypatch, tmp_path):
    password = 'serious-development-password-12345'
    monkeypatch.setattr(m, 'DATA', tmp_path / 'data')
    monkeypatch.setattr(m, 'DB_FILE', tmp_path / 'data' / 'switchyard.sqlite3')
    monkeypatch.setattr(m, 'BW_SESSION', None)
    with m.LOCK:
        m.FAILED.clear()
    with TestClient(m.app, base_url='http://testserver') as client:
        assert client.get('/api/setup/status', headers={'Host':'127.0.0.1:9791'}).json()['setup_required']
        response = client.post('/api/setup/complete', headers={'Host':'127.0.0.1:9791','Origin':'http://127.0.0.1:9791'}, json={
          'claim_code':m.BOOTSTRAP_CODE,'username':'admin','password':password,
          'lan_origins':['http://testserver']})
        assert response.status_code == 200, response.text
        yield client


def authenticate(client):
    response = client.post('/api/login', json={'username': 'admin', 'password': 'serious-development-password-12345'},
                           headers={'Origin': 'http://testserver'})
    assert response.status_code == 200, response.text
    assert 'HttpOnly' in response.headers['set-cookie']
    assert 'SameSite=strict' in response.headers['set-cookie']


def asset(label='Edge router'):
    return {'label': label, 'host': '192.168.0.12', 'port': 22, 'username': 'ops',
            'environment': 'Production', 'auth_type': 'interactive',
            'credential_ref': '', 'key_file': '', 'use_tmux': True, 'note': 'Test host'}


def test_bootstrap_health_and_auth(client):
    assert client.get('/healthz').json()['status'] == 'ok'
    assert client.get('/api/me').status_code == 401
    assert client.post('/api/login', json={'username': 'admin', 'password': 'invalid'},
                       headers={'Origin': 'http://testserver'}).status_code == 401
    authenticate(client)
    assert client.get('/api/me').json()['username'] == 'admin'
    assert client.get('/').status_code == 200
    assert client.get('/static/style.css').status_code == 200
    assert client.get('/static/notfound.js').status_code == 404
    assert client.post('/api/logout', headers={'Origin': 'http://testserver'}).status_code == 200
    assert client.get('/api/me').status_code == 401


def test_csrf_rejected(client):
    assert client.post('/api/login', json={'username': 'admin', 'password': 'serious-development-password-12345'}).status_code == 403
    authenticate(client)
    assert client.post('/api/assets', json=asset(), headers={'Origin': 'https://attacker.example'}).status_code == 403


def test_assets_persistence_and_audit(client):
    authenticate(client)
    headers = {'Origin': 'http://testserver'}
    response = client.post('/api/assets', json=asset(), headers=headers)
    assert response.status_code == 201, response.text
    aid = response.json()['id']
    assert len(client.get('/api/assets').json()) == 1
    modified = asset('Renamed router')
    modified['auth_type'] = 'vault'
    modified['credential_ref'] = 'b94cb0df-585e-4cc3-b74f-63b13ece9992'
    assert client.put('/api/assets/' + aid, json=modified, headers=headers).status_code == 200
    assert client.get('/api/assets').json()[0]['auth_type'] == 'vault'
    assert client.get('/api/overview').json()['assets'] == 1
    assert len(client.get('/api/audit').json()) >= 3
    # Re-opening the database preserves the asset record.
    assert m.fetch_asset(aid)['label'] == 'Renamed router'
    assert client.delete('/api/assets/' + aid, headers=headers).status_code == 200
    assert client.delete('/api/assets/' + aid, headers=headers).status_code == 404


def test_asset_validation(client):
    authenticate(client)
    headers = {'Origin': 'http://testserver'}
    bad = asset()
    bad['host'] = '-oProxyCommand=evil'
    assert client.post('/api/assets', json=bad, headers=headers).status_code == 422
    bad = asset()
    bad['key_file'] = '../../private_key'
    assert client.post('/api/assets', json=bad, headers=headers).status_code == 422
    bad = asset()
    bad['port'] = 99999
    assert client.post('/api/assets', json=bad, headers=headers).status_code == 422


def test_password_change_revokes_other_sessions(client):
    authenticate(client)
    other = TestClient(m.app, base_url='http://testserver')
    authenticate(other)
    changed = client.post('/api/password', headers={'Origin': 'http://testserver'},
                          json={'current_password': 'serious-development-password-12345', 'new_password': 'replacement-password-very-strong'})
    assert changed.status_code == 200
    assert other.get('/api/me').status_code == 401
    assert client.get('/api/me').status_code == 200
    client.post('/api/logout', headers={'Origin': 'http://testserver'})
    assert client.post('/api/login', headers={'Origin': 'http://testserver'},
                       json={'username': 'admin', 'password': 'replacement-password-very-strong'}).status_code == 200


def test_vault_config_and_redacted_items(client, monkeypatch):
    authenticate(client)
    calls = []
    def fake_bw(*args, **kwargs):
        calls.append(args)
        if args[:2] == ('list', 'items'):
            return '[{"id":"one","name":"Server login","type":1,"login":{"username":"root","password":"secret123"}},{"id":"two","name":"card","type":3}]'
        if args[:2] == ('get', 'item'):
            return '{"login":{"password":"secret123"}}'
        if args == ('unlock', '--passwordenv', 'SWITCHYARD_VW_PASSWORD', '--raw'):
            return 'testinglongsecret01234567890123'
        return '{}'
    monkeypatch.setattr(m, 'bw_run', fake_bw)
    headers = {'Origin': 'http://testserver'}
    assert client.post('/api/vault/configure', headers=headers, json={'server_url': 'http://example.com'}).status_code == 422
    assert client.post('/api/vault/configure', headers=headers, json={'server_url': 'https://vault.example.com'}).status_code == 200
    assert client.post('/api/vault/login', headers=headers, json={'client_id': 'user.a', 'client_secret': 'test'}).status_code == 200
    assert client.post('/api/vault/unlock', headers=headers, json={'master_password': 'test'}).status_code == 200
    payload = client.get('/api/vault/items').json()
    assert payload == [{'id': 'one', 'name': 'Server login', 'username': 'root'}]
    assert 'secret123' not in str(payload)
    assert m.vault_password('one') == 'secret123'
    assert client.post('/api/vault/lock', headers=headers).status_code == 200
    assert m.BW_SESSION is None


def test_login_rate_limit(client):
    for _ in range(8):
        assert client.post('/api/login', headers={'Origin': 'http://testserver'},
                           json={'username': 'admin', 'password': 'wrong'}).status_code == 401
    assert client.post('/api/login', headers={'Origin': 'http://testserver'},
                       json={'username': 'admin', 'password': 'serious-development-password-12345'}).status_code == 429


def test_docker_management_via_ssh_only(client, monkeypatch):
    authenticate(client)
    headers = {'Origin': 'http://testserver'}
    aid = client.post('/api/assets', json=asset(), headers=headers).json()['id']
    calls = []
    def fake_remote(a, command, password):
        calls.append((a['id'], command, password))
        if command.startswith('docker ps'):
            return ('{"ID":"' + 'a'*64 + '","Names":"web","Image":"nginx:stable",'
                    '"Status":"Up 3 hours","State":"running","Ports":"80/tcp"}\n')
        return 'abc\n'
    monkeypatch.setattr(m, 'remote_command', fake_remote)
    result = client.get(f'/api/assets/{aid}/docker/containers', headers={'X-SSH-Password': 'ephemeral-password'})
    assert result.status_code == 200
    assert result.json()[0]['name'] == 'web'
    assert result.json()[0]['state'] == 'running'
    assert 'ephemeral-password' not in str(result.json())
    assert client.post(f'/api/assets/{aid}/docker/action', headers=headers,
                       json={'action': 'remove', 'container_id': 'a'*64}).status_code == 422
    assert client.post(f'/api/assets/{aid}/docker/action', headers=headers,
                       json={'action': 'stop', 'container_id': ';rm -rf /tmp'}).status_code == 422
    action = client.post(f'/api/assets/{aid}/docker/action', headers=headers,
                         json={'action': 'restart', 'container_id': 'a'*64})
    assert action.status_code == 200, action.text
    assert calls[-1][1] == 'docker restart ' + 'a'*64
    assert client.get('/api/audit').json()[0]['action'] == 'docker.restart'


def test_remote_sftp_create_rename_delete(client, monkeypatch):
    authenticate(client)
    headers = {'Origin': 'http://testserver'}
    aid = client.post('/api/assets', json=asset(), headers=headers).json()['id']
    operations = []

    class FakeSFTP:
        def __enter__(self): return self
        def __exit__(self, *_): return False
        def mkdir(self, path): operations.append(('mkdir', path))
        def stat(self, path):
            if path == '/existing': return object()
            raise FileNotFoundError(path)
        def rename(self, a, b): operations.append(('rename', a, b))
        def remove(self, path): operations.append(('remove', path))
        def rmdir(self, path): operations.append(('rmdir', path))

    class FakeSSH:
        def open_sftp(self): return FakeSFTP()
        def close(self): pass

    monkeypatch.setattr(m, 'ssh_client', lambda a, password=None: FakeSSH())
    assert client.post(f'/api/assets/{aid}/files/mkdir', headers=headers,
                       json={'path': '/new'}).status_code == 200
    assert client.post(f'/api/assets/{aid}/files/rename', headers=headers,
                       json={'source': '/old', 'destination': '/existing'}).status_code == 409
    assert client.post(f'/api/assets/{aid}/files/rename', headers=headers,
                       json={'source': '/old', 'destination': '/new'}).status_code == 200
    assert client.request('DELETE', f'/api/assets/{aid}/files?directory=true', headers=headers,
                          json={'path': '/new'}).status_code == 200
    assert client.request('DELETE', f'/api/assets/{aid}/files', headers=headers,
                          json={'path': '/foo'}).status_code == 200
    assert operations == [('mkdir', '/new'), ('rename', '/old', '/new'),
                          ('rmdir', '/new'), ('remove', '/foo')]


def test_unauthenticated_websocket_is_rejected(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as err:
        with client.websocket_connect('/ws/terminal/fake', headers={'Origin': 'http://testserver'}) as ws:
            ws.receive_text()
    assert err.value.code == 4401


def test_no_public_schema_and_security_headers(client):
    assert client.get('/openapi.json').status_code == 404
    result = client.get('/')
    assert result.headers['X-Frame-Options'] == 'DENY'
    assert "script-src 'self'" in result.headers['Content-Security-Policy']
    assert result.headers['X-Content-Type-Options'] == 'nosniff'


def test_ssh_key_lifecycle_and_usage_protection(client):
    authenticate(client)
    origin = {'Origin': 'http://testserver'}
    assert client.get('/api/keys').json() == []
    made = client.post('/api/keys/generate', json={'name': 'prod_ed25519'}, headers=origin)
    assert made.status_code == 201, made.text
    assert made.json()['public_key'].startswith('ssh-ed25519 ')
    path = m.DATA / 'keys' / 'prod_ed25519'
    assert path.exists() and path.stat().st_mode & 0o077 == 0
    assert b'PRIVATE KEY' in path.read_bytes()
    assert len(client.get('/api/keys').json()) == 1
    assert client.post('/api/keys/generate', json={'name': 'prod_ed25519'}, headers=origin).status_code == 409
    bad_import = client.post('/api/keys/import?name=bad', headers=origin,
                             files={'file': ('key', b'not a private key')})
    assert bad_import.status_code == 422
    assert not (m.DATA / 'keys' / 'bad').exists()
    imported = client.post('/api/keys/import?name=copy_ed25519', headers=origin,
                           files={'file': ('key', path.read_bytes())})
    assert imported.status_code == 201, imported.text
    assert imported.json()['public_key'] == made.json()['public_key']
    assigned = asset()
    assigned['auth_type'] = 'key'
    assigned['key_file'] = 'prod_ed25519'
    assert client.post('/api/assets', json=assigned, headers=origin).status_code == 201
    assert client.get('/api/keys').json()[1]['used_by'] == 1
    assert client.delete('/api/keys/prod_ed25519', headers=origin).status_code == 409
    assert client.delete('/api/keys/copy_ed25519', headers=origin).status_code == 200
    assert client.delete('/api/keys/copy_ed25519', headers=origin).status_code == 404
    assert client.post('/api/keys/generate', headers=origin, json={'name':'../outside'}).status_code == 422


def test_backup_wal_snapshot_without_sessions_or_secrets(client):
    import io
    import zipfile
    import json
    import sqlite3
    import hashlib
    authenticate(client)
    origin = {'Origin': 'http://testserver'}
    assert client.post('/api/assets', headers=origin, json=asset()).status_code == 201
    (m.DATA / 'known_hosts').write_text('example invalid-public-host-key\n')
    (m.DATA / 'bw' / 'state').write_text('VERY-SECRET-VAULT-MATERIAL')
    (m.DATA / 'keys' / 'mykey').write_text('VERY-SECRET-SSH-KEY')
    result = client.get('/api/backup')
    assert result.status_code == 200, result.text
    assert result.headers['content-type'].startswith('application/zip')
    assert b'VERY-SECRET-' not in result.content
    with zipfile.ZipFile(io.BytesIO(result.content)) as z:
        assert sorted(z.namelist()) == ['known_hosts', 'manifest.json', 'mfa.key', 'switchyard.sqlite3']
        manifest = json.loads(z.read('manifest.json'))
        assert manifest['version'] == '0.5.0-dev.1'
        assert hashlib.sha256(z.read('mfa.key')).hexdigest() == manifest['files']['mfa.key']
        dbdata = z.read('switchyard.sqlite3')
        assert hashlib.sha256(dbdata).hexdigest() == manifest['files']['switchyard.sqlite3']
        assert z.read('known_hosts') == b'example invalid-public-host-key\n'
        snapshot = m.DATA / 'snap.sqlite3'
        snapshot.write_bytes(dbdata)
        with sqlite3.connect(snapshot) as db:
            assert db.execute('SELECT COUNT(*) FROM assets').fetchone()[0] == 1
            assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
            assert db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] > 0
    assert client.get('/api/me').status_code == 200  # export doesn't invalidate live sessions
    assert client.get('/api/audit/export').headers['content-type'].startswith('text/csv')


def test_host_key_revoke_and_no_unreviewed_rotation(client):
    import base64
    import hashlib
    paramiko = pytest.importorskip('paramiko', reason='Optional SSH dependency unavailable in local test environment')
    authenticate(client)
    origin = {'Origin': 'http://testserver'}
    k1 = paramiko.RSAKey.generate(bits=2048)
    k2 = paramiko.RSAKey.generate(bits=2048)
    host = {'host': 'workstation.local', 'port': 22, 'key_type': k1.get_name(),
            'public_key': k1.get_base64()}
    assert client.post('/api/hosts/trust', headers=origin, json=host).status_code == 200
    rotated = dict(host, public_key=k2.get_base64())
    assert client.post('/api/hosts/trust', headers=origin, json=rotated).status_code == 409
    current = client.get('/api/hosts').json()
    assert len(current) == 1
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(k1.asbytes()).digest()).decode().rstrip('=')
    assert current[0]['fingerprint'] == fingerprint
    assert client.post('/api/hosts/revoke', headers=origin,
                       json=dict(current[0], fingerprint='SHA256:garbage')).status_code == 409
    deleted = client.post('/api/hosts/revoke', headers=origin, json=current[0])
    assert deleted.status_code == 200, deleted.text
    assert client.get('/api/hosts').json() == []
    assert client.post('/api/hosts/trust', headers=origin, json=rotated).status_code == 200


def test_remote_docker_inspection_and_inventory_is_redacted(client, monkeypatch):
    import json
    authenticate(client)
    origin = {'Origin': 'http://testserver'}
    aid = client.post('/api/assets', json=asset(), headers=origin).json()['id']
    cid = 'a' * 64
    command_log = []
    def remote(_asset, command, password):
        command_log.append(command)
        if command.startswith('docker info'):
            return json.dumps({'Name': 'docker-prod', 'Containers': 3, 'ContainersRunning': 2,
                               'ServerVersion': '28.0', 'RegistryConfig': {'secret': 'PRIVATE'}})
        if command.startswith('docker container inspect'):
            return json.dumps([{'Id':cid, 'Name':'/api', 'Config': {'Image':'web:stable', 'Env':['PASSWORD=PRIVATE']},
                                'State':{'Status':'running', 'Health':{'Status':'healthy'}},
                                'NetworkSettings':{'Networks':{'bridge':{}}, 'Ports':{}},
                                'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}}}])
        if command.startswith('docker stats'):
            return json.dumps({'CPUPerc':'1.03%', 'MemUsage':'100MiB / 2GiB', 'ID':'PRIVATE'})
        if command.startswith('docker logs'):
            return 'line 1\nline 2\n'
        if command.startswith('docker images'):
            return json.dumps({'Repository':'redis','Tag':'latest','ID':'sha256:a','Size':'120MB'}) + '\n'
        if command.startswith('docker network'):
            return json.dumps({'Name':'bridge','ID':'net1','Driver':'bridge','Scope':'local'}) + '\n'
        if command.startswith('docker volume'):
            return json.dumps({'Name':'db','Driver':'local','Mountpoint':'/SECRET'}) + '\n'
        raise AssertionError(command)
    monkeypatch.setattr(m, 'remote_command', remote)
    summary = client.get(f'/api/assets/{aid}/docker/summary').json()
    assert summary['containers'] == 3 and summary['running'] == 2
    assert 'PRIVATE' not in str(summary)
    inspect = client.get(f'/api/assets/{aid}/docker/containers/{cid}/inspect').json()
    assert inspect['health'] == 'healthy' and inspect['networks'] == ['bridge']
    assert 'PASSWORD' not in str(inspect) and 'PRIVATE' not in str(inspect)
    stats = client.get(f'/api/assets/{aid}/docker/containers/{cid}/stats').json()
    assert stats['CPUPerc'] == '1.03%' and 'PRIVATE' not in str(stats)
    logs = client.get(f'/api/assets/{aid}/docker/containers/{cid}/logs?tail=100000').json()
    assert logs['tail'] == 500 and logs['logs'] == 'line 1\nline 2\n'
    for endpoint in ('images','networks','volumes'):
        result = client.get(f'/api/assets/{aid}/docker/{endpoint}')
        assert result.status_code == 200 and len(result.json()) == 1
        assert 'PRIVATE' not in str(result.json()) and 'SECRET' not in str(result.json())
    assert client.get(f'/api/assets/{aid}/docker/containers/;rm -rf/tmp/logs').status_code in (404, 422)
    assert any('docker stats' in line and cid in line for line in command_log)


def test_audit_filter_pagination_and_csv_formula_safety(client):
    authenticate(client)
    for idx in range(102):
        m.audit('docker.restart' if idx % 2 else 'asset.updated', '=HYPERLINK("evil")')
    results = client.get('/api/audit?limit=20&action=docker.restart').json()
    assert len(results) == 20
    earlier = client.get('/api/audit', params={'before':results[-1]['id'], 'limit':100, 'action':'docker.restart'}).json()
    assert len(earlier) == 31
    csv_result = client.get('/api/audit/export')
    assert csv_result.status_code == 200
    assert "'=HYPERLINK" in csv_result.text
    assert client.get('/api/audit?limit=900').status_code == 200


# 0.3.0 regression coverage: runbooks, health, atomic editing, Compose stacks.
def test_runbook_crud_execution_confirmation_and_no_output_persistence(client, monkeypatch):
    import sqlite3
    authenticate(client)
    origin = {'Origin': 'http://testserver'}
    aid = client.post('/api/assets', json=asset(), headers=origin).json()['id']
    command = 'echo SUPPLIED-SENSITIVE-COMMAND-TOKEN'
    body = {'name': 'Check daemon', 'description': 'No maintenance changes', 'command': command,
            'requires_confirmation': True}
    r = client.post('/api/runbooks', headers=origin, json=body)
    assert r.status_code == 201, r.text
    rid = r.json()['id']
    assert client.post('/api/runbooks', json={'name':'N','command':'  '}, headers=origin).status_code == 422
    assert client.post('/api/runbooks', json={'name':'N','command':'\u0000'}, headers=origin).status_code == 422
    assert client.post('/api/runbooks', json={**body, 'command':'x'*8193}, headers=origin).status_code == 422
    assert len(client.get('/api/runbooks').json()) == 1
    assert client.post(f'/api/runbooks/{rid}/execute', headers=origin,
                       json={'asset_id':aid, 'confirm':False}).status_code == 409
    calls = []
    def fake_run(a, command, password=None, limit_seconds=30):
        calls.append((a['id'], command, password))
        return {'exit_code':0,'stdout':'PRIVATE-TRANSIENT-OUTPUT','stderr':''}
    monkeypatch.setattr(m, 'execute_runbook_ssh', fake_run)
    ran = client.post(f'/api/runbooks/{rid}/execute', headers={**origin, 'X-SSH-Password':'temporary'},
                      json={'asset_id':aid, 'confirm':True})
    assert ran.status_code == 200, ran.text
    assert ran.json()['stdout'] == 'PRIVATE-TRANSIENT-OUTPUT'
    assert calls == [(aid,command,'temporary')]
    history = client.get('/api/runbooks/history').json()
    assert len(history) == 1 and history[0]['outcome'] == 'ok'
    assert 'PRIVATE-TRANSIENT-OUTPUT' not in str(history)
    assert command not in str(history)
    assert 'temporary' not in str(history)
    body['name'] = 'Updated name'
    assert client.put(f'/api/runbooks/{rid}', headers=origin,json=body).status_code == 200
    assert client.get('/api/runbooks').json()[0]['name'] == 'Updated name'
    assert client.delete(f'/api/runbooks/{rid}', headers=origin).status_code == 200
    assert client.delete(f'/api/runbooks/{rid}', headers=origin).status_code == 404
    assert len(client.get('/api/runbooks/history').json()) == 1
    with sqlite3.connect(m.DB_FILE) as db:
        blob = str(db.execute('SELECT * FROM run_history').fetchall())
        assert 'PRIVATE-TRANSIENT-OUTPUT' not in blob


def test_runbook_failed_execution_is_audited_and_history_saved(client, monkeypatch):
    from fastapi import HTTPException
    authenticate(client)
    origin = {'Origin':'http://testserver'}
    aid = client.post('/api/assets',json=asset(),headers=origin).json()['id']
    rid = client.post('/api/runbooks',json={'name':'Failing','command':'false'},headers=origin).json()['id']
    def failed(*_args, **_kwargs):
        raise HTTPException(504,'Remote command exceeded its execution deadline')
    monkeypatch.setattr(m, 'execute_runbook_ssh',failed)
    r = client.post(f'/api/runbooks/{rid}/execute',headers=origin,json={'asset_id':aid,'confirm':True})
    assert r.status_code == 504
    assert client.get('/api/runbooks/history').json()[0]['outcome'] == 'failed'
    assert client.get('/api/audit').json()[0]['outcome'] == 'failed'


def test_remote_exec_channel_drains_stderr_and_closes(client, monkeypatch):
    from fastapi import HTTPException
    class FakeChannel:
        closed = False
        def __init__(self, output=b'hello', stderr=b'notice', exit_code=7):
            self.output=output; self.errors=stderr; self.code=exit_code
        def settimeout(self, v): pass
        def exec_command(self, cmd): self.command=cmd
        def recv_ready(self): return bool(self.output)
        def recv_stderr_ready(self): return bool(self.errors)
        def recv(self, _): r=self.output;self.output=b'';return r
        def recv_stderr(self, _): r=self.errors;self.errors=b'';return r
        def exit_status_ready(self): return not self.output and not self.errors
        def recv_exit_status(self): return self.code
        def close(self): self.closed=True
    class FakeTransport:
        def __init__(self, channel): self.channel=channel
        def is_active(self): return True
        def open_session(self,timeout=10): return self.channel
    class FakeClient:
        closed=False
        def __init__(self,channel): self.transport=FakeTransport(channel)
        def get_transport(self): return self.transport
        def close(self): self.closed=True
    channel=FakeChannel(); ssh=FakeClient(channel)
    monkeypatch.setattr(m,'ssh_client',lambda a,p=None:ssh)
    result=m.execute_runbook_ssh({'id':'any'},'echo test','secret')
    assert result == {'exit_code':7,'stdout':'hello','stderr':'notice'}
    assert ssh.closed and channel.closed
    channel=FakeChannel(output=b'x'*(262144+2),stderr=b''); ssh=FakeClient(channel)
    monkeypatch.setattr(m,'ssh_client',lambda a,p=None:ssh)
    with pytest.raises(HTTPException) as e:
        m.execute_runbook_ssh({'id':'any'},'echo huge')
    assert e.value.status_code == 413 and ssh.closed


def test_linux_health_parsing_history_and_failure(client, monkeypatch):
    from fastapi import HTTPException
    authenticate(client)
    origin = {'Origin':'http://testserver'}
    aid = client.post('/api/assets',json=asset(),headers=origin).json()['id']
    sample = ('SYHOST\nweb1\nSYKERNEL\nLinux 6.1.0\nSYUPTIME\n86413.24 12.1\n'
              'SYLOAD\n0.04 0.12 0.20 1/2 33\nSYMEMORY\nMemTotal: 8000000 kB\n'
              'MemAvailable: 3000000 kB\nSYDISK\nFilesystem 1B-blocks Used Available Use% Mounted on\n'
              '/dev/sda1 1000000 250000 750000 25% /\n')
    monkeypatch.setattr(m,'remote_command', lambda *_args: sample)
    r=client.get(f'/api/assets/{aid}/health')
    assert r.status_code == 200, r.text
    assert r.json()['status']=='online' and r.json()['uptime_seconds']==86413
    assert r.json()['memory_total']==8000000*1024 and r.json()['disk_used']==250000
    assert len(client.get(f'/api/assets/{aid}/health/history').json())==1
    monkeypatch.setattr(m,'remote_command', lambda *_args: 'garbage')
    r=client.get(f'/api/assets/{aid}/health')
    assert r.status_code==502
    assert client.get(f'/api/assets/{aid}/health/history').json()[0]['status']=='offline'
    assert client.get('/api/audit').json()[0]['action']=='host.health'
    with pytest.raises(HTTPException): m.parse_linux_health('SYHOST\nx\n')


def test_sftp_editor_conflict_saves_atomically_and_cleans_temp(client, monkeypatch):
    import io, hashlib, stat
    authenticate(client)
    origin={'Origin':'http://testserver'}
    aid=client.post('/api/assets',json=asset(),headers=origin).json()['id']
    contents={'/etc/motd':b'Hello\n'}
    modes={'/etc/motd':0o644}
    renamed=[]
    class Info:
        def __init__(self,path):
            self.st_mode=stat.S_IFREG|modes[path]
            self.st_size=len(contents[path])
    class FakeFile:
        def __init__(self,path,mode): self.path=path;self.mode=mode
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def read(self,n): return contents[self.path][:n]
        def write(self,data): contents[self.path]=data
        def flush(self): pass
    class Sftp:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def stat(self,path): return Info(path)
        def file(self,path,mode):
            if mode=='x':
                assert path not in contents
                contents[path]=b''
                modes[path]=0o600
            return FakeFile(path,mode)
        def chmod(self,path,mode):modes[path]=mode
        def posix_rename(self,src,dst):
            renamed.append((src,dst));contents[dst]=contents.pop(src);modes[dst]=modes.pop(src)
        def remove(self,path):
            if path not in contents: raise FileNotFoundError(path)
            contents.pop(path)
    class Ssh:
        def open_sftp(self):return Sftp()
        def close(self): pass
    monkeypatch.setattr(m,'ssh_client',lambda *_args:Ssh())
    opened=client.get(f'/api/assets/{aid}/files/edit?path=/etc/motd')
    assert opened.status_code==200 and opened.json()['content']=='Hello\n'
    original=opened.json()['sha256']
    payload={'path':'/etc/motd','original_sha256':original,'content':'New message\n'}
    assert client.put(f'/api/assets/{aid}/files/edit',headers=origin,json={**payload,'original_sha256':'0'*64}).status_code==409
    assert contents['/etc/motd']==b'Hello\n'
    saved=client.put(f'/api/assets/{aid}/files/edit',headers=origin,json=payload)
    assert saved.status_code==200,saved.text
    assert contents['/etc/motd']==b'New message\n' and modes['/etc/motd']==0o644
    assert not any('.switchyard-edit-' in key for key in contents)
    assert len(renamed)==1
    assert client.put(f'/api/assets/{aid}/files/edit',headers=origin,json=payload).status_code==409
    contents['/etc/motd']=b'\x00binary'
    assert client.get(f'/api/assets/{aid}/files/edit?path=/etc/motd').status_code==415


def test_compose_stack_discovery_and_safe_control(client, monkeypatch):
    import json
    authenticate(client)
    origin={'Origin':'http://testserver'}
    aid=client.post('/api/assets',json=asset(),headers=origin).json()['id']
    history=[]
    def fake(asset,command,password=None):
        history.append(command)
        if command=='docker compose ls --all --format json':
            return json.dumps([{'Name':'service-a','Status':'running(2)','ConfigFiles':'/opt/the team/compose.yaml,/srv/other.yml'}])
        return 'service-a\n'
    monkeypatch.setattr(m,'remote_command',fake)
    assert client.get(f'/api/assets/{aid}/docker/stacks').json()[0]['name']=='service-a'
    assert client.post(f'/api/assets/{aid}/docker/stacks/action',headers=origin,
                       json={'project':'service-a','action':'up'}).status_code==422
    assert client.post(f'/api/assets/{aid}/docker/stacks/action',headers=origin,
                       json={'project':'../service-a','action':'restart'}).status_code==422
    assert client.post(f'/api/assets/{aid}/docker/stacks/action',headers=origin,
                       json={'project':'missing','action':'restart'}).status_code==404
    r=client.post(f'/api/assets/{aid}/docker/stacks/action',headers=origin,
                  json={'project':'service-a','action':'restart'})
    assert r.status_code==200,r.text
    assert history[-1]=="docker compose -f '/opt/the team/compose.yaml' -f /srv/other.yml -p service-a restart"
    assert client.get('/api/audit').json()[0]['action']=='compose.restart'


def test_new_api_requires_auth_and_origin(client):
    assert client.get('/api/runbooks').status_code==401
    assert client.get('/api/runbooks/history').status_code==401
    assert client.post('/api/runbooks',json={'name':'name','command':'id'}).status_code==403
    authenticate(client)
    assert client.post('/api/runbooks',headers={'Origin':'https://evil.example'},
                       json={'name':'name','command':'id'}).status_code==403


def test_previous_release_schema_upgrade_preserves_existing_asset(client):
    authenticate(client)
    origin={'Origin':'http://testserver'}
    aid=client.post('/api/assets',json=asset('existing-data'),headers=origin).json()['id']
    with m.dbconn() as db:
        db.execute('DROP TABLE run_history')
        db.execute('DROP TABLE runbooks')
        db.execute('DROP TABLE host_snapshots')
    m.init_data()
    assert m.fetch_asset(aid)['label']=='existing-data'
    assert client.get('/api/runbooks').json()==[]
