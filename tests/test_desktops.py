"""RDP/VNC regression coverage, including protocol and authorization boundaries."""
import asyncio
import secrets
import time

import pytest
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocketDisconnect
from app import main as m
from app import desktops
from app.guac import DesktopSettings, ProtocolError, connection_options, frame, read_frame, handshake


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(m, 'DATA', tmp_path / 'data')
    monkeypatch.setattr(m, 'DB_FILE', tmp_path / 'data' / 'switchyard.sqlite3')
    with desktops.GUARD:
        desktops.TICKETS.clear(); desktops.ACTIVE.clear(); desktops.SPICE_GROUPS.clear()
    with TestClient(m.app, client=('192.168.0.200', 4432), base_url='http://testserver') as client:
        response = client.post('/api/setup/complete', headers={'Host':'127.0.0.1:9791','Origin':'http://127.0.0.1:9791'}, json={
          'claim_code':m.BOOTSTRAP_CODE,'username':'admin',
          'password':'development-credential-long-enough', 'lan_origins':['http://testserver']})
        assert response.status_code == 200, response.text
        yield client
    with desktops.GUARD:
        desktops.TICKETS.clear(); desktops.ACTIVE.clear(); desktops.SPICE_GROUPS.clear()


def login(client):
    response = client.post('/api/login', headers={'Origin': 'http://testserver'},
      json={'username':'admin','password':'development-credential-long-enough'})
    assert response.status_code == 200


def record(protocol='rdp'):
    return {
      'label': 'Office '+ protocol.upper(), 'protocol': protocol,
      'host': '192.168.0.50', 'username': 'operator',
      'environment': 'IT', 'auth_type':'interactive'
    }


def created(client, protocol='rdp'):
    resp = client.post('/api/desktops', headers={'Origin': 'http://testserver'}, json=record(protocol))
    assert resp.status_code == 201, resp.text
    return resp.json()


def mutation(client, method, url, **kwargs):
    return getattr(client, method)(url, headers={'Origin': 'http://testserver'}, **kwargs)


def test_inventory_authenticated_and_persistent(client):
    assert client.get('/api/desktops').status_code == 401
    assert client.post('/api/desktops', json=record()).status_code == 403
    login(client)
    rdp = created(client)
    assert rdp['port'] == 3389 and rdp['security'] == 'nla'
    assert not rdp['ignore_cert'] and not rdp['read_only']
    vnc = created(client,'vnc')
    assert vnc['port'] == 5900
    assert [i['id'] for i in client.get('/api/desktops').json()] == [rdp['id'],vnc['id']]
    assert 'office' in m.connection().execute('SELECT label FROM desktop_connections LIMIT 1').fetchone()[0].lower()
    assert mutation(client,'delete','/api/desktops/'+rdp['id']).status_code == 200
    assert mutation(client,'delete','/api/desktops/'+rdp['id']).status_code == 404


def test_desktop_update_and_validation(client):
    login(client)
    obj = created(client)
    body = record(); body.update({'label':'Renamed RDP','host':'2001:db8::1','port':3390,'read_only':True,'ignore_cert':True})
    result = mutation(client, 'put', '/api/desktops/'+obj['id'], json=body)
    assert result.status_code == 200, result.text
    assert result.json()['host'] == '2001:db8::1'
    assert result.json()['ignore_cert'] and result.json()['read_only']
    assert mutation(client,'post','/api/desktops',json={**record(),'host':'-oProxyCommand=curl'}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'host':'good..example.com'}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'port':65536}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'protocol':'rsh'}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'auth_type':'vault'}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record('vnc'),'domain':'CORP'}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record('vnc'),'ignore_cert':True}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'width':99999}).status_code == 422
    assert mutation(client,'post','/api/desktops',json={**record(),'security':'none'}).status_code == 422


def test_ticket_one_time_and_ephemeral_password(client):
    login(client)
    obj = created(client)
    r = mutation(client, 'post', '/api/desktops/'+obj['id']+'/ticket', json={'password':'TOP-SECRET-PASSWORD'})
    assert r.status_code == 200, r.text
    ticket = r.json()['ticket']
    assert len(ticket) >= 40
    assert 'TOP-SECRET-PASSWORD' not in str(client.get('/api/desktops').json())
    assert 'TOP-SECRET-PASSWORD' not in str(client.get('/api/audit').json())
    assert desktops.TICKETS[ticket].settings.password == 'TOP-SECRET-PASSWORD'
    assert desktops.consume_ticket(ticket, client.cookies.get('switchyard_session')).settings.password == 'TOP-SECRET-PASSWORD'
    assert desktops.consume_ticket(ticket, client.cookies.get('switchyard_session')) is None
    assert not desktops.TICKETS


def test_ticket_requires_origin_session_and_valid_id(client):
    login(client)
    obj = created(client)
    assert client.post('/api/desktops/'+obj['id']+'/ticket',json={}).status_code == 403
    assert mutation(client,'post','/api/desktops/'+secrets.token_hex(16)+'/ticket',json={}).status_code == 404
    ticket = mutation(client,'post','/api/desktops/'+obj['id']+'/ticket',json={}).json()['ticket']
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws/desktop/'+ticket, headers={'origin':'https://evil.example'}):
            pass
    assert ticket in desktops.TICKETS, 'CSRF websocket attempt must not consume valid ticket'


def test_ticket_expiry_and_capacity(client):
    login(client)
    obj = created(client)
    ticket = mutation(client,'post','/api/desktops/'+obj['id']+'/ticket',json={}).json()['ticket']
    desktops.TICKETS[ticket].expires = time.monotonic() - 1
    assert desktops.consume_ticket(ticket, client.cookies.get('switchyard_session')) is None
    with desktops.GUARD:
        desktops.ACTIVE['synthetic'] = {'desktop_id':obj['id']}
    assert mutation(client,'delete','/api/desktops/'+obj['id']).status_code == 409
    assert mutation(client,'post','/api/desktops/'+obj['id']+'/ticket',json={}).status_code == 200
    with desktops.GUARD:
        for i in range(8): desktops.ACTIVE[str(i)] = {'desktop_id':obj['id']}
    assert mutation(client,'post','/api/desktops/'+obj['id']+'/ticket',json={}).status_code == 429


def test_vault_resolution_never_exposed(client, monkeypatch):
    login(client)
    calls = []
    def vault(ref):
        calls.append(ref)
        return 'VAULT-RESOLVED-SECRET'
    # The install-time dependency is captured; replace actual delegated main function globals.
    monkeypatch.setattr(m, 'vault_password', vault)
    # Separate resolution uses selected vault reference rather than raw request credential.
    body = desktops.DesktopInput(**{**record(), 'auth_type':'vault', 'credential_ref':'vault-uuid'})
    row = body.model_dump(); row['port'] = 3389
    settings = desktops.resolve_settings(row, desktops.TicketInput(password='ignored'), vault)
    assert settings.password == 'VAULT-RESOLVED-SECRET'
    assert calls == ['vault-uuid']
    assert 'VAULT-RESOLVED-SECRET' not in str(body.model_dump())


def test_protocol_frame_roundtrip_and_rejects():
    async def run():
        reader=asyncio.StreamReader()
        payload=frame('connect','hello','ñ')
        reader.feed_data(payload);reader.feed_eof()
        return await read_frame(reader)
    assert asyncio.run(run()) == ['connect','hello','ñ']
    assert frame('unicode','ñ','🎉') == b'7.unicode,1.\xc3\xb1,1.\xf0\x9f\x8e\x89;' 
    with pytest.raises(ProtocolError): frame('big','x'*70000)
    async def invalid(payload):
        reader=asyncio.StreamReader();reader.feed_data(payload);reader.feed_eof()
        return await read_frame(reader)
    for raw in (b'x.bad;', b'2.xx?', b'9000000.', b'1.\xff;'):
        with pytest.raises((ProtocolError, asyncio.IncompleteReadError)):
            asyncio.run(invalid(raw))


def test_guacd_handshake_maps_only_allowlisted_fields():
    class Writer:
        def __init__(self): self.chunks=[]
        def write(self,data): self.chunks.append(data)
        async def drain(self): pass
    async def run():
        reader=asyncio.StreamReader()
        reader.feed_data(frame('args','VERSION_1_1_0','hostname','port','password','domain','security','ignore-cert','untrusted-field'))
        reader.feed_data(frame('ready','abc-client-id'))
        writer=Writer()
        settings = DesktopSettings(protocol='rdp',host='192.168.0.5',port=3389,
                                   username='person',password='secret',security='nla')
        result=await handshake(reader,writer,settings)
        return result,writer.chunks
    result,chunks=asyncio.run(run())
    assert result == ['ready','abc-client-id']
    assert chunks[0] == frame('select','rdp')
    assert b'secret' in chunks[-1]
    assert b'untrusted-field' not in b''.join(chunks)
    assert frame('connect','VERSION_1_1_0','192.168.0.5','3389','secret','','nla','false','') in chunks[-1]


def test_guacd_handshake_rejects_invalid_negotiation():
    class Writer:
        def write(self,data): pass
        async def drain(self): pass
    async def run(payload):
        reader=asyncio.StreamReader(); reader.feed_data(payload)
        return await handshake(reader,Writer(),DesktopSettings('vnc','127.0.0.1',5900))
    with pytest.raises(ProtocolError): asyncio.run(run(frame('error','Not supported','519')))
    with pytest.raises(ProtocolError): asyncio.run(run(frame('args','hostname')))
    with pytest.raises(ProtocolError): asyncio.run(run(frame('args','hostname','hostname','port')))
    with pytest.raises(ProtocolError): asyncio.run(run(frame('args','hostname','port')+frame('error','Rejected','519')))


def test_no_database_password_fields(client):
    login(client)
    created(client)
    with m.dbconn() as db:
        columns = [row['name'] for row in db.execute('PRAGMA table_info(desktop_connections)')]
        assert 'password' not in columns
        assert 'credential_ref' in columns
        count = db.execute('SELECT count(*) FROM desktop_connections').fetchone()[0]
    assert count == 1


def test_spice_saved_inventory_ticket_and_multi_channel(client):
    login(client)
    body = {**record('vnc'), 'protocol': 'spice', 'spice_tls': True, 'port': 61000}
    created_resp = mutation(client, 'post', '/api/desktops', json=body)
    assert created_resp.status_code == 201, created_resp.text
    desktop = created_resp.json()
    assert desktop['protocol'] == 'spice' and desktop['spice_tls']
    assert desktop['port'] == 61000
    response = mutation(client, 'post', f"/api/desktops/{desktop['id']}/ticket", json={'password':'spice-secret'})
    assert response.status_code == 200 and response.headers['cache-control'] == 'no-store'
    assert response.json()['spice_password'] == 'spice-secret'
    token = response.json()['ticket']
    group = desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session'))
    assert group is not None and group.channels == 1 and group.settings.password == ''
    assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')).session_id == group.session_id
    assert group.channels == 2
    for _ in range(desktops.MAX_SPICE_CHANNELS - 2):
        assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')) is not None
    assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')) is None
    assert len(desktops.ACTIVE) == 1
    for _ in range(desktops.MAX_SPICE_CHANNELS): desktops.release_spice_channel(token)
    assert group.channels == 0
    group.idle_deadline = time.monotonic() - 1
    with desktops.GUARD: desktops.cleanup_spice_groups()
    assert token not in desktops.SPICE_GROUPS
    assert not desktops.ACTIVE
    assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')) is None
    assert 'spice-secret' not in str(m.connection().execute('SELECT * FROM desktop_connections').fetchall())


def test_spice_invalid_modes_and_client_security(client):
    login(client)
    for change in (
        {'read_only': True}, {'domain': 'CORP'}, {'security':'rdp'},
        {'ignore_cert':True},
    ):
        assert mutation(client, 'post', '/api/desktops', json={**record('vnc'), 'protocol':'spice',**change}).status_code == 422
    assert mutation(client, 'post', '/api/desktops', json={**record('vnc'), 'spice_tls':True}).status_code == 422
    vnc = created(client,'vnc')
    token = mutation(client, 'post',f"/api/desktops/{vnc['id']}/ticket",json={}).json()['ticket']
    assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')) is None
    assert token in desktops.TICKETS


def test_spice_transport_tls_context(monkeypatch):
    from app.spice import connect_spice
    settings = DesktopSettings(protocol='spice',host='vm.example.net',port=61000,spice_tls=True)
    seen=[]
    async def connector(host,port,**kwargs):
        seen.append((host,port,kwargs)); return ('r','w')
    assert asyncio.run(connect_spice(settings,connector)) == ('r','w')
    assert seen[0][:2] == ('vm.example.net',61000)
    assert seen[0][2]['ssl'].verify_mode == __import__('ssl').CERT_REQUIRED
    assert seen[0][2]['server_hostname'] == 'vm.example.net'
    settings = DesktopSettings(protocol='spice',host='1.2.3.4',port=5901)
    assert asyncio.run(connect_spice(settings,connector)) == ('r','w')
    assert seen[-1][2]['ssl'] is None


def test_spice_vv_import_is_ephemeral_and_requires_auth(client):
    from app.spice import parse_virt_viewer
    content = '[virt-viewer]\ntype=spice\nhost=10.2.3.4\nport=5901\npassword=EPHEMERAL-PASSWORD\ntitle=Linux guest\n'
    assert client.post('/api/desktops/spice/import-vv',json={'contents':content}).status_code == 403
    login(client)
    response = mutation(client,'post','/api/desktops/spice/import-vv',json={'contents':content})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['label'] == 'Linux guest'
    assert result['spice_password'] == 'EPHEMERAL-PASSWORD'
    assert response.headers['cache-control'] == 'no-store'
    assert client.get('/api/desktops').json() == []
    token = result['ticket']
    assert desktops.TICKETS[token].settings.host == '10.2.3.4'
    assert desktops.TICKETS[token].settings.password == 'EPHEMERAL-PASSWORD'
    assert desktops.acquire_spice_channel(token, client.cookies.get('switchyard_session')) is not None
    assert desktops.SPICE_GROUPS[token].settings.password == ''
    assert 'EPHEMERAL-PASSWORD' not in str(client.get('/api/audit').json())
    assert 'EPHEMERAL-PASSWORD' not in str(client.get('/api/desktops').json())
    for bad in (
        '[virt-viewer]\ntype=rdp\nhost=10.0.0.5\nport=3389',
        '[virt-viewer]\ntype=spice\nhost=bad\r\nHTTP/1.1 200\nport=5900',
        '[virt-viewer]\ntype=spice\nhost=10.0.0.5\nport=0',
        '[virt-viewer]\ntype=spice\nhost=10.0.0.5\nport=5900\nproxy=https://proxy:443',
        '[virt-viewer]\ntype=spice\nhost=pvespiceproxy:token\ntls-port=61000',
        '[virt-viewer]\ntype=spice\nhost=10.0.0.5\nport=5900\nca=-----BEGIN CERTIFICATE-----',
    ):
        with pytest.raises(ValueError): parse_virt_viewer(bad)



def test_spice_vv_bookmarks_save_only_non_secret_identity_and_require_fresh_matching_ticket(client):
    assert client.get('/api/desktops/spice/bookmarks').status_code == 401
    login(client)
    def file(ticket, title='VM 9909 - winserver25'):
        return ('[virt-viewer]\\ntype=spice\\ntitle='+title+
                '\\nhost=pvespiceproxy:'+ticket+
                '\\nproxy=http://pve.example.net:3128\\ntls-port=61000'+
                '\\nhost-subject=O=Proxmox,CN=pve.example.net'+
                '\\npassword=SINGLE-USE-SECRET-'+ticket+'\\n')
    initial = mutation(client, 'post','/api/desktops/spice/import-vv',
        json={'contents':file('ticket-1'), 'save_bookmark':True})
    assert initial.status_code == 200, initial.text
    info = initial.json()
    assert info['node'] == 'pve.example.net'
    assert info['bookmark']['label'] == 'VM 9909 - winserver25'
    bookmark_id = info['bookmark']['id']
    assert info['spice_password'] == 'SINGLE-USE-SECRET-ticket-1'
    shortcuts = client.get('/api/desktops/spice/bookmarks').json()
    assert len(shortcuts) == 1 and shortcuts[0]['id'] == bookmark_id
    assert 'password' not in str(shortcuts).lower()
    assert 'ticket-1' not in str(shortcuts)
    assert 'pvespiceproxy' not in str(shortcuts)
    assert 'SINGLE-USE-SECRET' not in str(shortcuts)
    persisted = [tuple(row) for row in m.connection().execute(
        'SELECT id,label,node,created_at FROM spice_vv_bookmarks')]
    assert len(persisted) == 1 and 'ticket-1' not in str(persisted)
    assert client.get('/api/desktops').json() == []

    again = mutation(client, 'post','/api/desktops/spice/import-vv',
        json={'contents':file('ticket-2'), 'bookmark_id':bookmark_id})
    assert again.status_code == 200, again.text
    assert again.json()['bookmark']['id'] == bookmark_id
    assert again.json()['ticket'] != info['ticket']
    assert again.json()['spice_password'] == 'SINGLE-USE-SECRET-ticket-2'

    wrong = mutation(client, 'post','/api/desktops/spice/import-vv',
        json={'contents':file('ticket-3','Different VM'),
              'bookmark_id':bookmark_id})
    assert wrong.status_code == 409
    unknown = mutation(client, 'post','/api/desktops/spice/import-vv',
        json={'contents':file('ticket-4'),'bookmark_id':'missing'})
    assert unknown.status_code == 404
    assert len(client.get('/api/desktops/spice/bookmarks').json()) == 1

    remove = mutation(client, 'delete',
        '/api/desktops/spice/bookmarks/'+bookmark_id)
    assert remove.status_code == 200
    assert client.get('/api/desktops/spice/bookmarks').json() == []
    assert mutation(client, 'delete',
        '/api/desktops/spice/bookmarks/'+bookmark_id).status_code == 404


def test_spice_proxmox_vv_proxy_and_tls_parse():
    from app.spice import parse_virt_viewer, proxy_endpoint
    vv='''[virt-viewer]
    type=spice
    title=Proxmox guest
    host=pvespiceproxy:abcdef:100:pve::deadbeef
    proxy=http://proxmox.example.net:3128
    tls-port=61000
    host-subject=O=Proxmox,CN=proxmox.example.net
    password=ticket-secret
    '''
    label, settings = parse_virt_viewer(vv)
    assert label == 'Proxmox guest'
    assert settings.spice_proxy == 'http://proxmox.example.net:3128'
    assert settings.spice_tls and settings.port == 61000
    assert settings.spice_server_name == 'proxmox.example.net'
    assert settings.password == 'ticket-secret'
    assert proxy_endpoint('proxy.example.com') == ('proxy.example.com',3128)
    for bad in ('https://proxy:3128','http://user:pass@proxy:3128','http://proxy:3128/a', 'http://proxy:99999'):
        with pytest.raises(ValueError): proxy_endpoint(bad)


def test_spice_websocket_binary_relay_and_rejects(client, monkeypatch):
    login(client)
    record_resp = mutation(client,'post','/api/desktops',json={**record('vnc'),'protocol':'spice'})
    assert record_resp.status_code == 201, record_resp.text
    did = record_resp.json()['id']
    token = mutation(client,'post',f'/api/desktops/{did}/ticket',json={'password':'echo'}).json()['ticket']
    captured = []
    class Writer:
        def __init__(self,reader): self.reader=reader; self.is_closed=False
        def write(self,data): captured.append(data); self.reader.feed_data(data.upper())
        async def drain(self): pass
        def close(self): self.is_closed=True; self.reader.feed_eof()
        async def wait_closed(self): pass
    async def fake_connect(settings):
        reader = asyncio.StreamReader()
        return reader, Writer(reader)
    monkeypatch.setattr(desktops,'connect_spice',fake_connect)
    with client.websocket_connect('/ws/spice/'+token,headers={'origin':'http://testserver'}) as ws:
        ws.send_bytes(b'hello-channel')
        assert ws.receive_bytes() == b'HELLO-CHANNEL'
        assert len(desktops.SPICE_GROUPS) == 1
    assert captured == [b'hello-channel']
    assert desktops.SPICE_GROUPS[token].channels == 0
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws/spice/'+token,headers={'origin':'https://evil.test'}):
            pass
    assert desktops.SPICE_GROUPS[token].channels == 0
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/ws/spice/not-a-valid-ticket',headers={'origin':'http://testserver'}):
            pass


def test_spice_proxy_connect_sequence():
    from app.spice import connect_spice
    class Writer:
        def __init__(self): self.parts=[]; self.closed=False
        def write(self,chunk): self.parts.append(chunk)
        async def drain(self): pass
        def close(self): self.closed=True
    async def check(response):
        reader=asyncio.StreamReader();reader.feed_data(response)
        writer=Writer();called=[]
        async def connector(host,port,**kwargs):
            called.append((host,port,kwargs)); return reader,writer
        settings = DesktopSettings(protocol='spice',host='pvespiceproxy:ticket:vm',port=61000,
                                  spice_proxy='http://pve.example.com:3128')
        try: await connect_spice(settings,connector)
        except ConnectionError: pass
        return called,writer
    called,writer=asyncio.run(check(b'HTTP/1.1 200 Connection established\r\n\r\n'))
    assert called[0][:2] == ('pve.example.com',3128)
    assert writer.parts == [b'CONNECT pvespiceproxy:ticket:vm:61000 HTTP/1.1\r\nHost: pvespiceproxy:ticket:vm:61000\r\n\r\n']
    assert not writer.closed
    _,badwriter=asyncio.run(check(b'HTTP/1.1 401 Unauthorized\r\n\r\n'))
    assert badwriter.closed


def test_desktop_tcp_probe_audited_and_no_credential_disclosure(client, monkeypatch):
    login(client)
    item=created(client, 'rdp')
    async def fake_probe(host,port,validate_tls=False):
        assert host == '192.168.0.50' and port == 3389 and not validate_tls
        return {'reachable':True,'tls_validated':False,'elapsed_ms':13,'message':'TCP port reachable; authentication not tested'}
    monkeypatch.setattr(desktops,'probe',fake_probe)
    resp=mutation(client,'post',f"/api/desktops/{item['id']}/probe",json={})
    assert resp.status_code == 200 and resp.json()['elapsed_ms'] == 13
    assert 'password' not in str(resp.json())
    assert 'desktop.probe' in str(client.get('/api/audit').json())
    assert client.post(f"/api/desktops/{item['id']}/probe",json={}).status_code == 403


def test_desktop_session_history_persists_without_secret(client):
    from app import desktop_history
    login(client)
    item=created(client,'spice')
    session_id='session-'+secrets.token_hex(8)
    desktop_history.started(m.connection,session_id,item['id'],item['label'],'spice')
    desktop_history.opened(m.connection,session_id)
    desktop_history.opened(m.connection,session_id)
    desktop_history.finished(m.connection,session_id)
    response=client.get('/api/desktops/sessions/history')
    assert response.status_code == 200
    obj=next(x for x in response.json() if x['session_id']==session_id)
    assert obj['protocol']=='spice' and obj['channel_count']==2 and obj['outcome']=='closed'
    assert 'password' not in str(obj)
    assert client.get('/api/desktops/sessions/history?limit=0').status_code == 200
    assert client.get('/api/desktops/sessions/history?limit=abc').status_code == 422


def test_desktop_ticket_bound_to_original_browser_session(client):
    login(client)
    obj=created(client, 'rdp')
    cookie=client.cookies.get('switchyard_session')
    token=mutation(client,'post',f"/api/desktops/{obj['id']}/ticket",json={}).json()['ticket']
    assert desktops.consume_ticket(token, 'some-other-valid-admin-session') is None
    assert token in desktops.TICKETS, 'Unauthorized attempt must not consume valid ticket'
    assert desktops.consume_ticket(token,cookie) is not None
    spice=created(client,'spice')
    token=mutation(client,'post',f"/api/desktops/{spice['id']}/ticket",json={}).json()['ticket']
    assert desktops.acquire_spice_channel(token, 'some-other-valid-admin-session') is None
    assert desktops.acquire_spice_channel(token,cookie) is not None
    assert desktops.acquire_spice_channel(token, 'some-other-valid-admin-session') is None
    assert desktops.SPICE_GROUPS[token].channels == 1


def test_private_desktop_viewer_static_path_and_csp(client):
    # The original static whitelist rejected every Guacamole/SPICE runtime asset.
    viewer = client.get('/static/spice-view.html')
    assert viewer.status_code == 200, viewer.text[:200]
    assert 'spice-screen' in viewer.text
    assert viewer.headers['x-frame-options'] == 'SAMEORIGIN'
    assert "frame-ancestors 'self'" in viewer.headers['content-security-policy']
    module = client.get('/static/spice-view.js')
    assert module.status_code == 200
    assert 'javascript' in module.headers['content-type']
    main_html = client.get('/')
    assert main_html.headers['x-frame-options'] == 'DENY'
    assert "frame-ancestors 'none'" in main_html.headers['content-security-policy']
    assert client.get('/static/../app/main.py').status_code in (404, 403)


def test_guacamole_websocket_bridge_mock_remote(client, monkeypatch):
    login(client)
    item=created(client,'rdp')
    ticket=mutation(client,'post',f"/api/desktops/{item['id']}/ticket",json={}).json()['ticket']
    remote=[]
    class Writer:
        def __init__(self,reader): self.reader=reader
        def write(self,data): remote.append(data); self.reader.feed_data(frame('ack','ok'))
        async def drain(self): pass
        def close(self): self.reader.feed_eof()
        async def wait_closed(self): pass
    async def fake_remote():
        reader=asyncio.StreamReader()
        return reader,Writer(reader)
    async def fake_handshake(reader,writer,settings):
        assert settings.protocol == 'rdp'
        return ['ready','mock-session']
    monkeypatch.setattr(desktops,'connect_guacd',fake_remote)
    monkeypatch.setattr(desktops,'handshake',fake_handshake)
    with client.websocket_connect('/ws/desktop/'+ticket,headers={'origin':'http://testserver'}) as ws:
        assert ws.receive_text() == frame('ready','mock-session').decode()
        ws.send_text(frame('key','1','97').decode())
        assert ws.receive_text() == frame('ack','ok').decode()
    assert remote == [frame('key','1','97')]
    assert desktops.ACTIVE == {}


def test_spice_default_port_create_and_update(client):
    login(client)
    obj = created(client, 'spice')
    assert obj['port'] == 5901
    res = mutation(client, 'put', f"/api/desktops/{obj['id']}", json=record('spice'))
    assert res.status_code == 200
    assert res.json()['port'] == 5901


def test_desktop_guacd_gateway_diagnostic(client, monkeypatch):
    login(client)
    class Writer:
        closed = False
        def close(self): self.closed = True
        async def wait_closed(self): pass
    writer = Writer()
    async def connected(): return object(), writer
    monkeypatch.setattr(desktops, 'connect_guacd', connected)
    result = client.get('/api/desktops/gateway/status')
    assert result.status_code == 200 and result.json()['ready'] is True
    assert result.json()['protocols'] == ['rdp', 'vnc']
    assert writer.closed
    async def refused(): raise OSError('test failure')
    monkeypatch.setattr(desktops, 'connect_guacd', refused)
    result = client.get('/api/desktops/gateway/status')
    assert result.status_code == 200 and result.json()['ready'] is False
    assert 'test failure' not in result.text
    client.cookies.clear()
    assert client.get('/api/desktops/gateway/status').status_code == 401


def test_session_csv_export_is_bounded_authenticated_and_formula_safe(client):
    from app import desktop_history
    assert client.get('/api/desktops/sessions/export').status_code == 401
    login(client)
    desktop_history.started(m.connection, 'sess-csv', 'desktop-test', '=DANGEROUS()', 'vnc')
    desktop_history.finished(m.connection, 'sess-csv')
    response = client.get('/api/desktops/sessions/export')
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert 'attachment' in response.headers['content-disposition']
    assert "'=DANGEROUS()" in response.text
    assert 'sess-csv' in response.text
    assert 'desktop.sessions.exported' in str(client.get('/api/audit').json())


def test_desktop_favorites_persist_and_order_before_other_assets(client):
    login(client)
    a=created(client,'rdp'); b=created(client,'vnc')
    r=mutation(client,'put',f"/api/desktops/{b['id']}",json={**record('vnc'), 'favorite':True})
    assert r.status_code == 200 and r.json()['favorite'] is True
    listed=client.get('/api/desktops').json()
    assert listed[0]['id']==b['id'] and listed[1]['id']==a['id']
    assert listed[1]['favorite'] is False
    with m.dbconn() as db:
        assert db.execute('SELECT favorite FROM desktop_connections WHERE id=?',(b['id'],)).fetchone()[0]==1


def test_duplicate_connection_copies_settings_but_not_identity_or_favorite(client):
    login(client)
    original=mutation(client,'post','/api/desktops',json={**record('rdp'),'favorite':True,'port':3390}).json()
    result=mutation(client,'post',f"/api/desktops/{original['id']}/duplicate",json={})
    assert result.status_code==201, result.text
    copied=result.json()
    assert copied['id']!=original['id']
    assert copied['label']==original['label']+' (copy)'
    assert copied['port']==3390 and copied['protocol']=='rdp'
    assert copied['favorite'] is False
    assert len(client.get('/api/desktops').json())==2
    assert mutation(client,'post','/api/desktops/none/duplicate',json={}).status_code==404


def test_inventory_json_export_authenticated_and_without_passwords(client):
    assert client.get('/api/desktops/export').status_code==401
    login(client)
    item=created(client,'rdp')
    response=client.get('/api/desktops/export')
    assert response.status_code==200
    data=response.json()
    assert data['format']=='switchyard-desktops-v1'
    assert len(data['connections'])==1
    assert data['connections'][0]['label']==item['label']
    assert 'password' not in str(data)
    assert data['connections'][0]['favorite'] is False
    assert 'attachment' in response.headers['content-disposition']


def test_desktop_import_validates_whole_batch_and_preserves_existing(client):
    login(client)
    payload={'format':'switchyard-desktops-v1','connections':[record('rdp'),record('spice')]}
    response=mutation(client,'post','/api/desktops/import',json=payload)
    assert response.status_code==200, response.text
    assert response.json()['created']==2
    assert len(set(response.json()['ids']))==2
    assert client.get('/api/desktops').json()[0]['port'] in (3389,5901)
    bad={**payload,'connections':[record('vnc'),{**record('rdp'),'host':'bad..name'}]}
    assert mutation(client,'post','/api/desktops/import',json=bad).status_code==422
    bad={**payload,'connections':[{'password':'no-import',**record('rdp')}]}
    assert mutation(client,'post','/api/desktops/import',json=bad).status_code==422
    assert len(client.get('/api/desktops').json())==2
    assert mutation(client,'post','/api/desktops/import',json={**payload,'format':'other'}).status_code==422
    assert client.post('/api/desktops/import',json=payload).status_code==403


def test_import_schema_matches_full_export_capacity(client):
    login(client)
    batch={**record('vnc'),'environment':'Restored'}
    payload={'format':'switchyard-desktops-v1','connections':[batch for _ in range(101)]}
    response=mutation(client,'post','/api/desktops/import',json=payload)
    assert response.status_code==200, response.text
    assert response.json()['created']==101
    assert len(client.get('/api/desktops').json())==101
    too_many={'format':'switchyard-desktops-v1','connections':[batch for _ in range(501)]}
    assert mutation(client,'post','/api/desktops/import',json=too_many).status_code==422
    assert len(client.get('/api/desktops').json())==101


def test_bounded_bulk_port_probe_and_target_validation(client, monkeypatch):
    login(client)
    rdp=created(client,'rdp');vnc=created(client,'vnc')
    calls=[]
    async def fake_probe(host,port,tls=False):
        calls.append((host,port,tls))
        return {'reachable':True,'elapsed_ms':4,'message':'TCP reachable','tls_validated':tls}
    monkeypatch.setattr(desktops,'probe',fake_probe)
    payload={'ids':[rdp['id'],vnc['id']]}
    result=mutation(client,'post','/api/desktops/probes',json=payload)
    assert result.status_code==200 and result.json()['count']==2
    assert len(calls)==2
    assert mutation(client,'post','/api/desktops/probes',json={'ids':[rdp['id'],rdp['id']]}).status_code==422
    assert mutation(client,'post','/api/desktops/probes',json={'ids':['missing']}).status_code==404
    assert mutation(client,'post','/api/desktops/probes',json={'ids':[]}).status_code==422
    assert client.post('/api/desktops/probes',json=payload).status_code==403


def test_desktop_history_filtering_by_protocol_and_outcome(client):
    from app import desktop_history
    login(client)
    desktop_history.started(m.connection,'rdp-session','a','RDP desktop','rdp')
    desktop_history.started(m.connection,'spice-session','b','SPICE desktop','spice')
    desktop_history.finished(m.connection,'spice-session',True)
    filtered=client.get('/api/desktops/sessions/history?protocol=spice&outcome=failed')
    assert filtered.status_code==200
    assert [item['session_id'] for item in filtered.json()]==['spice-session']
    assert client.get('/api/desktops/sessions/history?protocol=telnet').status_code==422
    assert client.get('/api/desktops/sessions/history?outcome=unknown').status_code==422


def test_session_task_registry_cleans_up_after_guacamole_bridge(client,monkeypatch):
    assert hasattr(desktops,'ACTIVE_TASKS')
    with desktops.GUARD:
        desktops.ACTIVE_TASKS.clear()
    assert not desktops.ACTIVE_TASKS


def test_authenticated_session_termination_cancels_all_protocol_channels(client):
    login(client)
    class Task:
        def __init__(self): self.cancelled=False
        def cancel(self): self.cancelled=True
    a,b=Task(),Task()
    with desktops.GUARD:
        desktops.ACTIVE_TASKS['managed-session']={a,b}
    try:
        result=mutation(client,'post','/api/desktops/sessions/managed-session/disconnect',json={})
        assert result.status_code==200 and result.json()['channels_terminated']==2
        assert a.cancelled and b.cancelled
        assert mutation(client,'post','/api/desktops/sessions/unknown/disconnect',json={}).status_code==404
        assert client.post('/api/desktops/sessions/managed-session/disconnect',json={}).status_code==403
    finally:
        with desktops.GUARD:
            desktops.ACTIVE_TASKS.pop('managed-session',None)


def test_failed_probe_in_batch_is_isolated_and_does_not_leak_error(client,monkeypatch):
    login(client)
    good=created(client,'rdp');bad=created(client,'vnc')
    async def fake_probe(host,port,tls=False):
        if port==5900: raise ValueError('sensitive network internals')
        return {'reachable':True,'tls_validated':False,'elapsed_ms':2,'message':'TCP reachable'}
    monkeypatch.setattr(desktops,'probe',fake_probe)
    response=mutation(client,'post','/api/desktops/probes',json={'ids':[good['id'],bad['id']]})
    assert response.status_code==200 and response.json()['count']==2
    assert response.json()['results'][0]['reachable']
    assert not response.json()['results'][1]['reachable']
    assert 'sensitive network internals' not in response.text
