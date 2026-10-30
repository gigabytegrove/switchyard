"""Live SSH + SFTP against a disposable, loopback-only CI OpenSSH server."""
import os
import subprocess
import json
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from app import main as m

pytestmark=pytest.mark.skipif(os.environ.get('SWITCHYARD_SSH_E2E')!='1',reason='isolated CI SSH daemon required')
ORIGIN='http://127.0.0.1:9791'
PORT=22222
PASSWORD='disposable-ci-ssh-credential-2026'

def test_real_ssh_host_trust_saved_password_sftp_and_terminal(monkeypatch,tmp_path):
    monkeypatch.setattr(m,'DATA',tmp_path/'appliance')
    monkeypatch.setattr(m,'DB_FILE',tmp_path/'appliance'/'switchyard.sqlite3')
    with TestClient(m.app,client=('127.0.0.1',4432),base_url=ORIGIN) as browser:
        headers={'Origin':ORIGIN}
        setup=browser.post('/api/setup/complete',headers=headers,json={
          'claim_code':m.BOOTSTRAP_CODE,'username':'ci-admin',
          'password':'disposable-local-admin-passphrase-2026'})
        assert setup.status_code==200,setup.text
        login=browser.post('/api/login',headers=headers,json={
          'username':'ci-admin','password':'disposable-local-admin-passphrase-2026'})
        assert login.status_code==200,login.text
        created=browser.post('/api/assets',headers=headers,json={
          'label':'Disposable OpenSSH target','host':'127.0.0.1','port':PORT,
          'username':'switchyardci','auth_type':'interactive','password':PASSWORD,
          'use_tmux':False,'environment':'CI'})
        assert created.status_code==201,created.text
        aid=created.json()['id']
        assert PASSWORD not in json.dumps(browser.get('/api/assets').json())
        asset=m.fetch_asset(aid)
        with pytest.raises(HTTPException) as untrusted:
            m.ssh_client(asset)
        assert untrusted.value.status_code==409,untrusted.value.detail
        assert 'not trusted' in untrusted.value.detail.lower()
        discovered=browser.post('/api/hosts/discover',headers=headers,json={'host':'127.0.0.1','port':PORT})
        assert discovered.status_code==200,discovered.text
        key=discovered.json()
        trusted=subprocess.check_output(['ssh-keygen','-lf','/etc/ssh/ssh_host_ed25519_key.pub','-E','sha256'],text=True)
        assert key['fingerprint'] in trusted,'host key must be verified out-of-band'
        approved=browser.post('/api/hosts/trust',headers=headers,json={
          'host':'127.0.0.1','port':PORT,'key_type':key['key_type'],'public_key':key['public_key']})
        assert approved.status_code==200,approved.text
        ssh=m.ssh_client(asset)
        try:
            _,stdout,stderr=ssh.exec_command('printf SWITCHYARD_LIVE_SSH_OK')
            assert stdout.read()==b'SWITCHYARD_LIVE_SSH_OK'
            assert stdout.channel.recv_exit_status()==0
        finally: ssh.close()
        listing=browser.get(f'/api/assets/{aid}/files',params={'path':'.'})
        assert listing.status_code==200,listing.text
        upload=browser.post(f'/api/assets/{aid}/upload',params={'path':'.'},files={
          'file':('switchyard-ci-upload.txt',b'SWITCHYARD_LIVE_SFTP_OK','text/plain')},headers=headers)
        assert upload.status_code==200,upload.text
        download=browser.get(f'/api/assets/{aid}/download',params={'path':'switchyard-ci-upload.txt'})
        assert download.status_code==200,download.text
        assert download.content==b'SWITCHYARD_LIVE_SFTP_OK'
        # Real atomic text-edit workflow and stale-content conflict.
        opened=browser.get(f'/api/assets/{aid}/files/edit',params={'path':'switchyard-ci-upload.txt'})
        assert opened.status_code==200,opened.text
        current=opened.json()
        assert current['content']=='SWITCHYARD_LIVE_SFTP_OK'
        saved=browser.put(f'/api/assets/{aid}/files/edit',headers=headers,json={
          'path':'switchyard-ci-upload.txt','original_sha256':current['sha256'],
          'content':'SWITCHYARD_LIVE_SFTP_EDIT_OK'})
        assert saved.status_code==200,saved.text
        conflict=browser.put(f'/api/assets/{aid}/files/edit',headers=headers,json={
          'path':'switchyard-ci-upload.txt','original_sha256':current['sha256'],
          'content':'DO_NOT_OVERWRITE'})
        assert conflict.status_code==409,conflict.text
        check=browser.get(f'/api/assets/{aid}/download',params={'path':'switchyard-ci-upload.txt'})
        assert check.content==b'SWITCHYARD_LIVE_SFTP_EDIT_OK'
        health=browser.get(f'/api/assets/{aid}/health')
        assert health.status_code==200,health.text
        assert health.json()['status']=='online'
        assert browser.get(f'/api/assets/{aid}/health/history').json()[0]['status']=='online'
        docker=browser.get(f'/api/assets/{aid}/docker/containers')
        assert docker.status_code==200,docker.text
        assert isinstance(docker.json(),list)
        with browser.websocket_connect(f'/ws/terminal/{aid}',headers={'Origin':ORIGIN}) as terminal:
            terminal.send_json({'type':'auth','password':''})
            terminal.send_json({'type':'input','data':'printf SWITCHYARD_LIVE_TERMINAL_OK\n'})
            output=''
            for _ in range(40):
                message=terminal.receive_json()
                assert message['type']!='error',message
                if message['type']=='data':output+=message['data']
                if 'SWITCHYARD_LIVE_TERMINAL_OK' in output:break
            assert 'SWITCHYARD_LIVE_TERMINAL_OK' in output
