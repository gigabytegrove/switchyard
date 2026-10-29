"""Machine-profile folders and encrypted credential persistence / confidentiality."""
from pathlib import Path
import io
import json
import sqlite3
import zipfile
import pytest
from app import main as m
from tests.test_app import client, authenticate, asset

ORIGIN = {'Origin':'http://testserver'}


def test_folder_hierarchy_and_machine_assignment(client):
    authenticate(client)
    parent = client.post('/api/folders', headers=ORIGIN, json={'name':'Production'});
    assert parent.status_code == 201, parent.text
    root = parent.json()['id']
    child = client.post('/api/folders', headers=ORIGIN, json={'name':'Databases','parent_id':root})
    assert child.status_code == 201, child.text
    fid = child.json()['id']
    assert client.post('/api/folders', headers=ORIGIN, json={'name':'DATABASES','parent_id':root}).status_code == 409
    a={**asset(), 'folder_id':fid}
    created=client.post('/api/assets',headers=ORIGIN,json=a)
    assert created.status_code == 201, created.text
    aid=created.json()['id']
    assert client.get('/api/assets').json()[0]['folder_id'] == fid
    assert client.delete('/api/folders/' + fid,headers=ORIGIN).status_code == 409
    assert client.put('/api/folders/' + root,headers=ORIGIN,json={'name':'Loop','parent_id':fid}).status_code == 422
    assert client.put('/api/assets/'+aid,headers=ORIGIN,json={**a,'folder_id':''}).status_code == 200
    assert client.delete('/api/folders/'+fid,headers=ORIGIN).status_code == 200
    assert client.delete('/api/folders/'+root,headers=ORIGIN).status_code == 200


def test_ssh_password_storage_is_encrypted_and_write_only(client):
    authenticate(client)
    password = 'test-only-never-persist-in-cleartext-!89'
    created = client.post('/api/assets', headers=ORIGIN,json={**asset(), 'password':password})
    assert created.status_code == 201, created.text
    aid=created.json()['id']
    listing = client.get('/api/assets').json()[0]
    assert listing['has_saved_password'] is True
    assert password not in json.dumps(listing)
    with sqlite3.connect(m.DB_FILE) as db:
        encrypted=db.execute("SELECT ciphertext FROM saved_passwords WHERE kind='ssh' AND entity_id=?",(aid,)).fetchone()[0]
    assert password not in encrypted
    assert m.saved_password('ssh',aid) == password
    key=m.DATA/'credentials.key'
    assert key.is_file() and not key.stat().st_mode & 0o077
    # Empty password on an edit retains it; deletion is explicit.
    assert client.put('/api/assets/'+aid,headers=ORIGIN,json={**asset(),'password':''}).status_code == 200
    assert m.saved_password('ssh',aid) == password
    assert client.put('/api/assets/'+aid,headers=ORIGIN,json={**asset(),'clear_password':True}).status_code == 200
    assert m.saved_password('ssh',aid) is None


def test_secret_backup_restores_key_and_does_not_include_plaintext(client):
    authenticate(client)
    password='test-only-secret-value-00001029'
    assert client.post('/api/assets',headers=ORIGIN,json={**asset(),'password':password}).status_code == 201
    response=client.get('/api/backup')
    assert response.status_code == 200, response.text
    assert password.encode() not in response.content
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert 'credentials.key' in archive.namelist()
        manifest=json.loads(archive.read('manifest.json'))
        assert 'credentials.key' in manifest['files']
    (m.DATA/'credentials.key').unlink()
    with pytest.raises(Exception):
        m.saved_password('ssh',client.get('/api/assets').json()[0]['id'])


def test_desktop_password_is_write_only_and_not_exported(client):
    authenticate(client)
    body={'label':'Server desktop','host':'192.168.0.12','protocol':'rdp','port':3389,
          'username':'operator','auth_type':'interactive','password':'desktop-secret-123!'}
    result=client.post('/api/desktops',headers=ORIGIN,json=body)
    assert result.status_code == 201, result.text
    did=result.json()['id']
    assert result.json()['has_saved_password'] is True
    assert 'desktop-secret' not in result.text
    assert m.saved_password('desktop',did)=='desktop-secret-123!'
    exported=client.get('/api/desktops/export')
    assert exported.status_code == 200
    assert 'desktop-secret' not in exported.text
    assert '"password"' not in exported.text
    assert client.put('/api/desktops/'+did,headers=ORIGIN,json={**body,'password':''}).status_code == 200
    assert m.saved_password('desktop',did)=='desktop-secret-123!'
    assert client.delete('/api/desktops/'+did,headers=ORIGIN).status_code == 200
    assert m.saved_password('desktop',did) is None


def test_mfa_login_options_optional_on_lan(client):
    assert client.get('/api/login/options').json() == {'mfa_required':False}


def test_updater_admin_authorization_and_detached_safe_command(client, monkeypatch):
    authenticate(client)
    a=client.post('/api/assets',headers=ORIGIN,json={**asset(),'password':'test-ssh-password-foo'}).json()['id']
    config={'asset_id':a,'compose_project':'testing-projects-switchyard-0g6qqq',
            'repository_directory':'/root/switchyard/switchyard',
            'current_password':'serious-development-password-12345'}
    assert client.put('/api/update/config',headers=ORIGIN,json={**config,'current_password':'wrong'}).status_code == 403
    assert client.put('/api/update/config',headers=ORIGIN,json={**config,'repository_directory':'/tmp/../../etc'}).status_code == 422
    assert client.put('/api/update/config',headers=ORIGIN,json=config).status_code == 200
    assert client.get('/api/update/status').json()['automatic_install_available'] is True
    calls=[]
    def mock_remote(_asset, command):
        calls.append(command)
        if command.startswith('nohup '):
            return 'SWITCHYARD_UPDATE_PID:123'
        return 'SWITCHYARD_UPDATE_SUCCESS'
    monkeypatch.setattr(m,'remote_command',mock_remote)
    assert client.post('/api/update/install',headers=ORIGIN,json={'current_password':'wrong'}).status_code == 403
    assert not calls
    res=client.post('/api/update/install',headers=ORIGIN,json={'current_password':config['current_password']})
    assert res.status_code == 200, res.text
    assert res.json()['status'] == 'scheduled'
    assert calls and calls[0].startswith('nohup sh -c ')
    assert 'git remote get-url origin' in calls[0]
    assert 'docker compose -p testing-projects-switchyard-0g6qqq' in calls[0]
    assert '>/dev/null' not in calls[0] or '2>&1' in calls[0]
    job=client.get('/api/update/job')
    assert job.status_code == 200
    assert job.json()['status'] == 'success'
    assert job.json()['job'] == res.json()['job']


def test_updater_fails_closed_without_saved_ssh_password(client):
    authenticate(client)
    aid=client.post('/api/assets',headers=ORIGIN,json=asset()).json()['id']
    config={'asset_id':aid,'compose_project':'prod-switchyard',
            'repository_directory':'/opt/switchyard',
            'current_password':'serious-development-password-12345'}
    assert client.put('/api/update/config',headers=ORIGIN,json=config).status_code==200
    response=client.post('/api/update/install',headers=ORIGIN,json={'current_password':config['current_password']})
    assert response.status_code==409
