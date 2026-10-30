"""Classification of SSH transport failures without leaking remote details."""
import socket
import sys
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from app import main as m

class FakeSSHException(Exception): pass
class FakeAuthException(FakeSSHException): pass
class FakeHostException(FakeSSHException): pass

@pytest.mark.parametrize('raised,code,phrase',[
 (FakeHostException('server changed'),409,'host key changed'),
 (FakeAuthException('password=secret'),502,'authentication rejected'),
 (FakeSSHException('Server not found in known_hosts'),409,'not trusted'),
 (FakeSSHException('banner password=secret'),502,'protocol negotiation'),
 (TimeoutError('password=secret'),504,'timed out'),
 (ConnectionRefusedError('password=secret'),502,'refused'),
 (socket.gaierror('password=secret'),502,'could not be resolved'),
 (OSError('password=secret'),502,'network connection failed'),
 (Exception('password=secret'),502,'unexpectedly'),
])
def test_ssh_diagnostics_are_safe(monkeypatch,tmp_path,raised,code,phrase):
 class Client:
  closed=False
  def load_host_keys(self,path): pass
  def set_missing_host_key_policy(self,policy): pass
  def connect(self,**kwargs): raise raised
  def close(self): self.closed=True
 client=Client()
 mock=SimpleNamespace(SSHClient=lambda:client,RejectPolicy=lambda:object(),
   BadHostKeyException=FakeHostException,AuthenticationException=FakeAuthException,
   SSHException=FakeSSHException)
 monkeypatch.setitem(sys.modules,'paramiko',mock)
 monkeypatch.setattr(m,'DATA',tmp_path)
 with pytest.raises(HTTPException) as exc:
  m.ssh_client({'id':'test','host':'192.168.0.6','port':22,'username':'admin',
    'auth_type':'interactive','credential_ref':''},'test-password')
 assert exc.value.status_code == code
 assert phrase in exc.value.detail.lower()
 assert 'secret' not in exc.value.detail
 assert client.closed
