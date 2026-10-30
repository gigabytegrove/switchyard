#!/usr/bin/env python3
"""Real image integration test: cookie -> HTTP 101 -> verified host key -> SSH -> shell output."""
import base64
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from websockets.sync.client import connect

BASE = "http://127.0.0.1:9791"
HOST = "127.0.0.1"
PORT = 22222

def api(path, *, method="GET", data=None, cookie=None):
    headers={"Origin":BASE, "Content-Type":"application/json"}
    if cookie:
        headers["Cookie"]=cookie
    req=urllib.request.Request(BASE+path,method=method,headers=headers,
        data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.urlopen(req,timeout=15) as resp:
        return resp.headers, json.loads(resp.read())

def container(*args):
    cid=subprocess.check_output(["docker","compose","ps","-q","switchyard"],text=True).strip()
    return subprocess.check_output(["docker","exec",cid,*args],text=True)

for _ in range(80):
    try:
        container("test","-f","/tmp/ci_ssh_ready")
        break
    except subprocess.CalledProcessError:
        time.sleep(0.25)
else:
    raise AssertionError("Disposable SSH target never became ready")

login_data={"username":"ci-admin","password":"ci-disposable-development-password-2026"}
headers, _=api("/api/login",method="POST",data=login_data)
cookie=headers.get("Set-Cookie","").split(";",1)[0]
assert cookie.startswith("switchyard_session="), "Missing session cookie"
_, asset=api("/api/assets",method="POST",cookie=cookie,data={
    "label":"Live image SSH/WebSocket integration",
    "host":HOST,"port":PORT,"username":"switchyardci",
    "auth_type":"interactive","password":"disposable-ci-ssh-credential-2026",
    "environment":"CI"
})
aid=asset["id"]
_, discovered=api("/api/hosts/discover",method="POST",cookie=cookie,data={"host":HOST,"port":PORT})
hostkey=container("cat","/tmp/ci_ssh_host.pub").strip().split()
assert len(hostkey)>=2
expected="SHA256:"+base64.b64encode(hashlib.sha256(base64.b64decode(hostkey[1])).digest()).decode().rstrip("=")
assert discovered["fingerprint"]==expected, (
    f"SSH fingerprint mismatch: reported={discovered['fingerprint']}, source={expected}")
_, trusted=api("/api/hosts/trust",method="POST",cookie=cookie,data={
    "host":HOST,"port":PORT,
    "key_type":discovered["key_type"],"public_key":discovered["public_key"]
})
print("PASS: independently verified and trusted SSH host key")
url=f"ws://127.0.0.1:9791/ws/terminal/{aid}"
with connect(url,origin=BASE,additional_headers={"Cookie":cookie},
             open_timeout=12,close_timeout=2) as ws:
    ws.send(json.dumps({"type":"auth","password":""}))
    echoed=""
    sent=False
    for i in range(80):
        msg=json.loads(ws.recv(timeout=10))
        if msg["type"]=="error":
            raise AssertionError(f"SSH terminal error: {msg}")
        if msg["type"]=="connected" and not sent:
            ws.send(json.dumps({"type":"input","data":"printf SWITCHYARD_IMAGE_SSH_OK\n"}))
            sent=True
        if msg["type"]=="data":
            echoed+=msg["data"]
            if "SWITCHYARD_IMAGE_SSH_OK" in echoed:
                break
    assert sent, "Authenticated shell never reported connected"
    assert "SWITCHYARD_IMAGE_SSH_OK" in echoed, repr(echoed)
print("PASS: real Docker image opened SSH shell over live WebSocket and returned command output")
