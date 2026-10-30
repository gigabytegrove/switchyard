#!/usr/bin/env python3
"""Actual TCP/WebSocket acceptance, run against the fresh Compose application image.

Not an ASGI TestClient: fails when Uvicorn has no WebSocket implementation, even
though /healthz is green. The machine has a deliberately closed SSH port, so
a successful test also proves the server handles real WebSocket messages.
"""
import json
import urllib.request
from websockets.sync.client import connect
from websockets.exceptions import InvalidStatus

BASE = "http://127.0.0.1:9791"
ORIGIN = BASE

def api(path, *, method="GET", data=None, cookie=None):
    headers={"Origin":ORIGIN, "Content-Type":"application/json"}
    if cookie: headers["Cookie"]=cookie
    req=urllib.request.Request(BASE+path, method=method, headers=headers,
       data=json.dumps(data).encode() if data is not None else None)
    with urllib.request.urlopen(req,timeout=15) as response:
        return response, json.loads(response.read())

_, login=api("/api/login",method="POST",data={
    "username":"ci-admin","password":"ci-disposable-development-password-2026"})
assert login["ok"] is True
# urllib response after context closure keeps the headers.
# Obtain session using a second authenticated login with the same disposable account.
req=urllib.request.Request(BASE+"/api/login",method="POST",
  headers={"Origin":ORIGIN,"Content-Type":"application/json"},
  data=json.dumps({"username":"ci-admin","password":"ci-disposable-development-password-2026"}).encode())
with urllib.request.urlopen(req,timeout=15) as response:
    cookie=response.headers.get("Set-Cookie","").split(";",1)[0]
assert cookie.startswith("switchyard_session="), "Login session cookie not issued"
_, asset=api("/api/assets",method="POST",cookie=cookie,data={
    "label":"Runtime network WebSocket probe","host":"127.0.0.1","port":1,
    "username":"ci-probe","auth_type":"interactive","password":"throwaway-ci-only",
    "environment":"CI"})
aid=asset["id"]
url=f"ws://127.0.0.1:9791/ws/terminal/{aid}"
try:
    # Missing/invalid session must not upgrade to a terminal connection.
    with connect(url,origin=ORIGIN,open_timeout=8,close_timeout=2):
        raise AssertionError("Unauthenticated WebSocket unexpectedly accepted")
except InvalidStatus as exc:
    assert exc.response.status_code in (401,403), (
      f"Unexpected unauthenticated upgrade status: {exc.response.status_code}")
print("PASS: unauthenticated WebSocket refused")
with connect(url,origin=ORIGIN,additional_headers={"Cookie":cookie},
             open_timeout=12,close_timeout=3) as ws:
    # connect() only returns after the *real* HTTP 101 Switching Protocols.
    print("PASS: authenticated WebSocket upgraded to HTTP 101")
    ws.send(json.dumps({"type":"auth","password":"throwaway-ci-only"}))
    received=json.loads(ws.recv(timeout=20))
    assert received["type"]=="error",received
    assert received.get("code")=="ssh_connection_error",received
    assert "SSH connection refused" in received.get("message",""),received
    print("PASS: terminal ASGI route received auth frame, attempted SSH, returned typed failure")
