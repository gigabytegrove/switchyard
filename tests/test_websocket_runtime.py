"""WebSocket protocol is a mandatory runtime dependency, not a test-only extra."""
from pathlib import Path
import importlib.util
ROOT=Path(__file__).resolve().parents[1]

def test_runtime_includes_websocket_server_implementation():
    requirements=(ROOT/'requirements.txt').read_text()
    assert 'websockets==16.0' in requirements
    assert importlib.util.find_spec('websockets') is not None
    from uvicorn.protocols.websockets.auto import AutoWebSocketsProtocol
    assert AutoWebSocketsProtocol is not None, 'Uvicorn lacks a WebSocket ASGI implementation'

def test_docker_ci_proves_live_tcp_upgrade():
    ci=(ROOT/'.github/workflows/ci.yml').read_text()
    assert 'python3 scripts/probe-websocket.py' in ci
    assert 'python3 -m pip install --disable-pip-version-check websockets==16.0' in ci
    probe=(ROOT/'scripts/probe-websocket.py').read_text()
    assert 'ws://127.0.0.1:9791/ws/terminal/' in probe
    assert 'connect(url,origin=ORIGIN' in probe
    assert 'unauthenticated WebSocket' in probe
