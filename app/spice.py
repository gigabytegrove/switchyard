"""Authenticated SPICE transport, HTTP CONNECT and remote-viewer .vv parsing.

SPICE is a multi-channel binary protocol. The browser's isolated spice-html5
runtime opens separate sockets, all authorized with one bounded session token.
No raw SPICE frame or plaintext .vv credential is written to persistence.
"""
from __future__ import annotations

import asyncio
import configparser
import re
import ssl
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import WebSocket

from .guac import DesktopSettings

MAX_FRAME = 1024 * 1024
CONNECT_TIMEOUT = 8
IDLE_TIMEOUT = 900
TARGET_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,253}$')
DNS_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')


def parse_virt_viewer(source: str) -> tuple[str, DesktopSettings]:
    """Convert a one-time virt-viewer (.vv) file to an ephemeral SPICE target.

    Proxy, TLS CA and password values never become saved desktop records.
    Unsupported protocols and malformed proxy/certificate formats fail closed.
    """
    if not 0 < len(source.encode('utf-8')) <= 16384 or '\x00' in source:
        raise ValueError('Invalid or oversized virt-viewer file')
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(source)
    except configparser.Error as exc:
        raise ValueError('Invalid virt-viewer format') from exc
    if not parser.has_section('virt-viewer'):
        raise ValueError('Missing virt-viewer section')
    values = parser['virt-viewer']
    if values.get('type', '').lower() != 'spice':
        raise ValueError('Only SPICE virt-viewer files are supported')
    host = values.get('host', '').strip()
    if not TARGET_RE.fullmatch(host) or '\n' in host or '\r' in host:
        raise ValueError('Invalid SPICE destination')
    proxy = values.get('proxy', '').strip()
    if host.startswith('pvespiceproxy:') and not proxy:
        raise ValueError('Proxmox token destinations require the .vv HTTP proxy')
    if proxy:
        proxy_endpoint(proxy)  # Validate before storing the private ticket.
    tls_port = values.get('tls-port', '').strip()
    plain_port = values.get('port', '').strip()
    tls = bool(tls_port)
    selected = tls_port if tls else plain_port
    if not selected.isascii() or not selected.isdecimal():
        raise ValueError('Virt-viewer needs a numeric port or tls-port')
    port = int(selected)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid SPICE port')
    ca = values.get('ca','').replace('\\n','\n')
    if ca and (not tls or len(ca) > 12000 or '-----BEGIN CERTIFICATE-----' not in ca):
        raise ValueError('SPICE CA must be a PEM certificate for TLS')
    # Host subjects in Proxmox .vv files provide the actual TLS server name,
    # unlike the pvespiceproxy:<ticket> virtual endpoint inside CONNECT.
    match = re.search(r'(?:^|,)CN=([^,]+)', values.get('host-subject',''))
    server_name = match.group(1).strip() if match else ''
    if server_name and not DNS_RE.fullmatch(server_name):
        raise ValueError('Invalid TLS server name')
    if tls and host.startswith('pvespiceproxy:') and not server_name:
        raise ValueError('TLS Proxmox token requires host-subject CN verification')
    password = values.get('password','')
    if len(password) > 4096:
        raise ValueError('SPICE credential too long')
    label = values.get('title','SPICE one-time console').strip()
    label = ''.join(ch for ch in label if ch.isprintable())[:120] or 'SPICE one-time console'
    settings = DesktopSettings(protocol='spice',host=host,port=port,password=password,
                               spice_tls=tls,spice_proxy=proxy,spice_ca_pem=ca,
                               spice_server_name=server_name)
    return label, settings


def proxy_endpoint(proxy: str) -> tuple[str, int]:
    candidate = proxy if '://' in proxy else f'http://{proxy}'
    try:
        url = urlsplit(candidate)
        port = url.port or 3128
    except ValueError as exc:
        raise ValueError('Invalid SPICE proxy address') from exc
    if (url.scheme != 'http' or not url.hostname or not DNS_RE.fullmatch(url.hostname)
            or url.username or url.password or url.path not in ('', '/')
            or url.query or url.fragment or not 1 <= port <= 65535):
        raise ValueError('SPICE proxy must be an HTTP CONNECT host without credentials')
    return url.hostname, port


async def connect_spice(settings: DesktopSettings, connector: Callable | None = None):
    """Open raw SPICE TCP, verified TLS, or HTTP CONNECT followed by TLS."""
    ssl_context = None
    if settings.spice_tls:
        ssl_context = ssl.create_default_context()
        if settings.spice_ca_pem:
            ssl_context.load_verify_locations(cadata=settings.spice_ca_pem)
        if settings.ignore_cert:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
    open_connection = connector or asyncio.open_connection
    server_name = settings.spice_server_name or settings.host
    if not settings.spice_proxy:
        return await asyncio.wait_for(open_connection(
            settings.host, settings.port, ssl=ssl_context,
            server_hostname=server_name if ssl_context else None,
        ), timeout=CONNECT_TIMEOUT)

    proxy_host, proxy_port = proxy_endpoint(settings.spice_proxy)
    if not TARGET_RE.fullmatch(settings.host):
        raise ValueError('Invalid proxy CONNECT target')
    reader, writer = await asyncio.wait_for(open_connection(
        proxy_host, proxy_port, ssl=None, server_hostname=None), timeout=CONNECT_TIMEOUT)
    try:
        target = f'{settings.host}:{settings.port}'
        writer.write(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode('ascii'))
        await asyncio.wait_for(writer.drain(), timeout=CONNECT_TIMEOUT)
        header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=CONNECT_TIMEOUT)
        if len(header) > 4096 or not re.match(rb'^HTTP/1\.[01] 200(?: |\r\n)', header):
            raise ConnectionError('SPICE proxy refused HTTP CONNECT')
        if ssl_context:
            await asyncio.wait_for(writer.start_tls(ssl_context,
                  server_hostname=server_name, ssl_handshake_timeout=CONNECT_TIMEOUT), timeout=CONNECT_TIMEOUT)
        return reader, writer
    except BaseException:
        writer.close()
        raise


async def relay_spice(ws: WebSocket, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter):
    """Tunnel binary SPICE channel frames with bounds and idle timeout."""
    last_activity = asyncio.get_running_loop().time()

    async def from_server():
        nonlocal last_activity
        while True:
            data = await reader.read(65536)
            if not data:
                return
            last_activity = asyncio.get_running_loop().time()
            await ws.send_bytes(data)

    async def from_browser():
        nonlocal last_activity
        while True:
            msg = await ws.receive()
            if msg['type'] == 'websocket.disconnect':
                return
            if msg['type'] != 'websocket.receive' or msg.get('bytes') is None:
                raise ValueError('SPICE requires binary WebSocket frames')
            data = msg['bytes']
            if len(data) > MAX_FRAME:
                raise ValueError('SPICE frame exceeds limit')
            last_activity = asyncio.get_running_loop().time()
            writer.write(data)
            await asyncio.wait_for(writer.drain(), timeout=CONNECT_TIMEOUT)

    async def idle_guard():
        while True:
            await asyncio.sleep(15)
            if asyncio.get_running_loop().time() - last_activity > IDLE_TIMEOUT:
                raise TimeoutError('SPICE channel idle timeout')

    tasks = [asyncio.create_task(fn()) for fn in (from_server, from_browser, idle_guard)]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
