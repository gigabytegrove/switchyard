"""Bounded outbound protocol socket checks. No credentials or payloads sent."""
from __future__ import annotations

import asyncio
import ssl
import time


async def probe(host: str, port: int, validate_tls: bool = False) -> dict:
    started = time.monotonic()
    context = ssl.create_default_context() if validate_tls else None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=context,
            server_hostname=host if context else None), timeout=4.0)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return {'reachable': False, 'tls_validated': False,
                'elapsed_ms': int((time.monotonic()-started)*1000),
                'message': 'Remote TCP/TLS connection could not be established'}
    try:
        return {'reachable': True, 'tls_validated': bool(context),
                'elapsed_ms': int((time.monotonic()-started)*1000),
                'message': 'TCP port reachable' + ('; TLS certificate verified' if context else '; authentication not tested')}
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except (OSError, asyncio.TimeoutError):
            pass
