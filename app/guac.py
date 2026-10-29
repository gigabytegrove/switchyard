"""Bounded Apache Guacamole protocol framing and guacd handshake.

The gateway generates the handshake itself, never accepting arbitrary guacd
connection parameters from browser sockets. The browser receives only the
interactive drawing/input stream after a verified server-side connect.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

MAX_ELEMENT = 65536
MAX_ARGUMENTS = 160
VERSION = re.compile(r'^VERSION_[0-9]+_[0-9]+_[0-9]+$')

class ProtocolError(Exception):
    pass


def frame(*elements: str) -> bytes:
    if not elements or len(elements) > MAX_ARGUMENTS:
        raise ProtocolError('Invalid argument count')
    encoded = []
    for value in elements:
        if not isinstance(value, str):
            raise ProtocolError('Expected string element')
        raw = value.encode('utf-8')
        if len(value) > MAX_ELEMENT:
            raise ProtocolError('Oversized protocol element')
        # Guacamole length prefixes count Unicode code points, not UTF-8 bytes.
        encoded.append(str(len(value)).encode('ascii') + b'.' + raw)
    return b','.join(encoded) + b';'


async def read_frame(reader: asyncio.StreamReader) -> list[str]:
    values = []
    while len(values) < MAX_ARGUMENTS:
        digits = bytearray()
        while True:
            byte = await reader.readexactly(1)
            if byte == b'.':
                break
            if not (b'0' <= byte <= b'9') or len(digits) >= 7:
                raise ProtocolError('Invalid protocol length')
            digits.extend(byte)
        if not digits:
            raise ProtocolError('Missing protocol length')
        size = int(digits)
        if size > MAX_ELEMENT:
            raise ProtocolError('Protocol element too large')
        raw = bytearray()
        for _ in range(size):
            first = (await reader.readexactly(1))[0]
            if first < 0x80:
                width = 1
            elif 0xC2 <= first <= 0xDF:
                width = 2
            elif 0xE0 <= first <= 0xEF:
                width = 3
            elif 0xF0 <= first <= 0xF4:
                width = 4
            else:
                raise ProtocolError('Invalid UTF-8 codepoint')
            raw.append(first)
            if width > 1:
                raw.extend(await reader.readexactly(width - 1))
        try:
            values.append(raw.decode('utf-8'))
        except UnicodeDecodeError as exc:
            raise ProtocolError('Invalid UTF-8') from exc
        separator = await reader.readexactly(1)
        if separator == b';':
            return values
        if separator != b',':
            raise ProtocolError('Invalid protocol separator')
    raise ProtocolError('Too many protocol arguments')


@dataclass(frozen=True)
class DesktopSettings:
    protocol: str
    host: str
    port: int
    username: str = ''
    password: str = ''
    domain: str = ''
    security: str = 'nla'
    ignore_cert: bool = False
    spice_tls: bool = False
    spice_proxy: str = ''
    spice_ca_pem: str = ''
    spice_server_name: str = ''
    read_only: bool = False
    width: int = 1366
    height: int = 768
    dpi: int = 96


def connection_options(settings: DesktopSettings) -> dict[str, str]:
    if settings.protocol not in ('rdp', 'vnc'):
        raise ProtocolError('Unsupported protocol')
    result = {
        'hostname': settings.host,
        'port': str(settings.port),
        'username': settings.username,
        'password': settings.password,
        'read-only': 'true' if settings.read_only else 'false',
    }
    if settings.protocol == 'rdp':
        result.update({
            'domain': settings.domain,
            'security': settings.security,
            'ignore-cert': 'true' if settings.ignore_cert else 'false',
            'enable-wallpaper': 'false',
            'enable-printing': 'false',
            'enable-drive': 'false',
            'enable-sftp': 'false',
            'resize-method': 'display-update',
        })
    return result


async def handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                    settings: DesktopSettings) -> list[str]:
    """Sends select and connect; returns initial guacd ready/status instruction.

    The caller forwards the returned instruction to the browser and then
    bidirectionally pipes subsequent interactive protocol bytes.
    """
    writer.write(frame('select', settings.protocol))
    await writer.drain()
    args = await asyncio.wait_for(read_frame(reader), timeout=12)
    if not args or args[0] != 'args':
        raise ProtocolError('guacd did not negotiate supported parameters')
    accepted = args[1:]
    negotiated_version = ''
    if accepted and VERSION.fullmatch(accepted[0]):
        # guacd's protocol version is itself the first expected argument for
        # connect. Omitting it leads to a rejected RDP/VNC handshake.
        offered = accepted.pop(0)
        negotiated_version = 'VERSION_1_1_0' if offered >= 'VERSION_1_1_0' else 'VERSION_1_0_0'
    if len(accepted) > 120 or len(set(accepted)) != len(accepted):
        raise ProtocolError('Invalid guacd argument list')
    options = connection_options(settings)
    if not {'hostname', 'port'}.issubset(accepted):
        raise ProtocolError('Required guacd connection fields missing')
    writer.write(frame('size', str(settings.width), str(settings.height), str(settings.dpi)))
    writer.write(frame('audio'))
    writer.write(frame('video'))
    writer.write(frame('image', 'image/png', 'image/jpeg'))
    writer.write(frame('connect', *([negotiated_version] if negotiated_version else []),
                       *(options.get(name, '') for name in accepted)))
    await writer.drain()
    outcome = await asyncio.wait_for(read_frame(reader), timeout=20)
    if not outcome or outcome[0] != 'ready':
        raise ProtocolError('guacd rejected connection')
    return outcome
