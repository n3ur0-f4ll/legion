
# Legion — decentralized, anonymous communication platform
# Copyright (C) 2026  n3ur0-f4ll
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


"""
Klient WebSocket do łączenia się z innymi węzłami Legion przez Tora.

Każde wywołanie send_message otwiera nowe połączenie, wysyła jedną wiadomość
i zamyka połączenie. Połączenie nawiązywane jest przez Tor SOCKS5 (domyślnie
127.0.0.1:9050), więc adres .onion jest rozwiązywany przez Tora.

Moduł nie loguje treści wiadomości ani adresów docelowych.
"""

from __future__ import annotations

import asyncio
import json
import socket as _socket
from typing import Final

import websockets.asyncio.client

_SOCKS5_VERSION: Final = 5
_SOCKS5_CMD_CONNECT: Final = 1
_SOCKS5_ATYP_DOMAIN: Final = 3
_SOCKS5_AUTH_NONE: Final = 0

_CONNECT_TIMEOUT = 60   # seconds — onion connections can be slow
_SEND_TIMEOUT = 30      # seconds to complete send after connection


class NodeClientError(Exception):
    """Raised when sending a message to another node fails."""


async def send_message(
    msg: dict,
    onion_address: str,
    *,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
    hs_port: int = 80,
) -> None:
    """Send one message to a remote Legion node through Tor.

    msg: validated protocol message dict (already signed).
    onion_address: full '<id>.onion' address of the destination node.
    Raises NodeClientError on any connection or send failure.
    """
    loop = asyncio.get_event_loop()

    try:
        sock = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _socks5_connect(onion_address, hs_port, socks_host, socks_port),
            ),
            timeout=_CONNECT_TIMEOUT,
        )
    except asyncio.TimeoutError as exc:
        raise NodeClientError("Connection timed out") from exc
    except OSError as exc:
        raise NodeClientError(f"Connection failed: {exc}") from exc

    uri = f"ws://{onion_address}:{hs_port}"
    try:
        async with asyncio.timeout(_SEND_TIMEOUT):
            async with websockets.asyncio.client.connect(
                uri, sock=sock, max_size=12 * 1024 * 1024
            ) as ws:
                await ws.send(json.dumps(msg))
    except TimeoutError as exc:
        raise NodeClientError("Send timed out") from exc
    except Exception as exc:
        raise NodeClientError(f"Send failed: {exc}") from exc


# ------------------------------------------------------------------
# SOCKS5 — blocking, run in executor
# ------------------------------------------------------------------

def _socks5_connect(
    host: str, port: int, proxy_host: str, proxy_port: int
) -> _socket.socket:
    """Return a non-blocking socket tunnelled through SOCKS5 to host:port."""
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((proxy_host, proxy_port))
        _socks5_handshake(sock, host, port)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def _socks5_handshake(sock: _socket.socket, host: str, port: int) -> None:
    # Greeting: no-auth
    sock.sendall(bytes([_SOCKS5_VERSION, 1, _SOCKS5_AUTH_NONE]))
    resp = _recv_exact(sock, 2)
    if resp[0] != _SOCKS5_VERSION or resp[1] != _SOCKS5_AUTH_NONE:
        raise OSError(f"SOCKS5 auth rejected: {resp!r}")

    # CONNECT request (ATYP=domain)
    host_b = host.encode("ascii")
    if len(host_b) > 255:
        raise ValueError(f"Hostname too long: {host!r}")
    request = (
        bytes([_SOCKS5_VERSION, _SOCKS5_CMD_CONNECT, 0, _SOCKS5_ATYP_DOMAIN, len(host_b)])
        + host_b
        + port.to_bytes(2, "big")
    )
    sock.sendall(request)

    # Response header: VER REP RSV ATYP
    resp = _recv_exact(sock, 4)
    if resp[1] != 0x00:
        raise OSError(f"SOCKS5 connect refused (code {resp[1]})")

    # Discard bound address
    atyp = resp[3]
    if atyp == 0x01:       # IPv4
        _recv_exact(sock, 4 + 2)
    elif atyp == 0x03:     # domain
        n = _recv_exact(sock, 1)[0]
        _recv_exact(sock, n + 2)
    elif atyp == 0x04:     # IPv6
        _recv_exact(sock, 16 + 2)


def _recv_exact(sock: _socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS5 connection closed unexpectedly")
        buf += chunk
    return buf
