
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
Logika dostarczania wiadomości przez relay.

Relay dostarcza wiadomość do odbiorcy przez Tor SOCKS5 + WebSocket.
Payload to oryginalny blob JSON wiadomości Legion — relay przesyła go
bez modyfikacji, nie znając treści.

Harmonogram retry: [60, 300, 900, 3600, 21600, 86400] sekund.
Po wyczerpaniu harmonogramu status = 'failed', wpis zostaje do TTL.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket as _socket
import time
from typing import Final

import websockets.asyncio.client

from relay.storage import Database

logger = logging.getLogger(__name__)

RETRY_SCHEDULE: Final = [60, 300, 900, 3600, 21600, 86400]

_LOOP_INTERVAL = 30     # seconds between delivery sweeps
_CONNECT_TIMEOUT = 60   # onion connections can be slow
_SEND_TIMEOUT = 30
_SOCKS5_VERSION: Final = 5
_SOCKS5_CMD_CONNECT: Final = 1
_SOCKS5_ATYP_DOMAIN: Final = 3
_SOCKS5_AUTH_NONE: Final = 0


class DeliveryQueue:
    """Background delivery queue for relay — forwards opaque payload blobs."""

    def __init__(
        self,
        db: Database,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        hs_port: int = 80,
    ) -> None:
        self._db = db
        self._socks_host = socks_host
        self._socks_port = socks_port
        self._hs_port = hs_port
        self._task: asyncio.Task | None = None
        self._running = False

    async def enqueue(
        self,
        message_id: str,
        sender_key: str,
        for_key: str,
        destination_onion: str,
        payload: bytes,
        expires_at: int,
    ) -> None:
        """Store a message and schedule immediate delivery attempt."""
        await self._db.save_message(
            id=message_id,
            sender_key=sender_key,
            for_key=for_key,
            destination_onion=destination_onion,
            payload=payload,
            received_at=int(time.time()),
            expires_at=expires_at,
            next_retry_at=int(time.time()),
        )

    async def process_due(self, now: int | None = None) -> tuple[int, int]:
        """Attempt delivery of all due messages. Returns (delivered, failed)."""
        if now is None:
            now = int(time.time())

        due = await self._db.get_due(now)
        delivered = failed = 0

        for entry in due:
            if await self._try_deliver(entry, now):
                delivered += 1
            else:
                failed += 1

        return delivered, failed

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                delivered, failed = await self.process_due()
                if delivered or failed:
                    logger.debug("Relay sweep: delivered=%d failed=%d", delivered, failed)
            except Exception:
                logger.exception("Unexpected error in relay delivery loop")
            await asyncio.sleep(_LOOP_INTERVAL)

    async def _try_deliver(self, entry: dict, now: int) -> bool:
        try:
            await asyncio.wait_for(
                self._send_payload(
                    entry["destination_onion"],
                    entry["payload"],
                ),
                timeout=_CONNECT_TIMEOUT + _SEND_TIMEOUT,
            )
            await self._db.update_status(entry["id"], "delivered")
            return True
        except Exception:
            retry_count = entry["retry_count"]
            if retry_count < len(RETRY_SCHEDULE):
                await self._db.update_retry(entry["id"], now + RETRY_SCHEDULE[retry_count])
            else:
                await self._db.update_status(entry["id"], "failed")
            return False

    async def _send_payload(self, destination_onion: str, payload: bytes) -> None:
        """Connect via Tor SOCKS5 and send payload over WebSocket."""
        loop = asyncio.get_event_loop()
        sock = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: _socks5_connect(
                    destination_onion,
                    self._hs_port,
                    self._socks_host,
                    self._socks_port,
                ),
            ),
            timeout=_CONNECT_TIMEOUT,
        )
        uri = f"ws://{destination_onion}:{self._hs_port}"
        async with asyncio.timeout(_SEND_TIMEOUT):
            async with websockets.asyncio.client.connect(uri, sock=sock) as ws:
                await ws.send(payload)


# ------------------------------------------------------------------
# SOCKS5 — blocking, run in executor
# ------------------------------------------------------------------

def _socks5_connect(
    host: str, port: int, proxy_host: str, proxy_port: int
) -> _socket.socket:
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
    sock.sendall(bytes([_SOCKS5_VERSION, 1, _SOCKS5_AUTH_NONE]))
    resp = _recv_exact(sock, 2)
    if resp[0] != _SOCKS5_VERSION or resp[1] != _SOCKS5_AUTH_NONE:
        raise OSError(f"SOCKS5 auth rejected: {resp!r}")

    host_b = host.encode("ascii")
    request = (
        bytes([_SOCKS5_VERSION, _SOCKS5_CMD_CONNECT, 0, _SOCKS5_ATYP_DOMAIN, len(host_b)])
        + host_b
        + port.to_bytes(2, "big")
    )
    sock.sendall(request)

    resp = _recv_exact(sock, 4)
    if resp[1] != 0x00:
        raise OSError(f"SOCKS5 connect refused (code {resp[1]})")

    atyp = resp[3]
    if atyp == 0x01:
        _recv_exact(sock, 6)
    elif atyp == 0x03:
        n = _recv_exact(sock, 1)[0]
        _recv_exact(sock, n + 2)
    elif atyp == 0x04:
        _recv_exact(sock, 18)


def _recv_exact(sock: _socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS5 connection closed unexpectedly")
        buf += chunk
    return buf
