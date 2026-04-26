
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
Serwer WebSocket węzła Legion.

Nasłuchuje wyłącznie na 127.0.0.1 — Tor Hidden Service przekierowuje połączenia
przychodzące z sieci na ten lokalny port. Każde połączenie dostarcza jedną
wiadomość. Wiadomości z błędami protokołu są odrzucane cicho bez żadnej odpowiedzi.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

import websockets.asyncio.server

from core.protocol import ProtocolError, parse_message, validate_message

logger = logging.getLogger(__name__)

MessageHandler = Callable[[dict], Awaitable[None]]

_RECV_TIMEOUT = 30  # seconds to wait for a message before closing idle connection
_MAX_MSG_BYTES = 12 * 1024 * 1024  # 12 MB — covers 5 MB file after base64+encrypt overhead


class NodeServer:
    """WebSocket server accepting one message per connection from other nodes.

    Invalid messages are dropped silently — no response, no error log containing
    message contents. Handler exceptions are caught and logged without details.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        self._host = host
        self._port = port
        self._server: websockets.asyncio.server.Server | None = None
        self._server_cm: websockets.asyncio.server.serve | None = None

    @property
    def is_running(self) -> bool:
        return self._server is not None

    async def start(self, handler: MessageHandler) -> None:
        """Start listening. handler is awaited for each valid received message."""
        self._server_cm = websockets.asyncio.server.serve(
            lambda ws: self._handle(ws, handler),
            self._host,
            self._port,
            max_size=_MAX_MSG_BYTES,
        )
        self._server = await self._server_cm.__aenter__()
        logger.info("Node server listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        """Stop accepting connections and wait for active handlers to finish."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self._server_cm = None

    async def _handle(self, websocket, handler: MessageHandler) -> None:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=_RECV_TIMEOUT)
        except Exception:
            return

        try:
            msg = parse_message(raw)
            validate_message(msg)
        except ProtocolError:
            return  # silent drop — no response, contents never logged

        try:
            await handler(msg)
        except Exception:
            logger.exception("Handler raised for message type=%r", msg.get("type"))
