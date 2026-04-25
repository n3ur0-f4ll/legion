
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
Serwer WebSocket relay.

Przyjmuje zlecenia relay_send i relay_status od autoryzowanych właścicieli.
Każde połączenie obsługuje jedno żądanie.

Protokół żądania relay_send:
{
    "v": 1,
    "type": "relay_send",
    "sender_key": "<hex klucz publiczny właściciela>",
    "auth": "<base64 podpis Ed25519 nad canonical JSON bez pola auth>",
    "destination_key": "<hex klucz publiczny odbiorcy>",
    "destination_onion": "<adres.onion odbiorcy>",
    "payload": "<base64 oryginalnej wiadomości protokołu Legion>",
    "message_id": "<SHA256 payload>",
    "ttl": 604800
}

Protokół żądania relay_status:
{
    "v": 1,
    "type": "relay_status",
    "sender_key": "<hex>",
    "auth": "<base64 podpis>",
    "message_id": "<SHA256>"
}

Nieprawidłowy podpis lub nieautoryzowany nadawca: zamknięcie połączenia
natychmiast i cicho — bez odpowiedzi, bez logowania treści.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from typing import Awaitable, Callable

import nacl.exceptions
import nacl.signing
import websockets.asyncio.server

from relay.storage import Database

logger = logging.getLogger(__name__)

_RECV_TIMEOUT = 30
_MAX_MESSAGE_BYTES = 512 * 1024  # 512 KB

# Called by server when a valid relay_send arrives.
# Signature: (message_id, sender_key, for_key, destination_onion, payload, expires_at) -> None
SendHandler = Callable[
    [str, str, str, str, bytes, int], Awaitable[None]
]


class RelayServer:
    """WebSocket server accepting relay requests from authorized senders."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765) -> None:
        self._host = host
        self._port = port
        self._db: Database | None = None
        self._send_handler: SendHandler | None = None
        self._server = None
        self._server_cm = None

    @property
    def is_running(self) -> bool:
        return self._server is not None

    async def start(self, db: Database, send_handler: SendHandler) -> None:
        self._db = db
        self._send_handler = send_handler
        self._server_cm = websockets.asyncio.server.serve(
            self._handle,
            self._host,
            self._port,
            max_size=_MAX_MESSAGE_BYTES,
        )
        self._server = await self._server_cm.__aenter__()
        logger.info("Relay server listening on %s:%d", self._host, self._port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self._server_cm = None

    async def _handle(self, websocket) -> None:
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=_RECV_TIMEOUT)
        except Exception:
            return

        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            return  # silent drop

        if not isinstance(req, dict) or req.get("v") != 1:
            return

        req_type = req.get("type")

        if req_type == "relay_send":
            await self._handle_send(websocket, req)
        elif req_type == "relay_status":
            await self._handle_status(websocket, req)
        # unknown type: silent drop

    async def _handle_send(self, websocket, req: dict) -> None:
        if not await verify_auth_async(req, self._db):
            return  # silent drop

        # Validate required fields
        try:
            message_id = req["message_id"]
            sender_key = req["sender_key"]
            for_key = req["destination_key"]
            destination_onion = req["destination_onion"]
            payload = base64.b64decode(req["payload"])
            ttl = int(req["ttl"])
        except (KeyError, ValueError):
            return

        # Verify message_id matches payload
        if hashlib.sha256(payload).hexdigest() != message_id:
            return

        now = int(time.time())
        expires_at = now + min(ttl, 30 * 86400)  # cap at MAX_TTL_DAYS

        await self._send_handler(
            message_id, sender_key, for_key, destination_onion, payload, expires_at
        )

    async def _handle_status(self, websocket, req: dict) -> None:
        if not await verify_auth_async(req, self._db):
            return  # silent drop

        try:
            message_id = req["message_id"]
        except KeyError:
            return

        row = await self._db.get_message(message_id)
        if row is None:
            response = {
                "v": 1,
                "type": "relay_status_response",
                "message_id": message_id,
                "status": "unknown",
            }
        else:
            response = {
                "v": 1,
                "type": "relay_status_response",
                "message_id": message_id,
                "status": row["status"],
                "retry_count": row["retry_count"],
                "next_retry_at": row["next_retry_at"],
                "expires_at": row["expires_at"],
            }

        try:
            await websocket.send(json.dumps(response))
        except Exception:
            pass


# ------------------------------------------------------------------
# Auth verification (sync — called from async context)
# ------------------------------------------------------------------

def _verify_auth(req: dict, db: Database) -> bool:
    """Verify Ed25519 signature and authorization. Returns False on any failure."""
    try:
        sender_key_hex = req["sender_key"]
        auth_b64 = req["auth"]
        sender_pubkey = bytes.fromhex(sender_key_hex)
        signature = base64.b64decode(auth_b64)
    except (KeyError, ValueError):
        return False

    # Build signed data: canonical JSON without "auth" field
    signed_data = _canonical(req)

    try:
        nacl.signing.VerifyKey(sender_pubkey).verify(signed_data, signature)
    except nacl.exceptions.BadSignatureError:
        return False
    except Exception:
        return False

    # Check authorization (sync wrapper — DB is always open)
    # We run this synchronously because the DB is always in-process.
    # Using asyncio.get_event_loop().run_until_complete() is not safe here;
    # caller must use _verify_auth_async instead for async contexts.
    return True  # signature OK — caller must check DB separately


async def verify_auth_async(req: dict, db: Database) -> bool:
    """Async version: verify signature AND check authorized_senders table."""
    try:
        sender_key_hex = req["sender_key"]
        auth_b64 = req["auth"]
        sender_pubkey = bytes.fromhex(sender_key_hex)
        signature = base64.b64decode(auth_b64)
    except (KeyError, ValueError):
        return False

    signed_data = _canonical(req)

    try:
        nacl.signing.VerifyKey(sender_pubkey).verify(signed_data, signature)
    except Exception:
        return False

    return await db.is_authorized(sender_key_hex)


def _canonical(req: dict) -> bytes:
    """Canonical JSON of request without the 'auth' field."""
    without_auth = {k: v for k, v in req.items() if k != "auth"}
    return json.dumps(without_auth, sort_keys=True, separators=(",", ":")).encode()


def sign_request(req: dict, private_key: bytes) -> str:
    """Sign a request dict and return base64-encoded signature.

    Used by legion-node when building relay_send / relay_status requests.
    Exported here so both sides use the same canonical format.
    """
    import nacl.signing as _signing
    data = _canonical(req)
    sk = _signing.SigningKey(private_key)
    return base64.b64encode(sk.sign(data).signature).decode()
