
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


"""Tests for relay/server.py — auth verification and request routing."""

import asyncio
import base64
import hashlib
import json
import socket
import time

import nacl.signing
import pytest
import websockets.asyncio.client

from relay.server import (
    RelayServer,
    _canonical,
    sign_request,
    verify_auth_async,
)
from relay.storage import Database

NOW = int(time.time())


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_key() -> tuple[bytes, bytes]:
    """Return (public_key, private_key) bytes."""
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk.verify_key), bytes(sk)


ALICE_PK, ALICE_SK = make_key()
BOB_PK, BOB_SK = make_key()


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        await database.add_sender(ALICE_PK.hex(), "Alice", NOW)
        yield database


# ------------------------------------------------------------------
# _canonical
# ------------------------------------------------------------------

def test_canonical_excludes_auth():
    req = {"v": 1, "type": "relay_send", "auth": "secret", "message_id": "abc"}
    data = _canonical(req)
    parsed = json.loads(data)
    assert "auth" not in parsed
    assert parsed["message_id"] == "abc"


def test_canonical_is_sorted():
    req = {"z": 1, "a": 2, "m": 3}
    data = _canonical(req)
    assert data == b'{"a":2,"m":3,"z":1}'


# ------------------------------------------------------------------
# sign_request / verify_auth_async
# ------------------------------------------------------------------

async def test_verify_auth_valid(db):
    req = {"v": 1, "type": "relay_send", "sender_key": ALICE_PK.hex(), "message_id": "abc"}
    req["auth"] = sign_request(req, ALICE_SK)
    assert await verify_auth_async(req, db) is True


async def test_verify_auth_unauthorized_sender(db):
    eve_pk, eve_sk = make_key()
    req = {"v": 1, "type": "relay_send", "sender_key": eve_pk.hex(), "message_id": "abc"}
    req["auth"] = sign_request(req, eve_sk)
    assert await verify_auth_async(req, db) is False


async def test_verify_auth_bad_signature(db):
    req = {"v": 1, "type": "relay_send", "sender_key": ALICE_PK.hex(), "message_id": "abc"}
    req["auth"] = base64.b64encode(b"\x00" * 64).decode()
    assert await verify_auth_async(req, db) is False


async def test_verify_auth_tampered_field(db):
    req = {"v": 1, "type": "relay_send", "sender_key": ALICE_PK.hex(), "message_id": "abc"}
    req["auth"] = sign_request(req, ALICE_SK)
    req["message_id"] = "tampered"
    assert await verify_auth_async(req, db) is False


async def test_verify_auth_missing_sender_key(db):
    req = {"v": 1, "type": "relay_send", "auth": "x"}
    assert await verify_auth_async(req, db) is False


# ------------------------------------------------------------------
# RelayServer integration
# ------------------------------------------------------------------

async def test_server_start_stop(db):
    srv = RelayServer(port=free_port())
    await srv.start(db, send_handler=None)
    assert srv.is_running
    await srv.stop()
    assert not srv.is_running


async def test_server_stop_before_start_safe(db):
    srv = RelayServer(port=free_port())
    await srv.stop()


def _make_relay_send(payload: bytes = b"msg") -> dict:
    msg_id = hashlib.sha256(payload).hexdigest()
    req = {
        "v": 1,
        "type": "relay_send",
        "sender_key": ALICE_PK.hex(),
        "destination_key": BOB_PK.hex(),
        "destination_onion": "bob.onion",
        "payload": base64.b64encode(payload).decode(),
        "message_id": msg_id,
        "ttl": 604800,
    }
    req["auth"] = sign_request(req, ALICE_SK)
    return req


async def test_relay_send_calls_handler(db):
    port = free_port()
    received = []

    async def handler(msg_id, sender_key, for_key, onion, payload, expires_at):
        received.append((msg_id, onion))

    srv = RelayServer(port=port)
    await srv.start(db, send_handler=handler)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send(json.dumps(_make_relay_send()))
            await asyncio.sleep(0.05)
    finally:
        await srv.stop()

    assert len(received) == 1
    assert received[0][1] == "bob.onion"


async def test_relay_send_unauthorized_ignored(db):
    port = free_port()
    received = []

    async def handler(*args):
        received.append(args)

    # Eve is not authorized
    eve_pk, eve_sk = make_key()
    req = _make_relay_send()
    req["sender_key"] = eve_pk.hex()
    req["auth"] = sign_request(req, eve_sk)

    srv = RelayServer(port=port)
    await srv.start(db, send_handler=handler)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send(json.dumps(req))
            await asyncio.sleep(0.05)
    finally:
        await srv.stop()

    assert received == []


async def test_relay_send_bad_signature_ignored(db):
    port = free_port()
    received = []

    async def handler(*args):
        received.append(args)

    req = _make_relay_send()
    req["auth"] = base64.b64encode(b"\xff" * 64).decode()

    srv = RelayServer(port=port)
    await srv.start(db, send_handler=handler)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send(json.dumps(req))
            await asyncio.sleep(0.05)
    finally:
        await srv.stop()

    assert received == []


async def test_relay_status_response(db):
    port = free_port()

    # Pre-store a message
    async with Database.open(":memory:") as db2:
        await db2.add_sender(ALICE_PK.hex(), "Alice", NOW)
        await db2.save_message(
            id="msg123", sender_key=ALICE_PK.hex(), for_key=BOB_PK.hex(),
            destination_onion="bob.onion", payload=b"x",
            received_at=NOW, expires_at=NOW + 86400, next_retry_at=NOW,
        )

        req = {
            "v": 1,
            "type": "relay_status",
            "sender_key": ALICE_PK.hex(),
            "message_id": "msg123",
        }
        req["auth"] = sign_request(req, ALICE_SK)

        srv = RelayServer(port=port)
        await srv.start(db2, send_handler=None)

        try:
            async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
                await ws.send(json.dumps(req))
                raw = await asyncio.wait_for(ws.recv(), timeout=2)
                response = json.loads(raw)
        finally:
            await srv.stop()

    assert response["type"] == "relay_status_response"
    assert response["message_id"] == "msg123"
    assert response["status"] == "queued"


async def test_relay_status_unknown_message(db):
    port = free_port()
    req = {
        "v": 1,
        "type": "relay_status",
        "sender_key": ALICE_PK.hex(),
        "message_id": "nonexistent",
    }
    req["auth"] = sign_request(req, ALICE_SK)

    srv = RelayServer(port=port)
    await srv.start(db, send_handler=None)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send(json.dumps(req))
            raw = await asyncio.wait_for(ws.recv(), timeout=2)
            response = json.loads(raw)
    finally:
        await srv.stop()

    assert response["status"] == "unknown"


async def test_invalid_json_ignored(db):
    port = free_port()
    received = []

    srv = RelayServer(port=port)
    await srv.start(db, send_handler=lambda *a: received.append(a))

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send("not json {{{")
            await asyncio.sleep(0.05)
    finally:
        await srv.stop()

    assert received == []
