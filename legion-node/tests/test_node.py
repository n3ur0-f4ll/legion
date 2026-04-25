
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


"""Tests for network/node.py."""

import asyncio
import json
import socket
import time

import pytest
import websockets.asyncio.client

from core.identity import generate as gen
from core.protocol import MSG_PRIVATE, build_message
from network.node import NodeServer


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def valid_raw_message() -> str:
    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"payload", alice.private_key)
    return json.dumps(msg)


# ------------------------------------------------------------------
# _handle — unit tests with mock WebSocket
# ------------------------------------------------------------------

class _MockWS:
    def __init__(self, message=None, recv_raises=None):
        self._message = message
        self._recv_raises = recv_raises

    async def recv(self):
        if self._recv_raises:
            raise self._recv_raises
        return self._message


async def test_handle_valid_message_calls_handler():
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer()
    await server._handle(_MockWS(valid_raw_message()), handler)
    assert len(received) == 1
    assert received[0]["type"] == MSG_PRIVATE


async def test_handle_invalid_json_does_not_call_handler():
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer()
    await server._handle(_MockWS("not json {{"), handler)
    assert received == []


async def test_handle_missing_fields_does_not_call_handler():
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer()
    await server._handle(_MockWS('{"v": 1}'), handler)
    assert received == []


async def test_handle_tampered_signature_does_not_call_handler():
    import base64

    received = []

    async def handler(msg):
        received.append(msg)

    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"x", alice.private_key)
    sig = bytearray(base64.b64decode(msg["signature"]))
    sig[0] ^= 0xFF
    msg["signature"] = base64.b64encode(bytes(sig)).decode()

    server = NodeServer()
    await server._handle(_MockWS(json.dumps(msg)), handler)
    assert received == []


async def test_handle_expired_message_does_not_call_handler():
    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"x", alice.private_key)
    msg["timestamp"] = int(time.time()) - msg["ttl"] - 1

    server = NodeServer()
    received = []
    await server._handle(_MockWS(json.dumps(msg)), lambda m: received.append(m))
    assert received == []


async def test_handle_recv_exception_does_not_call_handler():
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer()
    await server._handle(_MockWS(recv_raises=ConnectionError("gone")), handler)
    assert received == []


async def test_handle_handler_exception_does_not_propagate():
    async def bad_handler(msg):
        raise RuntimeError("handler bug")

    server = NodeServer()
    # Must not raise
    await server._handle(_MockWS(valid_raw_message()), bad_handler)


# ------------------------------------------------------------------
# NodeServer lifecycle — integration tests with real server
# ------------------------------------------------------------------

async def test_is_running_before_start():
    server = NodeServer(port=free_port())
    assert not server.is_running


async def test_is_running_after_start_and_stop():
    port = free_port()
    server = NodeServer(port=port)

    async def noop(msg):
        pass

    await server.start(noop)
    assert server.is_running

    await server.stop()
    assert not server.is_running


async def test_stop_before_start_is_safe():
    server = NodeServer(port=free_port())
    await server.stop()  # must not raise


async def test_server_receives_valid_message():
    port = free_port()
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer(port=port)
    await server.start(handler)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send(valid_raw_message())
            await asyncio.sleep(0.05)  # let handler run
    finally:
        await server.stop()

    assert len(received) == 1
    assert received[0]["type"] == MSG_PRIVATE


async def test_server_ignores_invalid_message():
    port = free_port()
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer(port=port)
    await server.start(handler)

    try:
        async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
            await ws.send("not a valid message")
            await asyncio.sleep(0.05)
    finally:
        await server.stop()

    assert received == []


async def test_server_handles_multiple_connections():
    port = free_port()
    received = []

    async def handler(msg):
        received.append(msg)

    server = NodeServer(port=port)
    await server.start(handler)

    try:
        for _ in range(3):
            async with websockets.asyncio.client.connect(f"ws://127.0.0.1:{port}") as ws:
                await ws.send(valid_raw_message())
        await asyncio.sleep(0.1)
    finally:
        await server.stop()

    assert len(received) == 3
