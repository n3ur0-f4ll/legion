
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


"""Tests for network/client.py."""

import json
import socket
import threading
from unittest.mock import MagicMock, patch

import pytest
import websockets.asyncio.server

from core.identity import generate as gen
from core.protocol import MSG_PRIVATE, build_message
from network.client import NodeClientError, _recv_exact, _socks5_connect, send_message


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def valid_msg() -> dict:
    alice = gen("alice")
    bob = gen("bob")
    return build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"data", alice.private_key)


# ------------------------------------------------------------------
# _recv_exact — pure socket helper
# ------------------------------------------------------------------

def test_recv_exact_reads_exact_bytes():
    a, b = socket.socketpair()
    b.sendall(b"hello world")
    result = _recv_exact(a, 5)
    assert result == b"hello"
    a.close()
    b.close()


def test_recv_exact_raises_on_closed_socket():
    a, b = socket.socketpair()
    b.close()
    with pytest.raises(OSError):
        _recv_exact(a, 10)
    a.close()


def test_recv_exact_assembles_fragmented_data():
    a, b = socket.socketpair()
    # Send in two parts; recv_exact must reassemble
    b.sendall(b"AB")
    b.sendall(b"CD")
    result = _recv_exact(a, 4)
    assert result == b"ABCD"
    a.close()
    b.close()


# ------------------------------------------------------------------
# _socks5_connect — tested with a fake SOCKS5 server
# ------------------------------------------------------------------

def _fake_socks5_server(port: int, host_to_connect: str, dest_port: int) -> None:
    """Minimal fake SOCKS5 server that accepts one connection and verifies protocol."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        conn, _ = srv.accept()
        with conn:
            # Read greeting
            greeting = conn.recv(3)
            assert greeting == b"\x05\x01\x00"
            conn.sendall(b"\x05\x00")  # choose no-auth

            # Read connect request
            header = conn.recv(5)  # VER CMD RSV ATYP LEN
            n = header[4]
            host = conn.recv(n).decode("ascii")
            port_bytes = conn.recv(2)
            assert host == host_to_connect
            assert int.from_bytes(port_bytes, "big") == dest_port

            # Send success response (bound addr: 0.0.0.0:0)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")


def test_socks5_connect_completes_handshake():
    proxy_port = free_port()
    target_host = "test123456789012345678901234567890123456789012345678.onion"
    target_port = 80

    t = threading.Thread(
        target=_fake_socks5_server,
        args=(proxy_port, target_host, target_port),
        daemon=True,
    )
    t.start()

    sock = _socks5_connect(target_host, target_port, "127.0.0.1", proxy_port)
    t.join(timeout=2)
    sock.close()
    assert not t.is_alive(), "Fake server did not finish — handshake incomplete"


def test_socks5_connect_raises_on_refused():
    # No server running — connection refused
    port = free_port()
    with pytest.raises(OSError):
        _socks5_connect("test.onion", 80, "127.0.0.1", port)


def test_socks5_connect_raises_on_auth_rejection():
    proxy_port = free_port()

    def bad_server(port):
        with socket.socket() as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                conn.recv(3)
                conn.sendall(b"\x05\xFF")  # no acceptable method

    t = threading.Thread(target=bad_server, args=(proxy_port,), daemon=True)
    t.start()
    with pytest.raises(OSError):
        _socks5_connect("test.onion", 80, "127.0.0.1", proxy_port)
    t.join(timeout=2)


def test_socks5_connect_raises_on_connect_failure():
    proxy_port = free_port()

    def refusing_server(port):
        with socket.socket() as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", port))
            srv.listen(1)
            conn, _ = srv.accept()
            with conn:
                conn.recv(3)
                conn.sendall(b"\x05\x00")
                conn.recv(64)  # consume connect request
                # Reply with "connection refused" (code 5)
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")

    t = threading.Thread(target=refusing_server, args=(proxy_port,), daemon=True)
    t.start()
    with pytest.raises(OSError):
        _socks5_connect("test.onion", 80, "127.0.0.1", proxy_port)
    t.join(timeout=2)


# ------------------------------------------------------------------
# send_message — integration test with real WebSocket, mocked SOCKS5
# ------------------------------------------------------------------

async def test_send_message_delivers_to_server():
    """send_message with SOCKS5 mocked to return a direct localhost socket."""
    port = free_port()
    received = []

    async def ws_handler(ws):
        raw = await ws.recv()
        received.append(json.loads(raw))

    msg = valid_msg()

    async with websockets.asyncio.server.serve(ws_handler, "127.0.0.1", port):
        def fake_socks5(host, dst_port, proxy_host, proxy_port):
            sock = socket.create_connection(("127.0.0.1", port))
            sock.setblocking(False)
            return sock

        with patch("network.client._socks5_connect", side_effect=fake_socks5):
            await send_message(msg, "fake.onion", socks_port=9999, hs_port=port)

    assert len(received) == 1
    assert received[0]["id"] == msg["id"]


async def test_send_message_raises_on_connection_failure():
    port = free_port()  # nothing listening

    with pytest.raises(NodeClientError):
        await send_message(valid_msg(), "fake.onion", socks_host="127.0.0.1", socks_port=port)


async def test_send_message_raises_on_timeout():
    import asyncio as _asyncio

    msg = valid_msg()
    loop = _asyncio.get_event_loop()

    # Use a Future that never resolves so no thread is spawned,
    # then let a real tiny timeout expire cleanly.
    pending: _asyncio.Future = loop.create_future()
    try:
        with patch.object(loop, "run_in_executor", return_value=pending):
            with patch("network.client._CONNECT_TIMEOUT", 0.001):
                with pytest.raises(NodeClientError, match="timed out"):
                    await send_message(msg, "fake.onion", socks_port=9999)
    finally:
        pending.cancel()
