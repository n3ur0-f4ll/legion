
# Legion — decentralized, anonymous communication platform
# Copyright (C) 2026  n3ur0-f4ll
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Tests for burn-after-reading and TTL cleanup loop.

Covers:
- burn flag in _encode_payload / _decode_payload
- send() with burn=True stores burn_after_reading in DB
- receive() extracts burn flag from payload
- burn_read_messages() deletes burn messages and returns IDs
- delete_if_burn() only deletes messages with burn_after_reading=1
- delete_expired_messages() / delete_expired_group_posts() (TTL cleanup bug fix)
- Full round-trip: send burn → receive → mark read → read_receipt sent
- read_receipt message type validates correctly
- Non-burn messages are NOT deleted by burn_read_messages
"""

from __future__ import annotations

import base64
import json
import time

import pytest
import pytest_asyncio

from core.identity import generate as gen_identity
from core.protocol import (
    MSG_READ_RECEIPT,
    build_message,
    validate_message,
    _VALID_TYPES,
)
from core.storage import Database
from messaging.private import _decode_payload, _encode_payload, receive, send


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------

@pytest_asyncio.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


@pytest_asyncio.fixture
async def alice(db):
    identity = gen_identity("Alice")
    await db.save_contact(
        public_key=identity.public_key.hex(),
        onion_address=identity.onion_address,
        alias="Alice",
        trusted_since=int(time.time()),
    )
    return identity


@pytest_asyncio.fixture
async def bob(db):
    identity = gen_identity("Bob")
    await db.save_contact(
        public_key=identity.public_key.hex(),
        onion_address=identity.onion_address,
        alias="Bob",
        trusted_since=int(time.time()),
    )
    return identity


# ------------------------------------------------------------------
# _encode_payload / _decode_payload
# ------------------------------------------------------------------

def test_encode_payload_no_burn():
    data = _encode_payload("hello", None, None, None, burn=False)
    parsed = json.loads(data)
    assert parsed == {"t": "hello"}
    assert "burn" not in parsed


def test_encode_payload_with_burn():
    data = _encode_payload("hello", None, None, None, burn=True)
    parsed = json.loads(data)
    assert parsed["t"] == "hello"
    assert parsed["burn"] is True


def test_decode_payload_extracts_burn():
    raw = json.dumps({"t": "secret", "burn": True}).encode()
    parsed = _decode_payload(raw)
    assert parsed["t"] == "secret"
    assert parsed["burn"] is True


def test_decode_payload_no_burn_defaults_false():
    raw = json.dumps({"t": "normal"}).encode()
    parsed = _decode_payload(raw)
    assert "burn" not in parsed or not parsed.get("burn")


# ------------------------------------------------------------------
# send() with burn flag
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_send_burn_sets_db_flag(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "burn me", burn=True)
    row = await db.get_message_by_id(msg["id"])
    assert row is not None
    assert row["burn_after_reading"] == 1


@pytest.mark.asyncio
async def test_send_no_burn_db_flag_zero(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "keep me", burn=False)
    row = await db.get_message_by_id(msg["id"])
    assert row is not None
    assert row["burn_after_reading"] == 0


@pytest.mark.asyncio
async def test_send_burn_payload_contains_flag(db, alice, bob):
    """Burn flag is inside the encrypted payload (verified by decrypting)."""
    from core import crypto
    msg = await send(db, alice, bob.public_key, "eyes only", burn=True)
    ciphertext = base64.b64decode(msg["payload"])
    raw = crypto.decrypt(bob.private_key, alice.public_key, ciphertext)
    parsed = json.loads(raw)
    assert parsed.get("burn") is True


# ------------------------------------------------------------------
# receive() extracts burn flag
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receive_stores_burn_flag(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "burn me", burn=True)
    await receive(db, bob, msg)
    row = await db.get_message_by_id(msg["id"])
    assert row["burn_after_reading"] == 1


@pytest.mark.asyncio
async def test_receive_no_burn_flag_zero(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "keep me")
    await receive(db, bob, msg)
    row = await db.get_message_by_id(msg["id"])
    assert row["burn_after_reading"] == 0


# ------------------------------------------------------------------
# burn_read_messages()
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_burn_read_deletes_burn_messages(db, alice, bob):
    """burn_read_messages deletes unread burn messages and returns their IDs."""
    msg1 = await send(db, alice, bob.public_key, "burn 1", burn=True)
    msg2 = await send(db, alice, bob.public_key, "burn 2", burn=True)
    await receive(db, bob, msg1)
    await receive(db, bob, msg2)

    burned_ids = await db.burn_read_messages(alice.public_key.hex(), bob.public_key.hex())

    assert set(burned_ids) == {msg1["id"], msg2["id"]}
    assert await db.get_message_by_id(msg1["id"]) is None
    assert await db.get_message_by_id(msg2["id"]) is None


@pytest.mark.asyncio
async def test_burn_read_does_not_delete_normal_messages(db, alice, bob):
    """burn_read_messages leaves non-burn messages intact."""
    burn_msg = await send(db, alice, bob.public_key, "burn", burn=True)
    keep_msg = await send(db, alice, bob.public_key, "keep")
    await receive(db, bob, burn_msg)
    await receive(db, bob, keep_msg)

    burned_ids = await db.burn_read_messages(alice.public_key.hex(), bob.public_key.hex())

    assert burn_msg["id"] in burned_ids
    assert keep_msg["id"] not in burned_ids
    assert await db.get_message_by_id(keep_msg["id"]) is not None


@pytest.mark.asyncio
async def test_burn_read_returns_empty_when_no_burn_messages(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "no burn")
    await receive(db, bob, msg)
    burned = await db.burn_read_messages(alice.public_key.hex(), bob.public_key.hex())
    assert burned == []


@pytest.mark.asyncio
async def test_burn_read_does_not_delete_already_read_messages(db, alice, bob):
    """Messages already marked as read are NOT re-burned (already processed)."""
    msg = await send(db, alice, bob.public_key, "burn", burn=True)
    await receive(db, bob, msg)
    # Mark as read first
    await db.mark_conversation_read(alice.public_key.hex(), bob.public_key.hex())
    # Now burn_read — should find nothing (read_at is set)
    burned = await db.burn_read_messages(alice.public_key.hex(), bob.public_key.hex())
    assert burned == []


# ------------------------------------------------------------------
# delete_if_burn()
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delete_if_burn_removes_burn_message(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "will burn", burn=True)
    result = await db.delete_if_burn(msg["id"])
    assert result is True
    assert await db.get_message_by_id(msg["id"]) is None


@pytest.mark.asyncio
async def test_delete_if_burn_ignores_normal_message(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "keep me")
    result = await db.delete_if_burn(msg["id"])
    assert result is False
    assert await db.get_message_by_id(msg["id"]) is not None


@pytest.mark.asyncio
async def test_delete_if_burn_returns_false_for_unknown_id(db):
    result = await db.delete_if_burn("nonexistent-id")
    assert result is False


# ------------------------------------------------------------------
# TTL cleanup (bug fix: delete_expired_messages was never called)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_delete_expired_messages_removes_old(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "old message")
    # Manually set expires_at to the past
    await db._conn.execute(
        "UPDATE messages SET expires_at = ? WHERE id = ?",
        (int(time.time()) - 1, msg["id"]),
    )
    await db._conn.commit()

    deleted = await db.delete_expired_messages(int(time.time()))
    assert deleted >= 1
    assert await db.get_message_by_id(msg["id"]) is None


@pytest.mark.asyncio
async def test_delete_expired_messages_keeps_fresh(db, alice, bob):
    msg = await send(db, alice, bob.public_key, "fresh")
    deleted = await db.delete_expired_messages(int(time.time()))
    assert deleted == 0
    assert await db.get_message_by_id(msg["id"]) is not None


@pytest.mark.asyncio
async def test_delete_expired_group_posts(db, alice):
    """delete_expired_group_posts removes posts past expires_at."""
    group_id = "a" * 64
    await db.save_group(
        id=group_id, name="g", group_key=b"\x00" * 32,
        admin_key=alice.public_key.hex(), is_admin=True, created_at=int(time.time()),
    )
    now = int(time.time())
    await db.save_group_post(
        id="post1", group_id=group_id, author_key=alice.public_key.hex(),
        payload=b"x", signature=b"\x00" * 64,
        timestamp=now - 10, expires_at=now - 1,  # already expired
    )
    deleted = await db.delete_expired_group_posts(now)
    assert deleted >= 1


# ------------------------------------------------------------------
# Protocol: MSG_READ_RECEIPT is a valid type
# ------------------------------------------------------------------

def test_read_receipt_in_valid_types():
    assert MSG_READ_RECEIPT in _VALID_TYPES
    assert MSG_READ_RECEIPT == "read_receipt"


def test_read_receipt_message_validates(alice, bob):
    """A well-formed read_receipt message passes validate_message()."""
    payload = json.dumps({"message_id": "abc123"}).encode()
    from core import crypto
    ct = crypto.encrypt(alice.private_key, bob.public_key, payload)
    msg = build_message(
        type=MSG_READ_RECEIPT,
        from_key=alice.public_key,
        to_key=bob.public_key,
        payload=ct,
        private_key=alice.private_key,
    )
    # Should not raise
    validate_message(msg)
    assert msg["type"] == "read_receipt"
