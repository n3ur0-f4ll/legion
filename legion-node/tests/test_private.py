
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


"""Tests for messaging/private.py."""

import pytest

from core.identity import generate as gen
from core.protocol import validate_message
from core.storage import Database
from messaging.private import get_conversation, receive, send


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


ALICE = gen("alice")
BOB = gen("bob")


# ------------------------------------------------------------------
# send
# ------------------------------------------------------------------

async def test_send_returns_valid_protocol_message(db):
    msg = await send(db, ALICE, BOB.public_key, "hello bob")
    validate_message(msg)  # must not raise


async def test_send_message_type_is_private(db):
    msg = await send(db, ALICE, BOB.public_key, "hello")
    assert msg["type"] == "msg"


async def test_send_from_and_to_fields(db):
    msg = await send(db, ALICE, BOB.public_key, "hello")
    assert msg["from"] == ALICE.public_key.hex()
    assert msg["to"] == BOB.public_key.hex()


async def test_send_payload_is_not_plaintext(db):
    import base64
    plaintext = "secret content"
    msg = await send(db, ALICE, BOB.public_key, plaintext)
    raw_payload = base64.b64decode(msg["payload"])
    assert plaintext.encode() not in raw_payload


async def test_send_stores_message_as_queued(db):
    msg = await send(db, ALICE, BOB.public_key, "hello")
    rows = await db.get_messages(BOB.public_key.hex(), ALICE.public_key.hex())
    assert len(rows) == 1
    assert rows[0]["id"] == msg["id"]
    assert rows[0]["status"] == "queued"


async def test_send_different_messages_have_different_ids(db):
    m1 = await send(db, ALICE, BOB.public_key, "first")
    m2 = await send(db, ALICE, BOB.public_key, "second")
    assert m1["id"] != m2["id"]


# ------------------------------------------------------------------
# receive
# ------------------------------------------------------------------

async def _sent_msg(db):
    """Helper: Alice sends to Bob, returns the protocol message."""
    return await send(db, ALICE, BOB.public_key, "hello from alice")


async def test_receive_returns_plaintext(db):
    msg = await _sent_msg(db)
    plaintext = await receive(db, BOB, msg)
    assert plaintext == "hello from alice"


async def test_receive_stores_message_as_delivered(db):
    msg = await _sent_msg(db)
    await receive(db, BOB, msg)
    rows = await db.get_messages(ALICE.public_key.hex(), BOB.public_key.hex())
    assert any(r["status"] == "delivered" for r in rows)


async def test_receive_wrong_recipient_raises(db):
    eve = gen("eve")
    msg = await _sent_msg(db)
    with pytest.raises(ValueError, match="not addressed"):
        await receive(db, eve, msg)


async def test_receive_unicode_content(db):
    msg = await send(db, ALICE, BOB.public_key, "zażółć gęślą jaźń 🔐")
    plaintext = await receive(db, BOB, msg)
    assert plaintext == "zażółć gęślą jaźń 🔐"


async def test_receive_empty_message(db):
    msg = await send(db, ALICE, BOB.public_key, "")
    plaintext = await receive(db, BOB, msg)
    assert plaintext == ""


async def test_receive_does_not_duplicate_on_second_call(db):
    msg = await _sent_msg(db)
    await receive(db, BOB, msg)
    await receive(db, BOB, msg)  # second call — INSERT OR IGNORE
    rows = await db.get_messages(ALICE.public_key.hex(), BOB.public_key.hex())
    assert len(rows) == 1


# ------------------------------------------------------------------
# send → receive round-trip
# ------------------------------------------------------------------

async def test_roundtrip_alice_to_bob(db):
    msg = await send(db, ALICE, BOB.public_key, "secure message")
    plaintext = await receive(db, BOB, msg)
    assert plaintext == "secure message"


async def test_roundtrip_bob_to_alice(db):
    msg = await send(db, BOB, ALICE.public_key, "reply from bob")
    plaintext = await receive(db, ALICE, msg)
    assert plaintext == "reply from bob"


# ------------------------------------------------------------------
# get_conversation
# ------------------------------------------------------------------

async def test_get_conversation_empty(db):
    result = await get_conversation(db, ALICE.public_key, BOB.public_key)
    assert result == []


async def test_get_conversation_returns_all_messages(db):
    await send(db, ALICE, BOB.public_key, "msg 1")
    await send(db, ALICE, BOB.public_key, "msg 2")
    result = await get_conversation(db, ALICE.public_key, BOB.public_key)
    assert len(result) == 2


async def test_get_conversation_ordered_by_timestamp(db):
    m1 = await send(db, ALICE, BOB.public_key, "first")
    m2 = await send(db, ALICE, BOB.public_key, "second")
    result = await get_conversation(db, ALICE.public_key, BOB.public_key)
    ids = [r["id"] for r in result]
    assert ids.index(m1["id"]) < ids.index(m2["id"])


async def test_get_conversation_includes_both_directions(db):
    await send(db, ALICE, BOB.public_key, "from alice")
    msg_bob = await send(db, BOB, ALICE.public_key, "from bob")
    await receive(db, ALICE, msg_bob)
    result = await get_conversation(db, ALICE.public_key, BOB.public_key)
    assert len(result) == 2
