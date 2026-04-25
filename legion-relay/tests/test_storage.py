
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


"""Tests for relay/storage.py."""

import pytest
from relay.storage import Database

NOW = 1_714_000_000
EXPIRES = NOW + 7 * 86400


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


# ------------------------------------------------------------------
# relay_identity
# ------------------------------------------------------------------

async def test_load_identity_empty(db):
    assert await db.load_identity() is None


async def test_save_and_load_identity(db):
    await db.save_identity("pubkey", b"\x01" * 32, "test.onion", NOW)
    row = await db.load_identity()
    assert row["public_key"] == "pubkey"
    assert row["private_key"] == b"\x01" * 32
    assert row["onion_address"] == "test.onion"
    assert row["created_at"] == NOW


async def test_save_identity_replaces(db):
    await db.save_identity("pk1", b"\x01" * 32, "a.onion", NOW)
    await db.save_identity("pk1", b"\x02" * 32, "b.onion", NOW + 1)
    row = await db.load_identity()
    assert row["private_key"] == b"\x02" * 32


# ------------------------------------------------------------------
# authorized_senders
# ------------------------------------------------------------------

async def test_is_authorized_empty(db):
    assert await db.is_authorized("alice") is False


async def test_add_and_check_sender(db):
    await db.add_sender("alice_key", "Alice", NOW)
    assert await db.is_authorized("alice_key") is True
    assert await db.is_authorized("bob_key") is False


async def test_get_senders(db):
    await db.add_sender("alice", "Alice", NOW)
    await db.add_sender("bob", "Bob", NOW)
    senders = await db.get_senders()
    assert len(senders) == 2
    keys = {s["public_key"] for s in senders}
    assert keys == {"alice", "bob"}


async def test_remove_sender(db):
    await db.add_sender("alice", "Alice", NOW)
    await db.remove_sender("alice")
    assert await db.is_authorized("alice") is False


async def test_sender_alias_nullable(db):
    await db.add_sender("alice", None, NOW)
    senders = await db.get_senders()
    assert senders[0]["alias"] is None


async def test_add_sender_replace(db):
    await db.add_sender("alice", "Old", NOW)
    await db.add_sender("alice", "New", NOW + 1)
    senders = await db.get_senders()
    assert len(senders) == 1
    assert senders[0]["alias"] == "New"


# ------------------------------------------------------------------
# stored_messages
# ------------------------------------------------------------------

async def test_get_message_missing(db):
    assert await db.get_message("nonexistent") is None


async def test_save_and_get_message(db):
    await db.save_message(
        id="msg1", sender_key="alice", for_key="bob",
        destination_onion="bob.onion", payload=b"blob",
        received_at=NOW, expires_at=EXPIRES, next_retry_at=NOW,
    )
    row = await db.get_message("msg1")
    assert row["id"] == "msg1"
    assert row["status"] == "queued"
    assert row["retry_count"] == 0
    assert row["payload"] == b"blob"


async def test_save_message_duplicate_ignored(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"v1", NOW, EXPIRES, NOW)
    await db.save_message("msg1", "alice", "bob", "b.onion", b"v2", NOW, EXPIRES, NOW)
    row = await db.get_message("msg1")
    assert row["payload"] == b"v1"


async def test_get_due_returns_queued(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    due = await db.get_due(NOW + 1)
    assert len(due) == 1
    assert due[0]["id"] == "msg1"


async def test_get_due_filters_future(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW + 999)
    assert await db.get_due(NOW) == []


async def test_get_due_filters_delivered(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    await db.update_status("msg1", "delivered")
    assert await db.get_due(NOW + 1) == []


async def test_update_status(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    await db.update_status("msg1", "delivered")
    row = await db.get_message("msg1")
    assert row["status"] == "delivered"


async def test_update_retry(db):
    await db.save_message("msg1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    await db.update_retry("msg1", NOW + 60)
    row = await db.get_message("msg1")
    assert row["retry_count"] == 1
    assert row["next_retry_at"] == NOW + 60


async def test_delete_expired(db):
    await db.save_message("old", "alice", "bob", "b.onion", b"x", NOW - 100, NOW - 1, NOW - 100)
    await db.save_message("new", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    deleted = await db.delete_expired(NOW)
    assert deleted == 1
    assert await db.get_message("old") is None
    assert await db.get_message("new") is not None


async def test_count_queued(db):
    assert await db.count_queued() == 0
    await db.save_message("m1", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    await db.save_message("m2", "alice", "bob", "b.onion", b"x", NOW, EXPIRES, NOW)
    assert await db.count_queued() == 2
    await db.update_status("m1", "delivered")
    assert await db.count_queued() == 1
