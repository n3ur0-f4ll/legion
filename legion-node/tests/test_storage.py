
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


"""Tests for core/storage.py."""

import pytest

from core.storage import Database

NOW = 1_714_000_000
EXPIRES = NOW + 90 * 86400


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


# ------------------------------------------------------------------
# identity
# ------------------------------------------------------------------

async def test_load_identity_empty(db):
    assert await db.load_identity() is None


async def test_save_and_load_identity(db):
    await db.save_identity(
        public_key="aabbcc",
        private_key=b"\x01" * 32,
        onion_address="test.onion",
        alias="alice",
        created_at=NOW,
    )
    row = await db.load_identity()
    assert row["public_key"] == "aabbcc"
    assert row["private_key"] == b"\x01" * 32
    assert row["onion_address"] == "test.onion"
    assert row["alias"] == "alice"
    assert row["created_at"] == NOW


async def test_save_identity_replace(db):
    await db.save_identity("aabbcc", b"\x01" * 32, "a.onion", "alice", NOW)
    await db.save_identity("aabbcc", b"\x02" * 32, "b.onion", "alice2", NOW + 1)
    row = await db.load_identity()
    assert row["alias"] == "alice2"
    assert row["private_key"] == b"\x02" * 32


# ------------------------------------------------------------------
# relay_config
# ------------------------------------------------------------------

async def test_load_relay_config_empty(db):
    assert await db.load_relay_config() is None


async def test_save_and_load_relay_config(db):
    await db.save_relay_config("relay.onion", "pubkey123")
    row = await db.load_relay_config()
    assert row["onion_address"] == "relay.onion"
    assert row["public_key"] == "pubkey123"
    assert row["enabled"] == 1


async def test_delete_relay_config(db):
    await db.save_relay_config("relay.onion", "pubkey123")
    await db.delete_relay_config()
    assert await db.load_relay_config() is None


# ------------------------------------------------------------------
# contacts
# ------------------------------------------------------------------

async def test_get_contacts_empty(db):
    assert await db.get_contacts() == []


async def test_save_and_get_contact(db):
    await db.save_contact("pubkey_bob", "bob.onion", "Bob", NOW)
    contacts = await db.get_contacts()
    assert len(contacts) == 1
    assert contacts[0]["public_key"] == "pubkey_bob"
    assert contacts[0]["alias"] == "Bob"


async def test_get_contact_by_key(db):
    await db.save_contact("pubkey_bob", "bob.onion", "Bob", NOW)
    row = await db.get_contact("pubkey_bob")
    assert row is not None
    assert row["onion_address"] == "bob.onion"


async def test_get_contact_missing(db):
    assert await db.get_contact("nonexistent") is None


async def test_delete_contact(db):
    await db.save_contact("pubkey_bob", "bob.onion", "Bob", NOW)
    await db.delete_contact("pubkey_bob")
    assert await db.get_contact("pubkey_bob") is None


async def test_contact_alias_nullable(db):
    await db.save_contact("pubkey_bob", "bob.onion", None, NOW)
    row = await db.get_contact("pubkey_bob")
    assert row["alias"] is None


# ------------------------------------------------------------------
# messages
# ------------------------------------------------------------------

async def test_save_and_get_messages(db):
    await db.save_message(
        id="msg1",
        from_key="alice",
        to_key="bob",
        payload=b"encrypted",
        signature=b"sig",
        timestamp=NOW,
        expires_at=EXPIRES,
        status="queued",
    )
    rows = await db.get_messages("alice", "bob")
    assert len(rows) == 1
    assert rows[0]["id"] == "msg1"
    assert rows[0]["status"] == "queued"


async def test_get_messages_bidirectional(db):
    await db.save_message("m1", "alice", "bob", b"e", b"s", NOW, EXPIRES, "sent")
    await db.save_message("m2", "bob", "alice", b"e", b"s", NOW + 1, EXPIRES, "delivered")
    rows = await db.get_messages("alice", "bob")
    assert len(rows) == 2


async def test_update_message_status(db):
    await db.save_message("msg1", "alice", "bob", b"e", b"s", NOW, EXPIRES, "queued")
    await db.update_message_status("msg1", "delivered")
    rows = await db.get_messages("alice", "bob")
    assert rows[0]["status"] == "delivered"


async def test_save_message_duplicate_ignored(db):
    await db.save_message("msg1", "alice", "bob", b"e", b"s", NOW, EXPIRES, "queued")
    await db.save_message("msg1", "alice", "bob", b"e2", b"s2", NOW, EXPIRES, "sent")
    rows = await db.get_messages("alice", "bob")
    assert len(rows) == 1
    assert rows[0]["payload"] == b"e"


async def test_delete_expired_messages(db):
    await db.save_message("old", "alice", "bob", b"e", b"s", NOW - 200, NOW - 1, "sent")
    await db.save_message("new", "alice", "bob", b"e", b"s", NOW, EXPIRES, "sent")
    deleted = await db.delete_expired_messages(NOW)
    assert deleted == 1
    rows = await db.get_messages("alice", "bob")
    assert len(rows) == 1
    assert rows[0]["id"] == "new"


# ------------------------------------------------------------------
# groups & group_members
# ------------------------------------------------------------------

async def test_save_and_get_group(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin_key", True, NOW)
    groups = await db.get_groups()
    assert len(groups) == 1
    assert groups[0]["name"] == "Crew"
    assert groups[0]["is_admin"] == 1


async def test_get_group_by_id(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin_key", True, NOW)
    row = await db.get_group("grp1")
    assert row is not None
    assert row["group_key"] == b"\xaa" * 32


async def test_get_group_missing(db):
    assert await db.get_group("nope") is None


async def test_save_and_get_group_members(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin", False, NOW)
    await db.save_group_member("grp1", "alice", NOW)
    await db.save_group_member("grp1", "bob", NOW)
    members = await db.get_group_members("grp1")
    assert len(members) == 2
    keys = {m["public_key"] for m in members}
    assert keys == {"alice", "bob"}


async def test_save_group_member_duplicate_ignored(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin", False, NOW)
    await db.save_group_member("grp1", "alice", NOW)
    await db.save_group_member("grp1", "alice", NOW + 1)
    assert len(await db.get_group_members("grp1")) == 1


async def test_delete_group_member(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin", False, NOW)
    await db.save_group_member("grp1", "alice", NOW)
    await db.delete_group_member("grp1", "alice")
    assert await db.get_group_members("grp1") == []


# ------------------------------------------------------------------
# group_posts
# ------------------------------------------------------------------

async def test_save_and_get_group_posts(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin", False, NOW)
    await db.save_group_post("post1", "grp1", "alice", b"payload", b"sig", NOW, EXPIRES)
    posts = await db.get_group_posts("grp1")
    assert len(posts) == 1
    assert posts[0]["author_key"] == "alice"


async def test_delete_expired_group_posts(db):
    await db.save_group("grp1", "Crew", b"\xaa" * 32, "admin", False, NOW)
    await db.save_group_post("old", "grp1", "alice", b"p", b"s", NOW - 100, NOW - 1)
    await db.save_group_post("new", "grp1", "alice", b"p", b"s", NOW, EXPIRES)
    deleted = await db.delete_expired_group_posts(NOW)
    assert deleted == 1
    assert len(await db.get_group_posts("grp1")) == 1


# ------------------------------------------------------------------
# delivery_queue
# ------------------------------------------------------------------

async def test_enqueue_and_get_due(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW)
    due = await db.get_due(NOW)
    assert len(due) == 1
    assert due[0]["message_id"] == "msg1"
    assert due[0]["retry_count"] == 0


async def test_get_due_filters_future(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW + 9999)
    assert await db.get_due(NOW) == []


async def test_update_retry(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW)
    await db.update_retry("dq1", NOW + 60)
    due = await db.get_due(NOW + 60)
    assert due[0]["retry_count"] == 1
    assert due[0]["next_retry_at"] == NOW + 60


async def test_dequeue(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW)
    await db.dequeue("dq1")
    assert await db.get_due(NOW) == []


async def test_enqueue_duplicate_ignored(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW)
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW)
    assert len(await db.get_due(NOW)) == 1


async def test_via_relay_flag(db):
    await db.enqueue("dq1", "msg1", "bob_key", "bob.onion", NOW, via_relay=True)
    due = await db.get_due(NOW)
    assert due[0]["via_relay"] == 1
