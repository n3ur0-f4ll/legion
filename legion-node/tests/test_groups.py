
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


"""Tests for messaging/groups.py."""

import pytest

from core.identity import generate as gen
from core.protocol import validate_message
from core.storage import Database
from messaging.groups import (
    accept_invite,
    create_group,
    get_posts,
    invite_member,
    post,
    receive_post,
    remove_member,
    _pack_invite,
    _unpack_invite,
)

ALICE = gen("alice")
BOB = gen("bob")
EVE = gen("eve")


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


# ------------------------------------------------------------------
# _pack_invite / _unpack_invite
# ------------------------------------------------------------------

def test_pack_unpack_invite_roundtrip():
    group_id = "a" * 64
    group_name = "Test Group"
    encrypted_key = b"\xde\xad\xbe\xef" * 20
    packed = _pack_invite(group_id, group_name, encrypted_key)
    gid, name, key = _unpack_invite(packed)
    assert gid == group_id
    assert name == group_name
    assert key == encrypted_key


def test_pack_unpack_unicode_name():
    group_id = "b" * 64
    group_name = "Załoga 🔐"
    encrypted_key = b"\x01" * 50
    packed = _pack_invite(group_id, group_name, encrypted_key)
    _, name, _ = _unpack_invite(packed)
    assert name == group_name


# ------------------------------------------------------------------
# create_group
# ------------------------------------------------------------------

async def test_create_group_returns_record(db):
    group = await create_group(db, ALICE, "Crew")
    assert group["name"] == "Crew"
    assert group["admin_key"] == ALICE.public_key.hex()
    assert group["is_admin"] is True
    assert len(group["group_key"]) == 32
    assert len(group["id"]) == 64


async def test_create_group_stores_in_db(db):
    group = await create_group(db, ALICE, "Crew")
    stored = await db.get_group(group["id"])
    assert stored is not None
    assert stored["name"] == "Crew"


async def test_create_group_adds_admin_as_member(db):
    group = await create_group(db, ALICE, "Crew")
    members = await db.get_group_members(group["id"])
    keys = {m["public_key"] for m in members}
    assert ALICE.public_key.hex() in keys


async def test_create_two_groups_different_ids(db):
    g1 = await create_group(db, ALICE, "Group A")
    g2 = await create_group(db, ALICE, "Group B")
    assert g1["id"] != g2["id"]


# ------------------------------------------------------------------
# invite_member
# ------------------------------------------------------------------

async def test_invite_member_returns_valid_protocol_message(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    validate_message(msg)


async def test_invite_member_type_is_group_invite(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    assert msg["type"] == "group_invite"


async def test_invite_member_addressed_to_invitee(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    assert msg["to"] == BOB.public_key.hex()


async def test_invite_non_admin_raises(db):
    group = await create_group(db, ALICE, "Crew")
    with pytest.raises(PermissionError):
        await invite_member(db, BOB, group["id"], EVE.public_key)


async def test_invite_nonexistent_group_raises(db):
    with pytest.raises(LookupError):
        await invite_member(db, ALICE, "x" * 64, BOB.public_key)


# ------------------------------------------------------------------
# accept_invite
# ------------------------------------------------------------------

async def test_accept_invite_stores_group(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    result = await accept_invite(db, BOB, msg)
    assert result["id"] == group["id"]
    assert result["name"] == "Crew"
    stored = await db.get_group(group["id"])
    assert stored is not None


async def test_accept_invite_recovers_group_key(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    result = await accept_invite(db, BOB, msg)
    assert result["group_key"] == group["group_key"]


async def test_accept_invite_marks_not_admin(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    result = await accept_invite(db, BOB, msg)
    assert result["is_admin"] is False


async def test_accept_invite_wrong_recipient_raises(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    with pytest.raises(ValueError, match="not addressed"):
        await accept_invite(db, EVE, msg)


# ------------------------------------------------------------------
# remove_member
# ------------------------------------------------------------------

async def test_remove_member_rotates_key(db):
    group = await create_group(db, ALICE, "Crew")
    old_key = group["group_key"]
    new_key = await remove_member(db, ALICE, group["id"], BOB.public_key)
    assert new_key != old_key
    stored = await db.get_group(group["id"])
    assert stored["group_key"] == new_key


async def test_remove_member_removes_from_db(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    await accept_invite(db, BOB, msg)
    await db.save_group_member(group["id"], BOB.public_key.hex(), 0)
    await remove_member(db, ALICE, group["id"], BOB.public_key)
    members = await db.get_group_members(group["id"])
    assert BOB.public_key.hex() not in {m["public_key"] for m in members}


async def test_remove_member_non_admin_raises(db):
    group = await create_group(db, ALICE, "Crew")
    with pytest.raises(PermissionError):
        await remove_member(db, BOB, group["id"], EVE.public_key)


# ------------------------------------------------------------------
# post
# ------------------------------------------------------------------

async def test_post_returns_valid_protocol_message(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await post(db, ALICE, group["id"], "hello group")
    validate_message(msg)


async def test_post_type_is_group_post(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await post(db, ALICE, group["id"], "hello")
    assert msg["type"] == "group_post"


async def test_post_stores_in_db(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await post(db, ALICE, group["id"], "hello group")
    posts = await db.get_group_posts(group["id"])
    assert len(posts) == 1
    assert posts[0]["id"] == msg["id"]


async def test_post_payload_is_not_plaintext(db):
    import base64
    group = await create_group(db, ALICE, "Crew")
    plaintext = "secret group content"
    msg = await post(db, ALICE, group["id"], plaintext)
    raw = base64.b64decode(msg["payload"])
    assert plaintext.encode() not in raw


async def test_post_nonexistent_group_raises(db):
    with pytest.raises(LookupError):
        await post(db, ALICE, "z" * 64, "hello")


# ------------------------------------------------------------------
# receive_post
# ------------------------------------------------------------------

async def test_receive_post_returns_plaintext(db):
    group = await create_group(db, ALICE, "Crew")
    # Bob joins
    invite_msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    await accept_invite(db, BOB, invite_msg)
    # Alice posts
    msg = await post(db, ALICE, group["id"], "hey everyone")
    # Bob receives
    plaintext = await receive_post(db, BOB, group["id"], msg)
    assert plaintext == "hey everyone"


async def test_receive_post_stores_in_db(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg = await invite_member(db, ALICE, group["id"], BOB.public_key)
    await accept_invite(db, BOB, invite_msg)
    msg = await post(db, ALICE, group["id"], "stored post")
    await receive_post(db, BOB, group["id"], msg)
    posts = await db.get_group_posts(group["id"])
    assert any(p["id"] == msg["id"] for p in posts)


async def test_receive_post_unknown_group_raises(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await post(db, ALICE, group["id"], "hello")
    # Bob has his own fresh DB — he was never invited so the group is unknown
    async with Database.open(":memory:") as bob_db:
        with pytest.raises(LookupError):
            await receive_post(bob_db, BOB, group["id"], msg)


# ------------------------------------------------------------------
# get_posts
# ------------------------------------------------------------------

async def test_get_posts_empty(db):
    group = await create_group(db, ALICE, "Crew")
    assert await get_posts(db, group["id"]) == []


async def test_get_posts_returns_all(db):
    group = await create_group(db, ALICE, "Crew")
    await post(db, ALICE, group["id"], "one")
    await post(db, ALICE, group["id"], "two")
    posts = await get_posts(db, group["id"])
    assert len(posts) == 2


async def test_get_posts_ordered_by_timestamp(db):
    group = await create_group(db, ALICE, "Crew")
    m1 = await post(db, ALICE, group["id"], "first")
    m2 = await post(db, ALICE, group["id"], "second")
    posts = await get_posts(db, group["id"])
    ids = [p["id"] for p in posts]
    assert ids.index(m1["id"]) < ids.index(m2["id"])
