
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

import base64

import pytest

from core.identity import generate as gen
from core.protocol import validate_message
from core.storage import Database
from messaging.groups import (
    accept_invite,
    create_group,
    get_posts,
    handle_key_update,
    handle_member_update,
    invite_member,
    post,
    receive_post,
    remove_member,
)

ALICE = gen("alice")
BOB = gen("bob")
EVE = gen("eve")

BOB_ONION = "bobaddress.onion"
EVE_ONION = "eveaddress.onion"


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


# Helper: alice creates group, invites bob, bob accepts
async def _setup_group_with_bob(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(
        db, ALICE, group["id"], BOB.public_key, BOB_ONION
    )
    await accept_invite(db, BOB, invite_msg)
    return group


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
    assert ALICE.public_key.hex() in {m["public_key"] for m in members}


async def test_create_two_groups_different_ids(db):
    g1 = await create_group(db, ALICE, "Group A")
    g2 = await create_group(db, ALICE, "Group B")
    assert g1["id"] != g2["id"]


# ------------------------------------------------------------------
# invite_member
# ------------------------------------------------------------------

async def test_invite_member_returns_valid_protocol_message(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    validate_message(invite_msg)


async def test_invite_member_type_is_group_invite(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    assert invite_msg["type"] == "group_invite"


async def test_invite_member_addressed_to_invitee(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    assert invite_msg["to"] == BOB.public_key.hex()


async def test_invite_adds_member_to_admins_db(db):
    """Admin's group_members must include the invitee immediately after invite."""
    group = await create_group(db, ALICE, "Crew")
    await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    members = await db.get_group_members(group["id"])
    keys = {m["public_key"] for m in members}
    assert BOB.public_key.hex() in keys


async def test_invite_stores_invitee_onion(db):
    group = await create_group(db, ALICE, "Crew")
    await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    members = await db.get_group_members(group["id"])
    bob_entry = next((m for m in members if m["public_key"] == BOB.public_key.hex()), None)
    assert bob_entry is not None
    assert bob_entry["onion_address"] == BOB_ONION


async def test_invite_broadcasts_update_to_existing_members(db):
    """When Eve is invited, Alice gets a group_member_update for Eve."""
    group = await create_group(db, ALICE, "Crew")
    # First invite Bob
    await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    # Now invite Eve — should generate update_msgs for Bob
    _, update_msgs = await invite_member(db, ALICE, group["id"], EVE.public_key, EVE_ONION)
    # There should be a broadcast for Bob
    assert len(update_msgs) >= 1
    destinations = [onion for _, onion in update_msgs]
    assert BOB_ONION in destinations


async def test_invite_non_admin_raises(db):
    group = await create_group(db, ALICE, "Crew")
    with pytest.raises(PermissionError):
        await invite_member(db, BOB, group["id"], EVE.public_key, EVE_ONION)


async def test_invite_nonexistent_group_raises(db):
    with pytest.raises(LookupError):
        await invite_member(db, ALICE, "x" * 64, BOB.public_key, BOB_ONION)


# ------------------------------------------------------------------
# accept_invite
# ------------------------------------------------------------------

async def test_accept_invite_stores_group(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    result = await accept_invite(db, BOB, invite_msg)
    assert result["id"] == group["id"]
    assert result["name"] == "Crew"
    assert await db.get_group(group["id"]) is not None


async def test_accept_invite_recovers_group_key(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await accept_invite(db, BOB, invite_msg)
    stored = await db.get_group(group["id"])
    assert stored["group_key"] == group["group_key"]


async def test_accept_invite_marks_not_admin(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    result = await accept_invite(db, BOB, invite_msg)
    assert result["is_admin"] is False


async def test_accept_invite_saves_member_roster(db):
    """Bob's group_members should contain Eve's onion after getting an invite with roster."""
    group = await create_group(db, ALICE, "Crew")
    # Invite Eve first so her onion is in the roster when Bob is invited
    await invite_member(db, ALICE, group["id"], EVE.public_key, EVE_ONION)
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await accept_invite(db, BOB, invite_msg)
    members = await db.get_group_members(group["id"])
    onions = {m["onion_address"] for m in members}
    assert EVE_ONION in onions


async def test_accept_invite_wrong_recipient_raises(db):
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    with pytest.raises(ValueError, match="not addressed"):
        await accept_invite(db, EVE, invite_msg)


# ------------------------------------------------------------------
# remove_member
# ------------------------------------------------------------------

async def test_remove_member_rotates_key(db):
    group = await create_group(db, ALICE, "Crew")
    old_key = group["group_key"]
    new_key, _ = await remove_member(db, ALICE, group["id"], BOB.public_key)
    assert new_key != old_key
    stored = await db.get_group(group["id"])
    assert stored["group_key"] == new_key


async def test_remove_member_removes_from_db(db):
    group = await _setup_group_with_bob(db)
    await remove_member(db, ALICE, group["id"], BOB.public_key)
    members = await db.get_group_members(group["id"])
    assert BOB.public_key.hex() not in {m["public_key"] for m in members}


async def test_remove_member_broadcasts_to_remaining(db):
    """Remaining members (not Bob) should receive key_update + member_update."""
    group = await create_group(db, ALICE, "Crew")
    await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await invite_member(db, ALICE, group["id"], EVE.public_key, EVE_ONION)
    _, broadcasts = await remove_member(db, ALICE, group["id"], BOB.public_key)
    # Eve should receive both a key_update and a member_update
    destinations = [onion for _, onion in broadcasts]
    assert EVE_ONION in destinations
    # Should NOT send anything to Bob (he was removed)
    assert BOB_ONION not in destinations


async def test_remove_member_non_admin_raises(db):
    group = await create_group(db, ALICE, "Crew")
    with pytest.raises(PermissionError):
        await remove_member(db, BOB, group["id"], EVE.public_key)


# ------------------------------------------------------------------
# handle_member_update / handle_key_update
# ------------------------------------------------------------------

async def test_handle_member_update_add(db):
    """Receiving op=add should add member to local group_members."""
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await accept_invite(db, BOB, invite_msg)

    # Bob receives a member_update announcing Eve
    _, updates = await invite_member(db, ALICE, group["id"], EVE.public_key, EVE_ONION)
    # Find the update addressed to Bob
    bob_update = next((msg for msg, onion in updates if onion == BOB_ONION), None)
    assert bob_update is not None
    await handle_member_update(db, BOB, bob_update)

    members = await db.get_group_members(group["id"])
    assert EVE.public_key.hex() in {m["public_key"] for m in members}


async def test_handle_member_update_remove(db):
    """Receiving op=remove should remove member from local group_members."""
    group = await create_group(db, ALICE, "Crew")
    # Invite Bob (he's added to DB with BOB_ONION on Alice's side)
    bob_invite, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    # Invite Eve so she's in the roster
    await invite_member(db, ALICE, group["id"], EVE.public_key, EVE_ONION)
    # Bob accepts his own invite
    await accept_invite(db, BOB, bob_invite)

    # Admin removes Eve — broadcasts remove update to Bob
    _, broadcasts = await remove_member(db, ALICE, group["id"], EVE.public_key)
    bob_remove = next(
        (msg for msg, onion in broadcasts
         if onion == BOB_ONION and msg["type"] == "group_member_update"),
        None,
    )
    assert bob_remove is not None
    await handle_member_update(db, BOB, bob_remove)
    members = await db.get_group_members(group["id"])
    assert EVE.public_key.hex() not in {m["public_key"] for m in members}


async def test_handle_key_update_replaces_key(db):
    """Receiving group_key_update should update the local group key."""
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await accept_invite(db, BOB, invite_msg)

    new_key, broadcasts = await remove_member(db, ALICE, group["id"], EVE.public_key)
    bob_key_update = next(
        (msg for msg, onion in broadcasts
         if onion == BOB_ONION and msg["type"] == "group_key_update"),
        None,
    )
    if bob_key_update:
        await handle_key_update(db, BOB, bob_key_update)
        stored = await db.get_group(group["id"])
        assert stored["group_key"] == new_key


async def test_handle_key_update_rejects_non_admin(db):
    """Key updates from non-admins must be silently ignored."""
    group = await create_group(db, ALICE, "Crew")
    invite_msg, _ = await invite_member(db, ALICE, group["id"], BOB.public_key, BOB_ONION)
    await accept_invite(db, BOB, invite_msg)

    original_key = (await db.get_group(group["id"]))["group_key"]

    # Build a fake key_update from EVE (not admin)
    import json as _json
    from core import crypto as _crypto
    from core.protocol import MSG_GROUP_KEY_UPDATE, build_message as _bm
    fake_key = _crypto.generate_group_key()
    fake_payload = _json.dumps({
        "group_id": group["id"],
        "new_key": base64.b64encode(fake_key).decode(),
    }).encode()
    ct = _crypto.encrypt(EVE.private_key, BOB.public_key, fake_payload)
    fake_msg = _bm(
        type=MSG_GROUP_KEY_UPDATE,
        from_key=EVE.public_key,
        to_key=BOB.public_key,
        payload=ct,
        private_key=EVE.private_key,
    )
    await handle_key_update(db, BOB, fake_msg)
    # Key must NOT have changed
    stored = await db.get_group(group["id"])
    assert stored["group_key"] == original_key


# ------------------------------------------------------------------
# post / receive_post / get_posts
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
    group = await create_group(db, ALICE, "Crew")
    plaintext = "secret group content"
    msg = await post(db, ALICE, group["id"], plaintext)
    raw = base64.b64decode(msg["payload"])
    assert plaintext.encode() not in raw


async def test_post_nonexistent_group_raises(db):
    with pytest.raises(LookupError):
        await post(db, ALICE, "z" * 64, "hello")


async def test_receive_post_returns_plaintext(db):
    group = await _setup_group_with_bob(db)
    msg = await post(db, ALICE, group["id"], "hey everyone")
    plaintext = await receive_post(db, BOB, group["id"], msg)
    assert plaintext == "hey everyone"


async def test_receive_post_stores_in_db(db):
    group = await _setup_group_with_bob(db)
    msg = await post(db, ALICE, group["id"], "stored post")
    await receive_post(db, BOB, group["id"], msg)
    posts = await db.get_group_posts(group["id"])
    assert any(p["id"] == msg["id"] for p in posts)


async def test_receive_post_unknown_group_raises(db):
    group = await create_group(db, ALICE, "Crew")
    msg = await post(db, ALICE, group["id"], "hello")
    async with Database.open(":memory:") as bob_db:
        with pytest.raises(LookupError):
            await receive_post(bob_db, BOB, group["id"], msg)


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
