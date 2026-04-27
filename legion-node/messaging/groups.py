
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
Logika grup: tworzenie, zaproszenia, posty, rotacja klucza.

Grupa to wspólny klucz symetryczny (SecretBox) znany wszystkim członkom.
Każdy post jest szyfrowany tym kluczem i podpisany kluczem autora.

Bezpieczeństwo zaproszenia:
  Cały payload group_invite jest Box-szyfrowany (X25519) dla odbiorcy —
  metadane grupy (id, nazwa, roster) nie są widoczne na warstwie sieciowej.
  Zaproszenie zawiera listę członków z adresami .onion, dzięki czemu
  nowy członek może wysyłać posty peer-to-peer bez pośrednictwa admina.

Rotacja klucza:
  Po usunięciu członka admin generuje nowy klucz i rozsyła go do każdego
  pozostałego członka osobno przez group_key_update (Box-encrypted per-member).
  Wykluczona osoba traci możliwość odczytu nowych postów.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

from core import crypto
from core.identity import Identity
from core.protocol import (
    MSG_GROUP_INVITE,
    MSG_GROUP_KEY_UPDATE,
    MSG_GROUP_MEMBER_UPDATE,
    MSG_GROUP_POST,
    DEFAULT_TTL,
    build_message,
)
from core.storage import Database


# ------------------------------------------------------------------
# group management
# ------------------------------------------------------------------

async def create_group(
    db: Database,
    identity: Identity,
    name: str,
) -> dict:
    """Create a new group with a fresh symmetric key. Returns the group record."""
    group_key = crypto.generate_group_key()
    group_id = _group_id(identity.public_key, name, int(time.time()))
    now = int(time.time())

    await db.save_group(
        id=group_id,
        name=name,
        group_key=group_key,
        admin_key=identity.public_key.hex(),
        is_admin=True,
        created_at=now,
    )
    # Store admin's own onion so it's included in future invite rosters
    await db.save_group_member(
        group_id, identity.public_key.hex(), now,
        onion_address=identity.onion_address,
    )

    return {
        "id": group_id,
        "name": name,
        "group_key": group_key,
        "admin_key": identity.public_key.hex(),
        "is_admin": True,
        "created_at": now,
    }


async def invite_member(
    db: Database,
    identity: Identity,
    group_id: str,
    member_public_key: bytes,
    member_onion: str,
    ttl: int = DEFAULT_TTL,
) -> tuple[dict, list[dict]]:
    """Build invite message and member-update broadcasts.

    Returns (invite_msg, [group_member_update msgs for existing members]).
    Adds the new member to admin's group_members immediately.

    Raises PermissionError if caller is not admin.
    Raises LookupError if group does not exist.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")
    if group["admin_key"] != identity.public_key.hex():
        raise PermissionError("Only the group admin can invite members")

    member_hex = member_public_key.hex()
    existing_members = await db.get_group_members(group_id)

    # Build invite payload: group key + full member roster (Box-encrypted for invitee)
    plaintext = json.dumps({
        "group_id": group_id,
        "name": group["name"],
        "key": base64.b64encode(group["group_key"]).decode(),
        "members": [
            {"public_key": m["public_key"], "onion": m["onion_address"]}
            for m in existing_members
            if m["public_key"] != member_hex  # don't include the invitee themselves
        ],
    }).encode()

    ciphertext = crypto.encrypt(identity.private_key, member_public_key, plaintext)
    invite_msg = build_message(
        type=MSG_GROUP_INVITE,
        from_key=identity.public_key,
        to_key=member_public_key,
        payload=ciphertext,
        private_key=identity.private_key,
        ttl=ttl,
    )

    # Add new member to admin's group_members before broadcasting
    now = int(time.time())
    await db.save_group_member(group_id, member_hex, now, onion_address=member_onion)

    # Broadcast group_member_update(op=add) to all existing members
    update_msgs = []
    for member in existing_members:
        if member["public_key"] == identity.public_key.hex():
            continue  # skip self
        if not member["onion_address"]:
            continue  # skip members without onion (shouldn't happen, defensive)
        m_pub = bytes.fromhex(member["public_key"])
        update_payload = json.dumps({
            "op": "add",
            "group_id": group_id,
            "public_key": member_hex,
            "onion": member_onion,
        }).encode()
        ciphertext_upd = crypto.encrypt(identity.private_key, m_pub, update_payload)
        msg = build_message(
            type=MSG_GROUP_MEMBER_UPDATE,
            from_key=identity.public_key,
            to_key=m_pub,
            payload=ciphertext_upd,
            private_key=identity.private_key,
            ttl=ttl,
        )
        update_msgs.append((msg, member["onion_address"]))

    return invite_msg, update_msgs


async def accept_invite(
    db: Database,
    identity: Identity,
    msg: dict,
) -> dict:
    """Process an incoming group_invite message and store the group locally.

    msg must already be validated by validate_message() before calling this.
    Decrypts the Box-encrypted invite payload, saves group and full member roster.
    Raises ValueError if the invite is malformed or not addressed to this identity.
    Returns the stored group record.
    """
    if msg["to"] != identity.public_key.hex():
        raise ValueError("Invite is not addressed to this identity")

    sender_public_key = bytes.fromhex(msg["from"])
    ciphertext = base64.b64decode(msg["payload"])

    plaintext = crypto.decrypt(identity.private_key, sender_public_key, ciphertext)
    invite = json.loads(plaintext)

    group_id = invite["group_id"]
    group_name = invite["name"]
    group_key = base64.b64decode(invite["key"])
    members = invite.get("members", [])

    now = int(time.time())
    await db.save_group(
        id=group_id,
        name=group_name,
        group_key=group_key,
        admin_key=msg["from"],
        is_admin=False,
        created_at=now,
    )

    # Save all members from the roster — this includes the admin with their onion address.
    # Do not make a separate admin save that could overwrite roster data with empty onion.
    for m in members:
        await db.save_group_member(
            group_id, m["public_key"], now, onion_address=m.get("onion", "")
        )

    # Add self only if not already present — our own onion is not critical for routing
    # (others have our onion from the invite payload the admin sent them)
    self_hex = identity.public_key.hex()
    current = await db.get_group_members(group_id)
    if not any(m["public_key"] == self_hex for m in current):
        await db.save_group_member(group_id, self_hex, now, onion_address="")

    return {
        "id": group_id,
        "name": group_name,
        "admin_key": msg["from"],
        "is_admin": False,
        "created_at": now,
    }


async def remove_member(
    db: Database,
    identity: Identity,
    group_id: str,
    member_public_key: bytes,
    ttl: int = DEFAULT_TTL,
) -> tuple[bytes, list[tuple[dict, str]]]:
    """Remove a member, rotate the group key, and build broadcast messages.

    Returns (new_group_key, [(msg, destination_onion), ...]) where msgs are
    group_key_update and group_member_update messages for all remaining members
    PLUS a group_member_update for the removed member so they know they were removed.

    Raises PermissionError if caller is not admin.
    Raises LookupError if group does not exist.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")
    if group["admin_key"] != identity.public_key.hex():
        raise PermissionError("Only the group admin can remove members")

    member_hex = member_public_key.hex()

    # Save removed member's onion BEFORE deleting — needed to notify them
    all_members = await db.get_group_members(group_id)
    removed_record = next((m for m in all_members if m["public_key"] == member_hex), None)
    removed_onion = removed_record["onion_address"] if removed_record else ""

    await db.delete_group_member(group_id, member_hex)

    # Generate and save new key immediately
    new_key = crypto.generate_group_key()
    await db.update_group_key(group_id, new_key)

    broadcasts: list[tuple[dict, str]] = []

    # Notify the removed member so they can delete the group locally and show UI feedback
    if removed_onion:
        rm_payload = json.dumps({
            "op": "remove",
            "group_id": group_id,
            "public_key": member_hex,
            "group_name": group["name"],
        }).encode()
        rm_ct = crypto.encrypt(identity.private_key, member_public_key, rm_payload)
        rm_msg = build_message(
            type=MSG_GROUP_MEMBER_UPDATE,
            from_key=identity.public_key,
            to_key=member_public_key,
            payload=rm_ct,
            private_key=identity.private_key,
            ttl=ttl,
        )
        broadcasts.append((rm_msg, removed_onion))

    # Build broadcasts to all remaining members
    remaining = await db.get_group_members(group_id)
    for member in remaining:
        if member["public_key"] == identity.public_key.hex():
            continue
        if not member["onion_address"]:
            continue
        m_pub = bytes.fromhex(member["public_key"])

        # 1. New group key (Box-encrypted per member)
        key_payload = json.dumps({
            "group_id": group_id,
            "new_key": base64.b64encode(new_key).decode(),
        }).encode()
        key_ct = crypto.encrypt(identity.private_key, m_pub, key_payload)
        key_msg = build_message(
            type=MSG_GROUP_KEY_UPDATE,
            from_key=identity.public_key,
            to_key=m_pub,
            payload=key_ct,
            private_key=identity.private_key,
            ttl=2_592_000,  # 30 days — key updates are critical
        )
        broadcasts.append((key_msg, member["onion_address"]))

        # 2. Roster change: notify that removed member is gone
        upd_payload = json.dumps({
            "op": "remove",
            "group_id": group_id,
            "public_key": member_hex,
            "group_name": group["name"],
        }).encode()
        upd_ct = crypto.encrypt(identity.private_key, m_pub, upd_payload)
        upd_msg = build_message(
            type=MSG_GROUP_MEMBER_UPDATE,
            from_key=identity.public_key,
            to_key=m_pub,
            payload=upd_ct,
            private_key=identity.private_key,
            ttl=ttl,
        )
        broadcasts.append((upd_msg, member["onion_address"]))

    return new_key, broadcasts


async def handle_member_update(
    db: Database,
    identity: Identity,
    msg: dict,
) -> dict | None:
    """Process an incoming group_member_update from the group admin.

    Verifies that the sender is the admin of the referenced group,
    then adds or removes the member from the local group_members table.

    Special case: if op=remove and public_key == our own key, the admin removed US.
    We delete the group from local DB and return op="removed_self".

    Returns a dict with context for the SSE event, or None if the message was ignored.
    """
    if msg["to"] != identity.public_key.hex():
        return None

    ciphertext = base64.b64decode(msg["payload"])
    sender_pub = bytes.fromhex(msg["from"])
    plaintext = crypto.decrypt(identity.private_key, sender_pub, ciphertext)
    update = json.loads(plaintext)

    group_id = update.get("group_id", "")
    group = await db.get_group(group_id)
    if group is None:
        return None  # unknown group — ignore

    # Only accept roster updates from the group admin
    if msg["from"] != group["admin_key"]:
        return None

    op = update.get("op")
    pub = update.get("public_key", "")
    onion = update.get("onion", "")
    group_name = update.get("group_name", group["name"])

    if op == "add" and pub:
        await db.save_group_member(
            group_id, pub, int(time.time()), onion_address=onion
        )
        return {"op": "add", "group_id": group_id, "public_key": pub,
                "group_name": group_name}

    elif op == "remove" and pub:
        if pub == identity.public_key.hex():
            # We were removed — delete the group from our local DB
            await db.delete_group(group_id)
            return {"op": "removed_self", "group_id": group_id, "public_key": pub,
                    "group_name": group_name}
        else:
            await db.delete_group_member(group_id, pub)
            return {"op": "remove", "group_id": group_id, "public_key": pub,
                    "group_name": group_name}

    return None


async def handle_key_update(
    db: Database,
    identity: Identity,
    msg: dict,
) -> str | None:
    """Process an incoming group_key_update from the group admin.

    Verifies that the sender is the admin of the referenced group,
    then replaces the local group key with the new one.

    Returns the group_id on success, None if the message was ignored.
    """
    if msg["to"] != identity.public_key.hex():
        return None

    ciphertext = base64.b64decode(msg["payload"])
    sender_pub = bytes.fromhex(msg["from"])
    plaintext = crypto.decrypt(identity.private_key, sender_pub, ciphertext)
    update = json.loads(plaintext)

    group_id = update.get("group_id", "")
    group = await db.get_group(group_id)
    if group is None:
        return None

    # Only accept key updates from the group admin
    if msg["from"] != group["admin_key"]:
        return None

    new_key = base64.b64decode(update["new_key"])
    if len(new_key) != 32:
        return None  # invalid key length — reject silently

    await db.update_group_key(group_id, new_key)
    return group_id


# ------------------------------------------------------------------
# group posts
# ------------------------------------------------------------------

async def post(
    db: Database,
    identity: Identity,
    group_id: str,
    plaintext: str,
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Encrypt a post with the group key, sign it, and store it locally.

    Raises LookupError if the group does not exist.
    Returns the protocol message dict ready for delivery to group members.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")

    ciphertext = crypto.encrypt_group(group["group_key"], plaintext.encode())

    msg = build_message(
        type=MSG_GROUP_POST,
        from_key=identity.public_key,
        to_key=bytes.fromhex(group_id),
        payload=ciphertext,
        private_key=identity.private_key,
        ttl=ttl,
    )

    now = int(time.time())
    await db.save_group_post(
        id=msg["id"],
        group_id=group_id,
        author_key=identity.public_key.hex(),
        payload=ciphertext,
        signature=base64.b64decode(msg["signature"]),
        timestamp=msg["timestamp"],
        expires_at=msg["timestamp"] + ttl,
    )

    return msg


async def receive_post(
    db: Database,
    identity: Identity,
    group_id: str,
    msg: dict,
) -> str:
    """Decrypt and store an incoming group post.

    msg must already be validated by validate_message() before calling this.
    Raises LookupError if the group is not known.
    Raises nacl.exceptions.CryptoError if decryption fails (wrong group key).
    Returns the decrypted plaintext.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")

    ciphertext = base64.b64decode(msg["payload"])
    plaintext = crypto.decrypt_group(group["group_key"], ciphertext).decode()

    await db.save_group_post(
        id=msg["id"],
        group_id=group_id,
        author_key=msg["from"],
        payload=ciphertext,
        signature=base64.b64decode(msg["signature"]),
        timestamp=msg["timestamp"],
        expires_at=msg["timestamp"] + msg["ttl"],
    )

    return plaintext


async def get_posts(db: Database, group_id: str) -> list[dict]:
    """Return all stored posts for a group, ordered by timestamp."""
    return await db.get_group_posts(group_id)


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _group_id(admin_key: bytes, name: str, timestamp: int) -> str:
    """Deterministic 64-hex group id."""
    data = admin_key + name.encode() + timestamp.to_bytes(8, "big")
    return hashlib.sha256(data).hexdigest()
