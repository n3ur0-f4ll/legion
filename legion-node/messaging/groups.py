
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
Logika grup: tworzenie, zaproszenia, posty.

Grupa to wspólny klucz symetryczny (SecretBox) znany wszystkim członkom.
Admin tworzy grupę i szyfruje klucz grupy kluczem publicznym każdego nowego członka.
Posty grupowe są szyfrowane kluczem grupy i podpisane kluczem autora.
Rotacja klucza jest wymagana gdy członek opuszcza grupę.
"""

from __future__ import annotations

import base64
import hashlib
import time

from core import crypto
from core.identity import Identity
from core.protocol import (
    MSG_GROUP_INVITE,
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
    await db.save_group_member(group_id, identity.public_key.hex(), now)

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
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Build a signed group_invite message carrying the group key encrypted for the new member.

    Raises PermissionError if the caller is not the group admin.
    Raises LookupError if the group does not exist.
    Returns the protocol message dict ready for delivery.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")
    if group["admin_key"] != identity.public_key.hex():
        raise PermissionError("Only the group admin can invite members")

    # Encrypt the group key with the new member's public key
    encrypted_key = crypto.encrypt(
        identity.private_key, member_public_key, group["group_key"]
    )

    # Pack group metadata + encrypted key into the invite payload
    invite_payload = _pack_invite(group_id, group["name"], encrypted_key)

    msg = build_message(
        type=MSG_GROUP_INVITE,
        from_key=identity.public_key,
        to_key=member_public_key,
        payload=invite_payload,
        private_key=identity.private_key,
        ttl=ttl,
    )

    return msg


async def accept_invite(
    db: Database,
    identity: Identity,
    msg: dict,
) -> dict:
    """Process an incoming group_invite message and store the group locally.

    msg must already be validated by validate_message() before calling this.
    Raises ValueError if the invite is malformed or not addressed to this identity.
    Returns the stored group record.
    """
    if msg["to"] != identity.public_key.hex():
        raise ValueError("Invite is not addressed to this identity")

    sender_public_key = bytes.fromhex(msg["from"])
    invite_payload = base64.b64decode(msg["payload"])

    group_id, group_name, encrypted_key = _unpack_invite(invite_payload)
    group_key = crypto.decrypt(identity.private_key, sender_public_key, encrypted_key)

    now = int(time.time())
    await db.save_group(
        id=group_id,
        name=group_name,
        group_key=group_key,
        admin_key=msg["from"],
        is_admin=False,
        created_at=now,
    )
    await db.save_group_member(group_id, identity.public_key.hex(), now)

    return {
        "id": group_id,
        "name": group_name,
        "group_key": group_key,
        "admin_key": msg["from"],
        "is_admin": False,
        "created_at": now,
    }


async def remove_member(
    db: Database,
    identity: Identity,
    group_id: str,
    member_public_key: bytes,
) -> bytes:
    """Remove a member and rotate the group key.

    Raises PermissionError if the caller is not the group admin.
    Returns the new group key — admin must re-invite remaining members.
    """
    group = await db.get_group(group_id)
    if group is None:
        raise LookupError(f"Group {group_id!r} not found")
    if group["admin_key"] != identity.public_key.hex():
        raise PermissionError("Only the group admin can remove members")

    await db.delete_group_member(group_id, member_public_key.hex())

    new_key = crypto.generate_group_key()
    await db.save_group(
        id=group_id,
        name=group["name"],
        group_key=new_key,
        admin_key=group["admin_key"],
        is_admin=True,
        created_at=group["created_at"],
    )

    return new_key


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
        to_key=bytes.fromhex(group_id) if len(group_id) == 64 else _group_id_bytes(group_id),
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
# internal helpers
# ------------------------------------------------------------------

def _group_id(admin_key: bytes, name: str, timestamp: int) -> str:
    """Deterministic 64-hex group id."""
    data = admin_key + name.encode() + timestamp.to_bytes(8, "big")
    return hashlib.sha256(data).hexdigest()


def _group_id_bytes(group_id: str) -> bytes:
    """Return 32-byte representation of a group_id for use as 'to' key in protocol."""
    return bytes.fromhex(group_id)


def _pack_invite(group_id: str, group_name: str, encrypted_key: bytes) -> bytes:
    """Pack invite fields into a binary payload.

    Format: [1B group_id_len][group_id][2B name_len][name][encrypted_key]
    group_id is always 64 hex chars = 64 bytes ASCII.
    """
    gid_b = group_id.encode()
    name_b = group_name.encode()
    return (
        len(gid_b).to_bytes(1, "big")
        + gid_b
        + len(name_b).to_bytes(2, "big")
        + name_b
        + encrypted_key
    )


def _unpack_invite(data: bytes) -> tuple[str, str, bytes]:
    """Unpack binary invite payload. Returns (group_id, group_name, encrypted_key)."""
    offset = 0
    gid_len = data[offset]
    offset += 1
    group_id = data[offset : offset + gid_len].decode()
    offset += gid_len
    name_len = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    group_name = data[offset : offset + name_len].decode()
    offset += name_len
    encrypted_key = data[offset:]
    return group_id, group_name, encrypted_key
