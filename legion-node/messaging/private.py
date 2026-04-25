
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
Wiadomości prywatne między użytkownikami.

Odpowiada za szyfrowanie treści kluczem publicznym odbiorcy, budowanie
gotowego pakietu protokołu oraz odszyfrowywanie wiadomości przychodzących.
Warstwa ta nie zajmuje się transportem — korzysta z core/crypto i core/protocol.
"""

from __future__ import annotations

import base64

from core import crypto
from core.identity import Identity
from core.protocol import MSG_PRIVATE, DEFAULT_TTL, build_message, validate_message
from core.storage import Database


async def send(
    db: Database,
    identity: Identity,
    recipient_public_key: bytes,
    plaintext: str,
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Encrypt plaintext and build a signed protocol message.

    Stores the message in the database with status 'queued'.
    Returns the ready-to-send message dict.
    """
    ciphertext = crypto.encrypt(identity.private_key, recipient_public_key, plaintext.encode())

    msg = build_message(
        type=MSG_PRIVATE,
        from_key=identity.public_key,
        to_key=recipient_public_key,
        payload=ciphertext,
        private_key=identity.private_key,
        ttl=ttl,
    )

    await db.save_message(
        id=msg["id"],
        from_key=msg["from"],
        to_key=msg["to"],
        payload=ciphertext,
        signature=base64.b64decode(msg["signature"]),
        timestamp=msg["timestamp"],
        expires_at=msg["timestamp"] + ttl,
        status="queued",
    )

    return msg


async def receive(
    db: Database,
    identity: Identity,
    msg: dict,
) -> str:
    """Decrypt and store an incoming private message.

    msg must already be validated by validate_message() before calling this.
    Returns the decrypted plaintext.
    Raises ValueError if the message is not addressed to this identity.
    """
    if msg["to"] != identity.public_key.hex():
        raise ValueError("Message is not addressed to this identity")

    sender_public_key = bytes.fromhex(msg["from"])
    ciphertext = base64.b64decode(msg["payload"])

    plaintext = crypto.decrypt(identity.private_key, sender_public_key, ciphertext).decode()

    sig_bytes = base64.b64decode(msg["signature"])

    await db.save_message(
        id=msg["id"],
        from_key=msg["from"],
        to_key=msg["to"],
        payload=ciphertext,
        signature=sig_bytes,
        timestamp=msg["timestamp"],
        expires_at=msg["timestamp"] + msg["ttl"],
        status="delivered",
    )
    await db.update_message_status(msg["id"], "delivered")

    return plaintext


async def get_conversation(
    db: Database,
    our_key: bytes,
    peer_key: bytes,
) -> list[dict]:
    """Return all stored messages between this node and a peer, ordered by timestamp."""
    return await db.get_messages(peer_key.hex(), our_key.hex())
