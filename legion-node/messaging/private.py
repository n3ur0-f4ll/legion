
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

Payload szyfrowanego pakietu to JSON envelope:
  {"t": "tekst wiadomości"}                          ← wiadomość tekstowa
  {"f": "<base64>", "n": "plik.jpg", "m": "image/jpeg"} ← plik/obraz

Sanityzacja odbywa się na OBU końcach: nadawca przed szyfrowaniem,
odbiorca po odszyfrowaniu (obrona warstwowa).
"""

from __future__ import annotations

import base64
import json

from core import crypto
from core.identity import Identity
from core.protocol import MSG_PRIVATE, DEFAULT_TTL, build_message
from core.storage import Database
from messaging.files import FileError, prepare_outgoing, sanitize_incoming


def _encode_payload(text: str | None, file_data: bytes | None,
                    file_name: str | None, mime_type: str | None) -> bytes:
    if file_data is not None:
        return json.dumps({
            "f": base64.b64encode(file_data).decode(),
            "n": file_name,
            "m": mime_type,
        }).encode()
    return json.dumps({"t": text or ""}).encode()


def _decode_payload(raw: bytes) -> dict:
    """Decode payload envelope. Returns dict with 't' or 'f'/'n'/'m' keys.
    Falls back gracefully for legacy raw-text payloads.
    """
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and ("t" in data or "f" in data):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    # Legacy: raw text payload
    return {"t": raw.decode(errors="replace")}


async def send(
    db: Database,
    identity: Identity,
    recipient_public_key: bytes,
    plaintext: str,
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Encrypt a text message and build a signed protocol message."""
    payload_bytes = _encode_payload(plaintext, None, None, None)
    ciphertext = crypto.encrypt(identity.private_key, recipient_public_key, payload_bytes)

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


async def send_file(
    db: Database,
    identity: Identity,
    recipient_public_key: bytes,
    file_data: bytes,
    file_name: str,
    mime_type: str,
    ttl: int = DEFAULT_TTL,
) -> dict:
    """Sanitize, encrypt and send a file. Raises FileError on invalid input."""
    sanitized = prepare_outgoing(file_data, file_name, mime_type)
    payload_bytes = _encode_payload(None, sanitized, file_name, mime_type)
    ciphertext = crypto.encrypt(identity.private_key, recipient_public_key, payload_bytes)

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
        file_name=file_name,
        mime_type=mime_type,
    )
    return msg


async def receive(
    db: Database,
    identity: Identity,
    msg: dict,
) -> dict:
    """Decrypt and store an incoming message. Returns payload dict with 't' or 'f'/'n'/'m'.

    Sanitizes incoming files server-side (defense-in-depth).
    Raises ValueError if the message is not addressed to this identity.
    """
    if msg["to"] != identity.public_key.hex():
        raise ValueError("Message is not addressed to this identity")

    sender_public_key = bytes.fromhex(msg["from"])
    ciphertext = base64.b64decode(msg["payload"])
    raw = crypto.decrypt(identity.private_key, sender_public_key, ciphertext)
    payload = _decode_payload(raw)

    file_name = mime_type = None
    if "f" in payload:
        # Sanitize received file on the receiver side
        try:
            file_bytes = base64.b64decode(payload["f"])
            mime_type = payload.get("m", "application/octet-stream")
            file_name = payload.get("n", "file")
            sanitized = sanitize_incoming(file_bytes, mime_type)
            payload["f"] = base64.b64encode(sanitized).decode()
        except (FileError, Exception):
            payload = {"t": "[file could not be processed]"}
            file_name = mime_type = None

    await db.save_message(
        id=msg["id"],
        from_key=msg["from"],
        to_key=msg["to"],
        payload=ciphertext,
        signature=base64.b64decode(msg["signature"]),
        timestamp=msg["timestamp"],
        expires_at=msg["timestamp"] + msg["ttl"],
        status="delivered",
        file_name=file_name,
        mime_type=mime_type,
    )
    await db.update_message_status(msg["id"], "delivered")
    return payload


async def get_conversation(
    db: Database,
    our_key: bytes,
    peer_key: bytes,
) -> list[dict]:
    return await db.get_messages(peer_key.hex(), our_key.hex())
