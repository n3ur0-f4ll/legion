
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
Format i walidacja wiadomości protokołu Legion.

Każda wiadomość sieciowa jest obiektem JSON z polami v, type, id, from, to,
payload, signature, timestamp, ttl. Moduł udostępnia funkcje do budowania
i walidacji wiadomości oraz kart kontaktowych.

Walidacja weryfikuje: strukturę, SHA256(payload)==id, TTL, podpis Ed25519.
Wiadomości z nieprawidłową sygnaturą muszą być odrzucane cicho przez warstwę
sieciową — ten moduł sygnalizuje błąd wyjątkiem, nie logując szczegółów.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any

from core import crypto

VERSION = 1
DEFAULT_TTL = 604800  # 7 days in seconds

MSG_PRIVATE = "msg"
MSG_GROUP_POST = "group_post"
MSG_GROUP_INVITE = "group_invite"
MSG_GROUP_MEMBER_UPDATE = "group_member_update"  # admin broadcasts roster change
MSG_GROUP_KEY_UPDATE = "group_key_update"         # admin broadcasts new key after rotation
MSG_DELIVERY_ACK = "delivery_ack"
MSG_CONTACT_CARD = "contact_card"

_VALID_TYPES = frozenset({
    MSG_PRIVATE, MSG_GROUP_POST, MSG_GROUP_INVITE,
    MSG_GROUP_MEMBER_UPDATE, MSG_GROUP_KEY_UPDATE,
    MSG_DELIVERY_ACK, MSG_CONTACT_CARD,
})
_REQUIRED_FIELDS = frozenset(
    {"v", "type", "id", "from", "to", "payload", "signature", "timestamp", "ttl"}
)


# ------------------------------------------------------------------
# exceptions
# ------------------------------------------------------------------

class ProtocolError(Exception):
    """Base class for all protocol validation errors."""


class InvalidSignature(ProtocolError):
    """Ed25519 signature verification failed."""


class ExpiredMessage(ProtocolError):
    """Message age exceeds its TTL."""


class InvalidMessageId(ProtocolError):
    """Message id does not match SHA256 of payload."""


class MalformedMessage(ProtocolError):
    """Message structure or encoding is invalid."""


# ------------------------------------------------------------------
# messages
# ------------------------------------------------------------------

def build_message(
    type: str,
    from_key: bytes,
    to_key: bytes,
    payload: bytes,
    private_key: bytes,
    ttl: int = DEFAULT_TTL,
) -> dict[str, Any]:
    """Build and sign a protocol message dict ready for JSON serialisation."""
    if type not in _VALID_TYPES:
        raise ValueError(f"Unknown message type: {type!r}")

    timestamp = int(time.time())
    msg_id = hashlib.sha256(payload).hexdigest()
    from_hex = from_key.hex()
    to_hex = to_key.hex()

    sig_data = _msg_sig_data(type, msg_id, from_hex, to_hex, timestamp)
    signature = crypto.sign(private_key, sig_data)

    return {
        "v": VERSION,
        "type": type,
        "id": msg_id,
        "from": from_hex,
        "to": to_hex,
        "payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(signature).decode(),
        "timestamp": timestamp,
        "ttl": ttl,
    }


def parse_message(raw: str | bytes) -> dict[str, Any]:
    """Parse JSON into a message dict.

    Raises MalformedMessage on invalid JSON or missing required fields.
    Does not verify the signature — call validate_message() for that.
    """
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedMessage(f"Invalid JSON: {exc}") from exc

    if not isinstance(msg, dict):
        raise MalformedMessage("Message must be a JSON object")

    missing = _REQUIRED_FIELDS - msg.keys()
    if missing:
        raise MalformedMessage(f"Missing fields: {sorted(missing)}")

    return msg


def validate_message(msg: dict[str, Any], now: int | None = None) -> None:
    """Validate a parsed message dict.

    Checks (in order): version, type, payload encoding, id==SHA256(payload),
    TTL, public key length, signature.

    Raises a ProtocolError subclass on any failure. The caller is responsible
    for silently dropping the message without sending a response.
    """
    if now is None:
        now = int(time.time())

    if msg.get("v") != VERSION:
        raise MalformedMessage(f"Unsupported version: {msg.get('v')!r}")

    if msg.get("type") not in _VALID_TYPES:
        raise MalformedMessage(f"Unknown type: {msg.get('type')!r}")

    try:
        payload_bytes = base64.b64decode(msg["payload"])
    except Exception as exc:
        raise MalformedMessage(f"Invalid payload encoding: {exc}") from exc

    if hashlib.sha256(payload_bytes).hexdigest() != msg["id"]:
        raise InvalidMessageId("id does not match SHA256 of payload")

    try:
        ttl = int(msg["ttl"])
        timestamp = int(msg["timestamp"])
    except (TypeError, ValueError) as exc:
        raise MalformedMessage(f"Invalid ttl/timestamp: {exc}") from exc

    _CLOCK_SKEW = 300  # accept up to 5 minutes of clock drift
    if timestamp > now + _CLOCK_SKEW:
        raise ExpiredMessage("Message has a future timestamp")
    if now - timestamp > ttl:
        raise ExpiredMessage(f"Message expired (age={now - timestamp}s, ttl={ttl}s)")

    try:
        public_key = bytes.fromhex(msg["from"])
        signature = base64.b64decode(msg["signature"])
    except Exception as exc:
        raise MalformedMessage(f"Invalid key/signature encoding: {exc}") from exc

    if len(public_key) != 32:
        raise MalformedMessage(f"Invalid public key length: {len(public_key)}")

    sig_data = _msg_sig_data(msg["type"], msg["id"], msg["from"], msg["to"], timestamp)
    try:
        crypto.verify(public_key, sig_data, signature)
    except Exception as exc:
        raise InvalidSignature("Signature verification failed") from exc


# ------------------------------------------------------------------
# contact cards
# ------------------------------------------------------------------

def build_contact_card(
    public_key: bytes,
    onion_address: str,
    private_key: bytes,
    alias_hint: str | None = None,
) -> dict[str, Any]:
    """Build a signed contact card."""
    card: dict[str, Any] = {
        "v": VERSION,
        "public_key": public_key.hex(),
        "onion_address": onion_address,
    }
    if alias_hint is not None:
        card["alias_hint"] = alias_hint

    sig_data = _card_sig_data(card)
    card["signature"] = base64.b64encode(crypto.sign(private_key, sig_data)).decode()
    return card


def validate_contact_card(card: dict[str, Any]) -> None:
    """Verify a contact card's signature.

    Raises ProtocolError on failure.
    """
    required = {"v", "public_key", "onion_address", "signature"}
    missing = required - card.keys()
    if missing:
        raise MalformedMessage(f"Missing card fields: {sorted(missing)}")

    if card.get("v") != VERSION:
        raise MalformedMessage(f"Unsupported card version: {card.get('v')!r}")

    try:
        public_key = bytes.fromhex(card["public_key"])
        signature = base64.b64decode(card["signature"])
    except Exception as exc:
        raise MalformedMessage(f"Invalid card encoding: {exc}") from exc

    if len(public_key) != 32:
        raise MalformedMessage(f"Invalid public key length: {len(public_key)}")

    card_without_sig = {k: v for k, v in card.items() if k != "signature"}
    try:
        crypto.verify(public_key, _card_sig_data(card_without_sig), signature)
    except Exception as exc:
        raise InvalidSignature("Contact card signature verification failed") from exc


# ------------------------------------------------------------------
# internal helpers
# ------------------------------------------------------------------

def _msg_sig_data(type: str, id: str, from_hex: str, to_hex: str, timestamp: int) -> bytes:
    return f"{type}|{id}|{from_hex}|{to_hex}|{timestamp}".encode()


def _card_sig_data(card: dict[str, Any]) -> bytes:
    return json.dumps(card, sort_keys=True, separators=(",", ":")).encode()
