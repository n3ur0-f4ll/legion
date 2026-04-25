
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


"""Tests for core/protocol.py."""

import base64
import hashlib
import json
import time

import pytest

from core.identity import generate as gen
from core.protocol import (
    DEFAULT_TTL,
    MSG_GROUP_INVITE,
    MSG_GROUP_POST,
    MSG_PRIVATE,
    ExpiredMessage,
    InvalidMessageId,
    InvalidSignature,
    MalformedMessage,
    build_contact_card,
    build_message,
    parse_message,
    validate_contact_card,
    validate_message,
)

NOW = int(time.time())


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def valid_msg(type=MSG_PRIVATE, payload=b"encrypted", ttl=DEFAULT_TTL):
    alice = gen("alice")
    bob = gen("bob")
    return build_message(type, alice.public_key, bob.public_key, payload, alice.private_key, ttl)


# ------------------------------------------------------------------
# build_message
# ------------------------------------------------------------------

def test_build_message_fields():
    msg = valid_msg()
    assert msg["v"] == 1
    assert msg["type"] == MSG_PRIVATE
    assert "id" in msg
    assert "from" in msg
    assert "to" in msg
    assert "payload" in msg
    assert "signature" in msg
    assert "timestamp" in msg
    assert "ttl" in msg


def test_build_message_id_is_sha256_of_payload():
    payload = b"test payload"
    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, payload, alice.private_key)
    expected = hashlib.sha256(payload).hexdigest()
    assert msg["id"] == expected


def test_build_message_payload_is_base64():
    payload = b"some bytes"
    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, payload, alice.private_key)
    assert base64.b64decode(msg["payload"]) == payload


def test_build_message_from_to_are_hex():
    alice = gen("alice")
    bob = gen("bob")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"x", alice.private_key)
    assert bytes.fromhex(msg["from"]) == alice.public_key
    assert bytes.fromhex(msg["to"]) == bob.public_key


def test_build_message_unknown_type_raises():
    alice = gen("alice")
    bob = gen("bob")
    with pytest.raises(ValueError):
        build_message("unknown", alice.public_key, bob.public_key, b"x", alice.private_key)


def test_build_all_valid_types():
    alice = gen("alice")
    bob = gen("bob")
    from core.protocol import MSG_DELIVERY_ACK, MSG_CONTACT_CARD
    for t in (MSG_PRIVATE, MSG_GROUP_POST, MSG_GROUP_INVITE, MSG_DELIVERY_ACK, MSG_CONTACT_CARD):
        msg = build_message(t, alice.public_key, bob.public_key, b"x", alice.private_key)
        assert msg["type"] == t


# ------------------------------------------------------------------
# parse_message
# ------------------------------------------------------------------

def test_parse_message_valid():
    msg = valid_msg()
    raw = json.dumps(msg)
    parsed = parse_message(raw)
    assert parsed["v"] == 1


def test_parse_message_from_bytes():
    msg = valid_msg()
    raw = json.dumps(msg).encode()
    parsed = parse_message(raw)
    assert parsed["type"] == MSG_PRIVATE


def test_parse_message_invalid_json():
    with pytest.raises(MalformedMessage):
        parse_message("not json {{{")


def test_parse_message_not_object():
    with pytest.raises(MalformedMessage):
        parse_message("[1, 2, 3]")


def test_parse_message_missing_field():
    msg = valid_msg()
    del msg["signature"]
    with pytest.raises(MalformedMessage):
        parse_message(json.dumps(msg))


# ------------------------------------------------------------------
# validate_message — happy path
# ------------------------------------------------------------------

def test_validate_message_valid():
    msg = valid_msg()
    validate_message(msg, now=msg["timestamp"] + 10)  # must not raise


def test_validate_message_accepts_all_types():
    alice = gen("alice")
    bob = gen("bob")
    from core.protocol import MSG_DELIVERY_ACK, MSG_CONTACT_CARD
    for t in (MSG_PRIVATE, MSG_GROUP_POST, MSG_GROUP_INVITE, MSG_DELIVERY_ACK, MSG_CONTACT_CARD):
        msg = build_message(t, alice.public_key, bob.public_key, b"x", alice.private_key)
        validate_message(msg, now=msg["timestamp"] + 1)


# ------------------------------------------------------------------
# validate_message — rejection cases
# ------------------------------------------------------------------

def test_validate_rejects_wrong_version():
    msg = valid_msg()
    msg["v"] = 99
    with pytest.raises(MalformedMessage):
        validate_message(msg)


def test_validate_rejects_unknown_type():
    msg = valid_msg()
    msg["type"] = "bogus"
    with pytest.raises(MalformedMessage):
        validate_message(msg)


def test_validate_rejects_expired_message():
    msg = valid_msg(ttl=60)
    with pytest.raises(ExpiredMessage):
        validate_message(msg, now=msg["timestamp"] + 61)


def test_validate_rejects_tampered_payload():
    msg = valid_msg()
    # Change payload — id will no longer match
    msg["payload"] = base64.b64encode(b"tampered").decode()
    with pytest.raises(InvalidMessageId):
        validate_message(msg)


def test_validate_rejects_wrong_id():
    msg = valid_msg()
    msg["id"] = "a" * 64  # wrong SHA256
    with pytest.raises(InvalidMessageId):
        validate_message(msg)


def test_validate_rejects_tampered_signature():
    msg = valid_msg()
    sig = bytearray(base64.b64decode(msg["signature"]))
    sig[0] ^= 0xFF
    msg["signature"] = base64.b64encode(bytes(sig)).decode()
    with pytest.raises(InvalidSignature):
        validate_message(msg)


def test_validate_rejects_wrong_sender_key():
    alice = gen("alice")
    bob = gen("bob")
    eve = gen("eve")
    msg = build_message(MSG_PRIVATE, alice.public_key, bob.public_key, b"x", alice.private_key)
    # Swap `from` to eve — signature won't verify
    msg["from"] = eve.public_key.hex()
    with pytest.raises(InvalidSignature):
        validate_message(msg, now=msg["timestamp"] + 1)


def test_validate_rejects_invalid_payload_encoding():
    msg = valid_msg()
    msg["payload"] = "not base64!!!"
    with pytest.raises(MalformedMessage):
        validate_message(msg)


def test_validate_rejects_invalid_key_encoding():
    msg = valid_msg()
    msg["from"] = "not-hex"
    with pytest.raises(MalformedMessage):
        validate_message(msg)


def test_validate_rejects_short_public_key():
    msg = valid_msg()
    msg["from"] = b"\x01".hex()  # 1 byte
    with pytest.raises(MalformedMessage):
        validate_message(msg)


# ------------------------------------------------------------------
# contact cards
# ------------------------------------------------------------------

def test_build_contact_card_fields():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    assert card["v"] == 1
    assert card["public_key"] == alice.public_key.hex()
    assert card["onion_address"] == alice.onion_address
    assert "signature" in card
    assert "alias_hint" not in card


def test_build_contact_card_with_alias_hint():
    alice = gen("alice")
    card = build_contact_card(
        alice.public_key, alice.onion_address, alice.private_key, alias_hint="Alice"
    )
    assert card["alias_hint"] == "Alice"


def test_validate_contact_card_valid():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    validate_contact_card(card)  # must not raise


def test_validate_contact_card_with_alias_hint():
    alice = gen("alice")
    card = build_contact_card(
        alice.public_key, alice.onion_address, alice.private_key, alias_hint="Alice"
    )
    validate_contact_card(card)


def test_validate_contact_card_tampered_address():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    card["onion_address"] = "evil.onion"
    with pytest.raises(InvalidSignature):
        validate_contact_card(card)


def test_validate_contact_card_tampered_key():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    card["public_key"] = gen("bob").public_key.hex()
    with pytest.raises(InvalidSignature):
        validate_contact_card(card)


def test_validate_contact_card_missing_field():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    del card["onion_address"]
    with pytest.raises(MalformedMessage):
        validate_contact_card(card)


def test_validate_contact_card_wrong_version():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    card["v"] = 0
    with pytest.raises(MalformedMessage):
        validate_contact_card(card)


def test_validate_contact_card_short_key():
    alice = gen("alice")
    card = build_contact_card(alice.public_key, alice.onion_address, alice.private_key)
    card["public_key"] = b"\x01".hex()
    with pytest.raises(MalformedMessage):
        validate_contact_card(card)
