
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


"""Tests for core/identity.py."""

import pytest
import nacl.exceptions
import nacl.signing

from core.identity import (
    Identity,
    generate,
    encrypt_private_key,
    decrypt_private_key,
    signing_key,
    derive_onion_address,
)


def test_generate_returns_identity():
    identity = generate("alice")
    assert isinstance(identity, Identity)
    assert identity.alias == "alice"


def test_generate_key_sizes():
    identity = generate("alice")
    assert len(identity.public_key) == 32
    assert len(identity.private_key) == 32


def test_generate_produces_unique_keys():
    a = generate("alice")
    b = generate("bob")
    assert a.public_key != b.public_key
    assert a.private_key != b.private_key


def test_generate_onion_address_format():
    identity = generate("alice")
    addr = identity.onion_address
    assert addr.endswith(".onion")
    host = addr[:-6]
    assert len(host) == 56
    assert host == host.lower()


def test_onion_address_is_deterministic():
    identity = generate("alice")
    assert derive_onion_address(identity.public_key) == identity.onion_address


def test_different_keys_produce_different_onion_addresses():
    a = generate("alice")
    b = generate("bob")
    assert a.onion_address != b.onion_address


def test_encrypt_decrypt_roundtrip():
    identity = generate("alice")
    blob = encrypt_private_key(identity.private_key, "correct-password")
    recovered = decrypt_private_key(blob, "correct-password")
    assert recovered == identity.private_key


def test_encrypt_produces_different_blobs_each_call():
    identity = generate("alice")
    blob1 = encrypt_private_key(identity.private_key, "password")
    blob2 = encrypt_private_key(identity.private_key, "password")
    assert blob1 != blob2  # different random salts


def test_decrypt_wrong_password_raises():
    identity = generate("alice")
    blob = encrypt_private_key(identity.private_key, "correct-password")
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt_private_key(blob, "wrong-password")


def test_decrypt_corrupted_blob_raises():
    identity = generate("alice")
    blob = bytearray(encrypt_private_key(identity.private_key, "password"))
    blob[20] ^= 0xFF  # flip a byte in the ciphertext
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt_private_key(bytes(blob), "password")


def test_encrypt_invalid_key_length_raises():
    with pytest.raises(ValueError):
        encrypt_private_key(b"too-short", "password")


def test_signing_key_reconstructed_correctly():
    identity = generate("alice")
    sk = signing_key(identity)
    assert isinstance(sk, nacl.signing.SigningKey)
    assert bytes(sk.verify_key) == identity.public_key


def test_signing_key_can_sign_and_verify():
    identity = generate("alice")
    sk = signing_key(identity)
    message = b"hello legion"
    signed = sk.sign(message)
    # verify_key reconstructed from public_key must accept the signature
    vk = nacl.signing.VerifyKey(identity.public_key)
    assert vk.verify(signed) == message


def test_identity_is_immutable():
    identity = generate("alice")
    with pytest.raises(Exception):
        identity.alias = "bob"  # type: ignore[misc]
