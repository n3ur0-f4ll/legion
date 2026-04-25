
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


"""Tests for core/crypto.py."""

import pytest
import nacl.exceptions
import nacl.signing

from core.crypto import (
    sign,
    verify,
    encrypt,
    decrypt,
    encrypt_group,
    decrypt_group,
    generate_group_key,
)
from core.identity import generate as generate_identity


# --- signing ---

def test_sign_returns_64_bytes():
    identity = generate_identity("alice")
    sig = sign(identity.private_key, b"hello")
    assert len(sig) == 64


def test_verify_valid_signature():
    identity = generate_identity("alice")
    data = b"hello legion"
    sig = sign(identity.private_key, data)
    verify(identity.public_key, data, sig)  # must not raise


def test_verify_wrong_data_raises():
    identity = generate_identity("alice")
    sig = sign(identity.private_key, b"hello")
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify(identity.public_key, b"tampered", sig)


def test_verify_wrong_key_raises():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    sig = sign(alice.private_key, b"hello")
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify(bob.public_key, b"hello", sig)


def test_verify_corrupted_signature_raises():
    identity = generate_identity("alice")
    data = b"hello"
    sig = bytearray(sign(identity.private_key, data))
    sig[0] ^= 0xFF
    with pytest.raises(nacl.exceptions.BadSignatureError):
        verify(identity.public_key, data, bytes(sig))


# --- asymmetric encryption ---

def test_encrypt_decrypt_roundtrip():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    plaintext = b"secret message"
    ciphertext = encrypt(alice.private_key, bob.public_key, plaintext)
    recovered = decrypt(bob.private_key, alice.public_key, ciphertext)
    assert recovered == plaintext


def test_encrypt_is_not_plaintext():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    plaintext = b"secret message"
    ciphertext = encrypt(alice.private_key, bob.public_key, plaintext)
    assert plaintext not in ciphertext


def test_encrypt_produces_different_ciphertexts():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    plaintext = b"secret"
    c1 = encrypt(alice.private_key, bob.public_key, plaintext)
    c2 = encrypt(alice.private_key, bob.public_key, plaintext)
    assert c1 != c2  # random nonce each time


def test_decrypt_wrong_key_raises():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    eve = generate_identity("eve")
    ciphertext = encrypt(alice.private_key, bob.public_key, b"secret")
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt(eve.private_key, alice.public_key, ciphertext)


def test_decrypt_tampered_ciphertext_raises():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ct = bytearray(encrypt(alice.private_key, bob.public_key, b"secret"))
    ct[-1] ^= 0xFF
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt(bob.private_key, alice.public_key, bytes(ct))


def test_encrypt_decrypt_empty_payload():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ciphertext = encrypt(alice.private_key, bob.public_key, b"")
    assert decrypt(bob.private_key, alice.public_key, ciphertext) == b""


# --- group (symmetric) encryption ---

def test_generate_group_key_length():
    key = generate_group_key()
    assert len(key) == 32


def test_generate_group_key_is_random():
    assert generate_group_key() != generate_group_key()


def test_encrypt_decrypt_group_roundtrip():
    key = generate_group_key()
    plaintext = b"group post content"
    ciphertext = encrypt_group(key, plaintext)
    assert decrypt_group(key, ciphertext) == plaintext


def test_encrypt_group_produces_different_ciphertexts():
    key = generate_group_key()
    c1 = encrypt_group(key, b"post")
    c2 = encrypt_group(key, b"post")
    assert c1 != c2


def test_decrypt_group_wrong_key_raises():
    key = generate_group_key()
    wrong_key = generate_group_key()
    ciphertext = encrypt_group(key, b"secret")
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt_group(wrong_key, ciphertext)


def test_decrypt_group_tampered_raises():
    key = generate_group_key()
    ct = bytearray(encrypt_group(key, b"secret"))
    ct[-1] ^= 0xFF
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt_group(key, bytes(ct))
