
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
Operacje kryptograficzne Legion.

Podpisywanie: Ed25519 (nacl.signing).
Szyfrowanie prywatne: X25519 + XSalsa20-Poly1305 (Box).
Szyfrowanie grupowe: XSalsa20-Poly1305 (SecretBox).

Klucze tożsamości są Ed25519 — konwersja do Curve25519 odbywa się wewnętrznie
i jest przezroczysta dla reszty systemu.
"""

import nacl.bindings
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


def sign(private_key: bytes, data: bytes) -> bytes:
    """Sign data with an Ed25519 private key seed. Returns 64-byte signature."""
    return bytes(nacl.signing.SigningKey(private_key).sign(data).signature)


def verify(public_key: bytes, data: bytes, signature: bytes) -> None:
    """Verify an Ed25519 signature.

    Raises nacl.exceptions.BadSignatureError if the signature is invalid.
    """
    nacl.signing.VerifyKey(public_key).verify(data, signature)


def encrypt(sender_private_key: bytes, recipient_public_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with X25519+XSalsa20-Poly1305 (Box).

    Both keys are Ed25519 — converted to Curve25519 internally.
    Returns nonce + ciphertext.
    """
    box = _make_box(sender_private_key, recipient_public_key)
    return bytes(box.encrypt(plaintext))


def decrypt(recipient_private_key: bytes, sender_public_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext produced by encrypt().

    Raises nacl.exceptions.CryptoError if the ciphertext is invalid or tampered.
    """
    box = _make_box(recipient_private_key, sender_public_key)
    return bytes(box.decrypt(ciphertext))


def encrypt_group(group_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext with a symmetric group key (SecretBox).

    Returns nonce + ciphertext.
    """
    return bytes(nacl.secret.SecretBox(group_key).encrypt(plaintext))


def decrypt_group(group_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext produced by encrypt_group().

    Raises nacl.exceptions.CryptoError if the ciphertext is invalid or tampered.
    """
    return bytes(nacl.secret.SecretBox(group_key).decrypt(ciphertext))


def generate_group_key() -> bytes:
    """Generate a random 32-byte symmetric key for a group."""
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


def _make_box(our_private_key: bytes, their_public_key: bytes) -> nacl.public.Box:
    our_curve_sk = _ed25519_seed_to_curve25519(our_private_key)
    their_curve_pk = _ed25519_pk_to_curve25519(their_public_key)
    return nacl.public.Box(
        nacl.public.PrivateKey(our_curve_sk),
        nacl.public.PublicKey(their_curve_pk),
    )


def _ed25519_seed_to_curve25519(seed: bytes) -> bytes:
    signing_key = nacl.signing.SigningKey(seed)
    extended = bytes(signing_key) + bytes(signing_key.verify_key)
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(extended)


def _ed25519_pk_to_curve25519(public_key: bytes) -> bytes:
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)
