
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
Zarządzanie tożsamością użytkownika Legion.

Tożsamość to para kluczy Ed25519. Klucz prywatny jest zawsze szyfrowany
przed zapisem (Argon2id + SecretBox). Adres .onion jest wyznaczany
deterministycznie z klucza publicznego (Tor v3 Hidden Service).
"""

import base64
import hashlib
from dataclasses import dataclass

import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils

_SALT_SIZE = nacl.pwhash.argon2id.SALTBYTES  # 16 bytes
_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE    # 32 bytes

_ARGON2_OPS = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
_ARGON2_MEM = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE


@dataclass(frozen=True)
class Identity:
    public_key: bytes   # 32 bytes — network identifier
    private_key: bytes  # 32 bytes seed — never leaves the device in plaintext
    onion_address: str  # v3 .onion address
    alias: str          # local display name


def generate(alias: str) -> Identity:
    """Generate a new Ed25519 identity with a random key pair."""
    signing_key = nacl.signing.SigningKey.generate()
    public_key = bytes(signing_key.verify_key)
    private_key = bytes(signing_key)
    return Identity(
        public_key=public_key,
        private_key=private_key,
        onion_address=derive_onion_address(public_key),
        alias=alias,
    )


def encrypt_private_key(private_key: bytes, password: str) -> bytes:
    """Encrypt a 32-byte private key seed with a password.

    Returns salt (16 bytes) + SecretBox ciphertext.
    Raises ValueError if private_key is not 32 bytes.
    """
    if len(private_key) != 32:
        raise ValueError(f"private_key must be 32 bytes, got {len(private_key)}")
    salt = nacl.utils.random(_SALT_SIZE)
    derived_key = _derive_key(password, salt)
    ciphertext = nacl.secret.SecretBox(derived_key).encrypt(private_key)
    return salt + bytes(ciphertext)


def decrypt_private_key(blob: bytes, password: str) -> bytes:
    """Decrypt a blob produced by encrypt_private_key.

    Returns the 32-byte private key seed.
    Raises nacl.exceptions.CryptoError on wrong password or corrupted blob.
    """
    salt = blob[:_SALT_SIZE]
    ciphertext = blob[_SALT_SIZE:]
    derived_key = _derive_key(password, salt)
    return bytes(nacl.secret.SecretBox(derived_key).decrypt(ciphertext))


def signing_key(identity: Identity) -> nacl.signing.SigningKey:
    """Reconstruct a SigningKey from the identity's private key seed."""
    return nacl.signing.SigningKey(identity.private_key)


def derive_onion_address(public_key: bytes) -> str:
    """Derive a Tor v3 .onion address from a 32-byte Ed25519 public key.

    Tor v3 spec: address = base32(pubkey || checksum || version) + ".onion"
    where checksum = SHA3-256(".onion checksum" || pubkey || version)[0:2]
    and version = 0x03.
    """
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"


def _derive_key(password: str, salt: bytes) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        _KEY_SIZE,
        password.encode(),
        salt,
        opslimit=_ARGON2_OPS,
        memlimit=_ARGON2_MEM,
    )
