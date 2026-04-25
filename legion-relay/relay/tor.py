
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
Zarządzanie procesem Tor i Hidden Service relay.

Relay ma własną tożsamość Ed25519 (adres .onion determinowany przez klucz).
Klucz prywatny przechowywany bez szyfrowania — relay działa jako serwis
bez interakcji użytkownika.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import pathlib
import time
from typing import Any

import nacl.signing

import stem.control
import stem.process

from relay.storage import Database

logger = logging.getLogger(__name__)

_BOOTSTRAP_TIMEOUT = 120


class TorError(Exception):
    """Raised when Tor fails to start or create Hidden Service."""


class TorManager:
    def __init__(
        self,
        data_dir: pathlib.Path,
        socks_port: int = 9050,
        control_port: int = 9051,
    ) -> None:
        self._data_dir = data_dir
        self._socks_port = socks_port
        self._control_port = control_port
        self._process: Any = None
        self._controller: stem.control.Controller | None = None
        self._onion_address: str | None = None

    @property
    def onion_address(self) -> str:
        if self._onion_address is None:
            raise TorError("Tor is not running — call start() first")
        return self._onion_address

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._controller is not None

    async def start(self, private_key: bytes, hs_port: int) -> str:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_event_loop()

        try:
            self._process = await loop.run_in_executor(None, self._launch)
        except Exception as exc:
            raise TorError(f"Failed to launch Tor: {exc}") from exc

        try:
            self._controller = await loop.run_in_executor(
                None,
                lambda: stem.control.Controller.from_port(port=self._control_port),
            )
            await loop.run_in_executor(None, self._controller.authenticate)
        except Exception as exc:
            await self.stop()
            raise TorError(f"Failed to connect to controller: {exc}") from exc

        try:
            onion = await loop.run_in_executor(
                None, lambda: self._create_hs(private_key, hs_port)
            )
        except Exception as exc:
            await self.stop()
            raise TorError(f"Failed to create Hidden Service: {exc}") from exc

        self._onion_address = onion
        logger.info("Relay hidden service: %s", onion)
        return onion

    async def stop(self) -> None:
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            self._process = None

        self._onion_address = None

    def _launch(self):
        return stem.process.launch_tor_with_config(
            config={
                "SocksPort": str(self._socks_port),
                "ControlPort": str(self._control_port),
                "DataDirectory": str(self._data_dir),
                "Log": "notice stderr",
                "ExitPolicy": "reject *:*",
            },
            timeout=_BOOTSTRAP_TIMEOUT,
            take_ownership=True,
        )

    def _create_hs(self, private_key: bytes, hs_port: int) -> str:
        expanded = _ed25519_seed_to_expanded(private_key)
        key_b64 = base64.b64encode(expanded).decode()
        response = self._controller.create_ephemeral_hidden_service(
            ports={80: hs_port},
            key_type="ED25519-V3",
            key_content=key_b64,
            await_publication=True,
        )
        return response.service_id + ".onion"


# ------------------------------------------------------------------
# Identity generation
# ------------------------------------------------------------------

def generate_identity() -> tuple[bytes, bytes, str]:
    """Generate Ed25519 key pair for relay. Returns (public_key, private_key, onion_address)."""
    sk = nacl.signing.SigningKey.generate()
    public_key = bytes(sk.verify_key)
    private_key = bytes(sk)
    onion_address = _derive_onion_address(public_key)
    return public_key, private_key, onion_address


async def load_or_create_identity(db: Database) -> tuple[bytes, bytes, str]:
    """Load existing relay identity or generate a new one."""
    row = await db.load_identity()
    if row is not None:
        return bytes.fromhex(row["public_key"]), row["private_key"], row["onion_address"]

    public_key, private_key, onion_address = generate_identity()
    await db.save_identity(
        public_key=public_key.hex(),
        private_key=private_key,
        onion_address=onion_address,
        created_at=int(time.time()),
    )
    logger.info("Generated relay identity: %s", onion_address)
    return public_key, private_key, onion_address


def _ed25519_seed_to_expanded(seed: bytes) -> bytes:
    """64-byte expanded Ed25519 private key — Tor ADD_ONION ED25519-V3 format."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def _derive_onion_address(public_key: bytes) -> str:
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    import base64 as _b64
    return _b64.b32encode(public_key + checksum + version).decode().lower() + ".onion"
