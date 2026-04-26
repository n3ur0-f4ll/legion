
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
Zarządzanie procesem Tor i Hidden Service.

Uruchamia Tora jako subprocess, czeka na pełny bootstrap, tworzy v3 Hidden
Service używając klucza Ed25519 tożsamości użytkownika. Adres .onion jest
deterministyczny — wynika z klucza, nie z losowości Tora.

Blokujące operacje Stem są uruchamiane w executor, żeby nie blokować pętli zdarzeń.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import pathlib
import time
from typing import Any

import stem.control
import stem.process

logger = logging.getLogger(__name__)

_BOOTSTRAP_TIMEOUT = 120  # seconds


class TorError(Exception):
    """Raised when Tor fails to start, bootstrap, or operate."""


class TorManager:
    """Manages the Tor subprocess and a v3 Hidden Service for this node."""

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
    def socks_port(self) -> int:
        return self._socks_port

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._controller is not None

    async def start(self, private_key: bytes, hs_port: int) -> str:
        """Launch Tor, wait for full bootstrap, create v3 Hidden Service.

        private_key: 32-byte Ed25519 seed from the user's Identity.
        hs_port: local port the WebSocket server will listen on.

        Returns the .onion address (matches identity.onion_address).
        Raises TorError on any failure.
        """
        self._data_dir.mkdir(parents=True, exist_ok=True)
        loop = asyncio.get_running_loop()

        try:
            self._process = await asyncio.wait_for(
                loop.run_in_executor(None, self._launch),
                timeout=_BOOTSTRAP_TIMEOUT,
            )
        except asyncio.TimeoutError as exc:
            raise TorError("Tor failed to bootstrap within timeout") from exc
        except Exception as exc:
            raise TorError(f"Failed to launch Tor process: {exc}") from exc

        try:
            self._controller = await loop.run_in_executor(
                None,
                lambda: stem.control.Controller.from_port(port=self._control_port),
            )
            await loop.run_in_executor(None, self._controller.authenticate)
        except Exception as exc:
            await self.stop()
            raise TorError(f"Failed to connect to Tor controller: {exc}") from exc

        try:
            onion = await loop.run_in_executor(
                None, lambda: self._create_hidden_service(private_key, hs_port)
            )
        except Exception as exc:
            await self.stop()
            raise TorError(f"Failed to create Hidden Service: {exc}") from exc

        self._onion_address = onion
        logger.info("Tor running, hidden service: %s", onion)
        return onion

    async def stop(self) -> None:
        """Shut down the controller connection and Tor process."""
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

    # ------------------------------------------------------------------
    # internal — broken out for testability
    # ------------------------------------------------------------------

    def _launch(self):
        """Start the Tor subprocess and wait for full bootstrap.

        No timeout here — stem's timeout uses signal.alarm() which is
        restricted to the main thread. Timeout is handled by asyncio.wait_for
        in start() instead.
        """
        return stem.process.launch_tor_with_config(
            config={
                "SocksPort": str(self._socks_port),
                "ControlPort": str(self._control_port),
                "DataDirectory": str(self._data_dir),
                "Log": "notice stderr",
                "ExitPolicy": "reject *:*",
            },
            take_ownership=True,
        )

    def _create_hidden_service(self, private_key: bytes, hs_port: int) -> str:
        """Register ephemeral v3 HS with Tor. Returns '<service_id>.onion'."""
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
# pure helper — public for testing
# ------------------------------------------------------------------

def _ed25519_seed_to_expanded(seed: bytes) -> bytes:
    """Derive the 64-byte expanded Ed25519 private key from a 32-byte seed.

    This is the key format Tor expects for ADD_ONION ED25519-V3.
    The resulting public key is identical to nacl.signing.SigningKey(seed).verify_key,
    so the onion address matches identity.derive_onion_address(public_key).
    """
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)
