
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
Wysyłanie wiadomości przez węzeł pośredniczący (relay).

Relay to osobna, stale online instancja legion-relay skonfigurowana przez
użytkownika. Zamiast próbować dostarczyć wiadomość bezpośrednio (ryzyko
że odbiorca jest offline), nadawca wysyła ją do swojego relay, który
próbuje dostarczyć 24/7.

Ten moduł odpowiada wyłącznie za stronę nadawcy:
- sprawdzenie konfiguracji relay
- wysłanie wiadomości na adres relay przez Tora

Logika wyboru między relay a bezpośrednim dostarczeniem należy do warstwy API.
"""

from __future__ import annotations

from network.client import NodeClientError, send_message
from core.storage import Database


class RelayError(Exception):
    """Raised when relay is not usable (not configured, disabled, or unreachable)."""


async def is_relay_configured(db: Database) -> bool:
    """Return True if a relay is configured and enabled."""
    config = await db.load_relay_config()
    return config is not None and bool(config["enabled"])


async def get_relay_onion(db: Database) -> str:
    """Return the relay's onion address.

    Raises RelayError if no relay is configured or it is disabled.
    """
    config = await db.load_relay_config()
    if config is None:
        raise RelayError("No relay configured")
    if not config["enabled"]:
        raise RelayError("Relay is disabled")
    return config["onion_address"]


async def send_via_relay(
    db: Database,
    msg: dict,
    *,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9050,
) -> None:
    """Send a message to the configured relay node.

    The relay is responsible for forwarding the message to msg["to"].
    Raises RelayError if relay is not usable.
    Raises NodeClientError if the relay is unreachable.
    """
    relay_onion = await get_relay_onion(db)
    await send_message(
        msg,
        relay_onion,
        socks_host=socks_host,
        socks_port=socks_port,
    )


async def choose_destination(
    db: Database,
    recipient_onion: str,
) -> tuple[str, bool]:
    """Return (destination_onion, via_relay) for sending a message.

    If relay is configured: destination = relay onion, via_relay = True.
    Otherwise:             destination = recipient onion, via_relay = False.
    """
    config = await db.load_relay_config()
    if config is not None and bool(config["enabled"]):
        return config["onion_address"], True
    return recipient_onion, False
