
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
Punkt wejścia węzła Legion.

Kolejność startowania:
  1. Odczyt konfiguracji i inicjalizacja katalogów
  2. Otwarcie bazy danych
  3. Załadowanie tożsamości (hasło z terminala) lub pominięcie (pierwsze uruchomienie)
  4. Uruchomienie Tora i Hidden Service
  5. Uruchomienie serwera WebSocket (NodeServer)
  6. Uruchomienie kolejki dostarczania (DeliveryQueue)
  7. Uruchomienie lokalnego API (FastAPI / uvicorn) — blokuje do Ctrl-C
  8. Graceful shutdown w odwrotnej kolejności
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys

from api.server import AppState, make_message_handler, run_app
from config import Config
from core.identity import Identity, decrypt_private_key
from core.storage import Database
from messaging.delivery import DeliveryQueue
from network.client import NodeClientError, send_message
from network.node import NodeServer
from network.tor import TorError, TorManager

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Identity loading
# ------------------------------------------------------------------

async def _load_identity(db: Database) -> Identity | None:
    """Load and decrypt identity from DB. Returns None if not yet created."""
    row = await db.load_identity()
    if row is None:
        return None

    for attempt in range(3):
        try:
            password = getpass.getpass(
                "Enter password to unlock your Legion identity: "
            )
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        try:
            private_key = decrypt_private_key(row["private_key"], password)
            return Identity(
                public_key=bytes.fromhex(row["public_key"]),
                private_key=private_key,
                onion_address=row["onion_address"],
                alias=row["alias"],
            )
        except Exception:
            remaining = 2 - attempt
            if remaining:
                print(f"Wrong password. {remaining} attempt(s) left.")
            else:
                print("Wrong password. Exiting.")
                sys.exit(1)

    return None  # unreachable


# ------------------------------------------------------------------
# Core async entry point
# ------------------------------------------------------------------

async def _run(config: Config, interactive: bool = True) -> None:
    config.ensure_dirs()

    async with Database.open(config.db_path) as db:
        identity = await _load_identity(db) if interactive else None
        if identity is None:
            logger.info(
                "No identity loaded. Unlock via POST /api/identity/unlock."
            )

        # Sender: resolves destination and calls network client
        async def sender(msg: dict, onion: str) -> None:
            await send_message(msg, onion, socks_port=config.socks_port)

        tor = TorManager(
            config.tor_data_dir,
            socks_port=config.socks_port,
            control_port=config.control_port,
        )
        state = AppState(
            db=db,
            delivery_queue=None,
            identity=identity,
            tor_manager=tor,
            node_port=config.node_port,
        )
        dq = DeliveryQueue(db, sender=sender, on_delivered=state.on_message_delivered)
        state.delivery_queue = dq

        # NodeServer — listens for inbound WebSocket messages
        node_server = NodeServer(host="127.0.0.1", port=config.node_port)
        handler = make_message_handler(state)
        await node_server.start(handler)
        logger.info("Node server listening on port %d", config.node_port)

        # DeliveryQueue background loop
        await dq.start()

        # Interactive mode: identity loaded from DB — start Tor now synchronously
        # Non-interactive (GUI) mode: Tor starts after identity unlock via API
        if identity is not None:
            try:
                onion = await tor.start(identity.private_key, hs_port=config.node_port)
                state.tor_onion = onion
                logger.info("Hidden service: %s", onion)
            except TorError as exc:
                logger.error("Tor failed to start: %s", exc)
                logger.warning("Running without Tor — network functions unavailable")

        # API server — blocks until shutdown (Ctrl-C / SIGTERM)
        try:
            logger.info(
                "API server starting on http://127.0.0.1:%d", config.api_port
            )
            await run_app(state, config.api_port)
        finally:
            logger.info("Shutting down...")
            await dq.stop()
            await node_server.stop()
            if tor.is_running:
                await tor.stop()


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="legion-node",
        description="Legion decentralized communication node",
    )
    parser.add_argument(
        "--data-dir",
        metavar="PATH",
        help="Data directory (default: ~/.local/share/legion)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        metavar="PORT",
        help="Local API port (default: 8080)",
    )
    parser.add_argument(
        "--node-port",
        type=int,
        metavar="PORT",
        help="WebSocket node port (default: 8765)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level (default: INFO)",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Start without password prompt — GUI will unlock via /api/identity/unlock",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    config = Config.from_args(args)

    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Suppress noisy third-party loggers
    for name in ("uvicorn", "uvicorn.access", "websockets"):
        logging.getLogger(name).setLevel(logging.WARNING)

    try:
        asyncio.run(_run(config, interactive=not args.no_interactive))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
