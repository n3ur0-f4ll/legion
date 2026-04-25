
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
Punkt wejścia węzła relay Legion.

Kolejność startowania:
  1. Konfiguracja i katalogi
  2. Baza danych
  3. Tożsamość relay (generowana przy pierwszym uruchomieniu)
  4. Kolejka dostarczania (DeliveryQueue)
  5. Cleanup (periodic TTL sweep)
  6. Serwer WebSocket (RelayServer)
  7. Tor i Hidden Service — blokuje do Ctrl-C
  8. Graceful shutdown
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from config import Config
from relay.cleanup import Cleanup
from relay.delivery import DeliveryQueue
from relay.server import RelayServer
from relay.storage import Database
from relay.tor import TorError, TorManager, load_or_create_identity

logger = logging.getLogger(__name__)


async def _run(config: Config) -> None:
    config.ensure_dirs()

    async with Database.open(config.db_path) as db:
        public_key, private_key, onion_address = await load_or_create_identity(db)
        logger.info("Relay identity: %s", onion_address)
        logger.info("Relay public key: %s", public_key.hex())

        dq = DeliveryQueue(
            db,
            socks_port=config.socks_port,
            hs_port=80,
        )

        cleanup = Cleanup(db, interval=config.cleanup_interval)

        async def send_handler(message_id, sender_key, for_key, destination_onion, payload, expires_at):
            # Check message count limit
            count = await db.count_queued()
            if count >= config.max_stored_messages:
                logger.warning("Message limit reached (%d), rejecting new message", count)
                return
            await dq.enqueue(message_id, sender_key, for_key, destination_onion, payload, expires_at)

        server = RelayServer(host="127.0.0.1", port=config.relay_port)
        await server.start(db, send_handler)

        await dq.start()
        await cleanup.start()

        tor = TorManager(
            config.tor_data_dir,
            socks_port=config.socks_port,
            control_port=config.control_port,
        )

        try:
            await tor.start(private_key, hs_port=config.relay_port)
            logger.info("Relay running at: %s", tor.onion_address)

            # Block until Tor process exits or KeyboardInterrupt
            while tor.is_running:
                await asyncio.sleep(5)

        except TorError as exc:
            logger.error("Tor failed: %s", exc)
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("Shutting down relay...")
            await cleanup.stop()
            await dq.stop()
            await server.stop()
            if tor.is_running:
                await tor.stop()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="legion-relay",
        description="Legion anonymous message relay node",
    )
    parser.add_argument("--data-dir", metavar="PATH")
    parser.add_argument("--relay-port", type=int, metavar="PORT")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )
    parser.add_argument(
        "--add-sender",
        metavar="PUBLIC_KEY_HEX",
        help="Authorize a sender public key and exit",
    )
    parser.add_argument(
        "--remove-sender",
        metavar="PUBLIC_KEY_HEX",
        help="Revoke a sender public key and exit",
    )
    parser.add_argument(
        "--list-senders",
        action="store_true",
        help="List authorized senders and exit",
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
    for name in ("stem", "websockets"):
        logging.getLogger(name).setLevel(logging.WARNING)

    # Management commands (run, then exit)
    if args.add_sender or args.remove_sender or args.list_senders:
        asyncio.run(_manage_senders(config, args))
        return

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass


async def _manage_senders(config: Config, args) -> None:
    """Add/remove/list authorized senders without starting the relay."""
    config.ensure_dirs()
    import time
    async with Database.open(config.db_path) as db:
        if args.add_sender:
            await db.add_sender(args.add_sender, alias=None, added_at=int(time.time()))
            print(f"Authorized sender: {args.add_sender}")
        elif args.remove_sender:
            await db.remove_sender(args.remove_sender)
            print(f"Removed sender: {args.remove_sender}")
        elif args.list_senders:
            senders = await db.get_senders()
            if not senders:
                print("No authorized senders.")
            for s in senders:
                alias = s["alias"] or "(no alias)"
                print(f"  {s['public_key']}  {alias}")


if __name__ == "__main__":
    main()
