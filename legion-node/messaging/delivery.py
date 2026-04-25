
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
Kolejka dostarczania wiadomości i logika retry.

Gdy dostarczenie wiadomości nie powiedzie się (odbiorca offline), wiadomość
trafia do kolejki. Kolejka próbuje ponownie według harmonogramu:
[60, 300, 900, 3600, 21600, 86400] sekund między próbami.

Po wyczerpaniu harmonogramu wiadomość zostaje w kolejce bez dalszych
automatycznych prób — użytkownik może ją usunąć ręcznie.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from typing import Awaitable, Callable

from core.protocol import MSG_PRIVATE
from core.storage import Database

logger = logging.getLogger(__name__)

RETRY_SCHEDULE = [60, 300, 900, 3600, 21600, 86400]

Sender = Callable[[dict, str], Awaitable[None]]  # (msg_dict, onion_address) -> None

_LOOP_INTERVAL = 30  # seconds between queue sweeps


class DeliveryQueue:
    """Background delivery queue with exponential-ish retry schedule.

    Reconstructs message dicts from the messages table and hands them to
    the sender callable (network.client.send_message or relay equivalent).
    """

    def __init__(self, db: Database, sender: Sender) -> None:
        self._db = db
        self._sender = sender
        self._task: asyncio.Task | None = None
        self._running = False

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    async def enqueue(
        self,
        msg: dict,
        destination_onion: str,
        via_relay: bool = False,
    ) -> None:
        """Add a message to the delivery queue for immediate first attempt."""
        await self._db.enqueue(
            id=_entry_id(msg["id"], msg["to"]),
            message_id=msg["id"],
            destination_key=msg["to"],
            destination_onion=destination_onion,
            next_retry_at=int(time.time()),
            via_relay=via_relay,
        )

    async def process_due(self, now: int | None = None) -> tuple[int, int]:
        """Attempt delivery of all due queue entries.

        Returns (sent, failed) counts.
        """
        if now is None:
            now = int(time.time())

        due = await self._db.get_due(now)
        sent = failed = 0

        for entry in due:
            result = await self._try_deliver(entry, now)
            if result is True:
                sent += 1
            elif result is False:
                failed += 1
            # None = orphan, removed silently

        return sent, failed

    async def start(self) -> None:
        """Start the background delivery loop."""
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        """Stop the background delivery loop gracefully."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while self._running:
            try:
                sent, failed = await self.process_due()
                if sent or failed:
                    logger.debug("Delivery sweep: sent=%d failed=%d", sent, failed)
            except Exception:
                logger.exception("Unexpected error in delivery loop")
            await asyncio.sleep(_LOOP_INTERVAL)

    async def _try_deliver(self, entry: dict, now: int) -> bool | None:
        """Attempt delivery of one queue entry.

        Returns True (sent), False (failed, retry scheduled), or None (orphan removed).
        """
        msg_dict = await _reconstruct_message(self._db, entry["message_id"])
        if msg_dict is None:
            logger.warning("Delivery entry %s has no matching message — removing", entry["id"])
            await self._db.dequeue(entry["id"])
            return None

        try:
            await self._sender(msg_dict, entry["destination_onion"])
            await self._db.dequeue(entry["id"])
            await self._db.update_message_status(entry["message_id"], "delivered")
            return True
        except Exception:
            retry_count = entry["retry_count"]
            if retry_count < len(RETRY_SCHEDULE):
                next_retry = now + RETRY_SCHEDULE[retry_count]
                await self._db.update_retry(entry["id"], next_retry)
            # else: leave in queue, no more automatic retries
            return False


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

async def _reconstruct_message(db: Database, message_id: str) -> dict | None:
    """Rebuild a protocol message dict from the messages table.

    Returns None if the message is not found or has expired.
    Messages in this table are always type MSG_PRIVATE ("msg").
    """
    row = await db.get_message_by_id(message_id)
    if row is None:
        return None

    now = int(time.time())
    if row["expires_at"] < now:
        return None

    ttl = row["expires_at"] - row["timestamp"]
    return {
        "v": 1,
        "type": MSG_PRIVATE,
        "id": row["id"],
        "from": row["from_key"],
        "to": row["to_key"],
        "payload": base64.b64encode(row["payload"]).decode(),
        "signature": base64.b64encode(row["signature"]).decode(),
        "timestamp": row["timestamp"],
        "ttl": ttl,
    }


def _entry_id(message_id: str, destination_key: str) -> str:
    """Deterministic queue entry ID — prevents duplicate entries."""
    return hashlib.sha256(f"{message_id}:{destination_key}".encode()).hexdigest()
