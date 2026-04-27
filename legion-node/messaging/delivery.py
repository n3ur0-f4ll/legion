
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
trafia do kolejki. Kolejka próbuje ponownie co _LOOP_INTERVAL sekund,
bez limitu liczby prób, dopóki nie dotrze lub użytkownik jej nie anuluje.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Awaitable, Callable

from core.storage import Database

logger = logging.getLogger(__name__)

Sender = Callable[[dict, str], Awaitable[None]]  # (msg_dict, onion_address) -> None
OnDelivered = Callable[[str], Awaitable[None]]   # (message_id) -> None

_LOOP_INTERVAL = 10  # seconds between queue sweeps — also the retry interval


class DeliveryQueue:
    """Background delivery queue with exponential-ish retry schedule.

    Reads full message JSON from delivery_queue.message_json and hands it to
    the sender callable (network.client.send_message or relay equivalent).
    """

    def __init__(
        self,
        db: Database,
        sender: Sender,
        on_delivered: OnDelivered | None = None,
    ) -> None:
        self._db = db
        self._sender = sender
        self._on_delivered = on_delivered
        self._task: asyncio.Task | None = None
        self._running = False
        self._wake = asyncio.Event()  # set when a new message is enqueued

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
            message_json=json.dumps(msg),
            via_relay=via_relay,
        )
        self._wake.set()  # wake delivery loop immediately

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
            # Sleep until timeout OR woken by a new enqueue()
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=_LOOP_INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def _try_deliver(self, entry: dict, now: int) -> bool | None:
        """Attempt delivery of one queue entry.

        Returns True (sent), False (failed, retry scheduled), or None (orphan removed).
        """
        msg_dict = _load_message_json(entry)
        if msg_dict is None:
            logger.warning("Delivery entry %s has no message JSON — removing", entry["id"])
            await self._db.dequeue(entry["id"])
            return None

        # Skip expired messages
        ttl = msg_dict.get("ttl", 0)
        if int(time.time()) - msg_dict.get("timestamp", 0) > ttl:
            await self._db.dequeue(entry["id"])
            return None

        try:
            await self._sender(msg_dict, entry["destination_onion"])
            await self._db.dequeue(entry["id"])
            await self._db.update_message_status(entry["message_id"], "delivered")
            if self._on_delivered:
                try:
                    await self._on_delivered(entry["message_id"])
                except Exception:
                    pass
            return True
        except Exception:
            # Retry in _LOOP_INTERVAL seconds — indefinitely until delivered or cancelled
            await self._db.update_retry(entry["id"], now + _LOOP_INTERVAL)
            return False


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _load_message_json(entry: dict) -> dict | None:
    """Load message dict from the queue entry's stored JSON.

    Returns None if the entry has no JSON (legacy entry without message_json).
    """
    raw = entry.get("message_json", "")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def _entry_id(message_id: str, destination_key: str) -> str:
    """Deterministic queue entry ID — prevents duplicate entries."""
    return hashlib.sha256(f"{message_id}:{destination_key}".encode()).hexdigest()
