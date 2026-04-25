
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
Usuwanie wygasłych wiadomości z bazy relay.

Uruchamiane co CLEANUP_INTERVAL_SECONDS (domyślnie 3600s = 1h).
Usuwa wszystkie rekordy gdzie expires_at < now().
"""

from __future__ import annotations

import asyncio
import logging
import time

from relay.storage import Database

logger = logging.getLogger(__name__)

_DEFAULT_INTERVAL = 3600  # 1 hour


class Cleanup:
    """Periodic task that removes expired messages from the relay database."""

    def __init__(self, db: Database, interval: int = _DEFAULT_INTERVAL) -> None:
        self._db = db
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def run_once(self, now: int | None = None) -> int:
        """Delete expired messages. Returns count of deleted rows."""
        if now is None:
            now = int(time.time())
        deleted = await self._db.delete_expired(now)
        if deleted:
            logger.info("Cleanup: removed %d expired message(s)", deleted)
        return deleted

    async def _loop(self) -> None:
        while self._running:
            try:
                await self.run_once()
            except Exception:
                logger.exception("Error during cleanup")
            await asyncio.sleep(self._interval)
