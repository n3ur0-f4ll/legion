
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
Warstwa dostępu do bazy danych relay.

Relay nie wykonuje kryptografii na treści wiadomości — przechowuje
zaszyfrowane blobs jako BLOB i przekazuje je bez modyfikacji.
"""

from __future__ import annotations

import pathlib
from contextlib import asynccontextmanager
from typing import AsyncIterator

import aiosqlite

_SCHEMA = pathlib.Path(__file__).parent.parent / "data" / "schema.sql"


class Database:
    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    @staticmethod
    @asynccontextmanager
    async def open(path: str | pathlib.Path) -> AsyncIterator["Database"]:
        async with aiosqlite.connect(path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA foreign_keys=ON")
            await _apply_schema(conn)
            yield Database(conn)

    # ------------------------------------------------------------------
    # relay_identity
    # ------------------------------------------------------------------

    async def save_identity(
        self,
        public_key: str,
        private_key: bytes,
        onion_address: str,
        created_at: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO relay_identity VALUES (?, ?, ?, ?)",
            (public_key, private_key, onion_address, created_at),
        )
        await self._conn.commit()

    async def load_identity(self) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM relay_identity LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # authorized_senders
    # ------------------------------------------------------------------

    async def add_sender(
        self, public_key: str, alias: str | None, added_at: int
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO authorized_senders VALUES (?, ?, ?)",
            (public_key, alias, added_at),
        )
        await self._conn.commit()

    async def remove_sender(self, public_key: str) -> None:
        await self._conn.execute(
            "DELETE FROM authorized_senders WHERE public_key = ?", (public_key,)
        )
        await self._conn.commit()

    async def is_authorized(self, public_key: str) -> bool:
        async with self._conn.execute(
            "SELECT 1 FROM authorized_senders WHERE public_key = ?", (public_key,)
        ) as cur:
            return await cur.fetchone() is not None

    async def get_senders(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM authorized_senders") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # stored_messages
    # ------------------------------------------------------------------

    async def save_message(
        self,
        id: str,
        sender_key: str,
        for_key: str,
        destination_onion: str,
        payload: bytes,
        received_at: int,
        expires_at: int,
        next_retry_at: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO stored_messages "
            "(id, sender_key, for_key, destination_onion, payload, "
            "received_at, expires_at, next_retry_at, retry_count, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'queued')",
            (id, sender_key, for_key, destination_onion, payload,
             received_at, expires_at, next_retry_at),
        )
        await self._conn.commit()

    async def get_message(self, id: str) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM stored_messages WHERE id = ?", (id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_due(self, now: int) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM stored_messages "
            "WHERE status = 'queued' AND next_retry_at <= ? "
            "ORDER BY next_retry_at",
            (now,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_status(self, id: str, status: str) -> None:
        await self._conn.execute(
            "UPDATE stored_messages SET status = ? WHERE id = ?", (status, id)
        )
        await self._conn.commit()

    async def update_retry(self, id: str, next_retry_at: int) -> None:
        await self._conn.execute(
            "UPDATE stored_messages "
            "SET retry_count = retry_count + 1, next_retry_at = ? "
            "WHERE id = ?",
            (next_retry_at, id),
        )
        await self._conn.commit()

    async def delete_expired(self, now: int) -> int:
        cur = await self._conn.execute(
            "DELETE FROM stored_messages WHERE expires_at < ?", (now,)
        )
        await self._conn.commit()
        return cur.rowcount

    async def count_queued(self) -> int:
        async with self._conn.execute(
            "SELECT COUNT(*) FROM stored_messages WHERE status = 'queued'"
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0


async def _apply_schema(conn: aiosqlite.Connection) -> None:
    sql = _SCHEMA.read_text()
    await conn.executescript(sql)
