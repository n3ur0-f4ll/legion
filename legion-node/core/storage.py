
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
Warstwa dostępu do bazy danych SQLite.

Wszystkie operacje są asynchroniczne (aiosqlite).
Schemat bazy danych jest zdefiniowany w data/schema.sql.
Klasy row_factory zwracają słowniki — storage nie zna klas domenowych.
"""

from __future__ import annotations

import pathlib
import sqlite3
from contextlib import asynccontextmanager
from typing import AsyncIterator

import aiosqlite

_SCHEMA = pathlib.Path(__file__).parent.parent / "data" / "schema.sql"


class Database:
    """Wrapper na połączenie aiosqlite z metodami dla każdej tabeli."""

    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------
    # context manager
    # ------------------------------------------------------------------

    @staticmethod
    @asynccontextmanager
    async def open(path: str | pathlib.Path) -> AsyncIterator["Database"]:
        """Otwórz bazę danych i zainicjalizuj schemat."""
        async with aiosqlite.connect(path) as conn:
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA foreign_keys=ON")
            await _apply_schema(conn)
            yield Database(conn)

    # ------------------------------------------------------------------
    # identity
    # ------------------------------------------------------------------

    async def save_identity(
        self,
        public_key: str,
        private_key: bytes,
        onion_address: str,
        alias: str,
        created_at: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO identity VALUES (?, ?, ?, ?, ?)",
            (public_key, private_key, onion_address, alias, created_at),
        )
        await self._conn.commit()

    async def load_identity(self) -> dict | None:
        async with self._conn.execute("SELECT * FROM identity LIMIT 1") as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # relay_config
    # ------------------------------------------------------------------

    async def save_relay_config(
        self, onion_address: str, public_key: str, enabled: bool = True
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO relay_config (id, onion_address, public_key, enabled) "
            "VALUES (1, ?, ?, ?)",
            (onion_address, public_key, int(enabled)),
        )
        await self._conn.commit()

    async def load_relay_config(self) -> dict | None:
        async with self._conn.execute("SELECT * FROM relay_config WHERE id = 1") as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def delete_relay_config(self) -> None:
        await self._conn.execute("DELETE FROM relay_config WHERE id = 1")
        await self._conn.commit()

    # ------------------------------------------------------------------
    # contacts
    # ------------------------------------------------------------------

    async def save_contact(
        self,
        public_key: str,
        onion_address: str,
        alias: str | None,
        trusted_since: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO contacts VALUES (?, ?, ?, ?)",
            (public_key, onion_address, alias, trusted_since),
        )
        await self._conn.commit()

    async def get_contacts(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM contacts") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_contact(self, public_key: str) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM contacts WHERE public_key = ?", (public_key,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def delete_contact(self, public_key: str) -> None:
        await self._conn.execute(
            "DELETE FROM contacts WHERE public_key = ?", (public_key,)
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # messages
    # ------------------------------------------------------------------

    async def save_message(
        self,
        id: str,
        from_key: str,
        to_key: str,
        payload: bytes,
        signature: bytes,
        timestamp: int,
        expires_at: int,
        status: str,
    ) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (id, from_key, to_key, payload, signature, timestamp, expires_at, status),
        )
        await self._conn.commit()

    async def get_message_by_id(self, id: str) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM messages WHERE id = ?", (id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_messages(self, peer_key: str, our_key: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM messages "
            "WHERE (from_key = ? AND to_key = ?) OR (from_key = ? AND to_key = ?) "
            "ORDER BY timestamp",
            (peer_key, our_key, our_key, peer_key),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_message_status(self, id: str, status: str) -> None:
        await self._conn.execute(
            "UPDATE messages SET status = ? WHERE id = ?", (status, id)
        )
        await self._conn.commit()

    async def delete_expired_messages(self, now: int) -> int:
        cur = await self._conn.execute(
            "DELETE FROM messages WHERE expires_at < ?", (now,)
        )
        await self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # groups
    # ------------------------------------------------------------------

    async def save_group(
        self,
        id: str,
        name: str,
        group_key: bytes,
        admin_key: str,
        is_admin: bool,
        created_at: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR REPLACE INTO groups VALUES (?, ?, ?, ?, ?, ?)",
            (id, name, group_key, admin_key, int(is_admin), created_at),
        )
        await self._conn.commit()

    async def get_groups(self) -> list[dict]:
        async with self._conn.execute("SELECT * FROM groups") as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def get_group(self, id: str) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM groups WHERE id = ?", (id,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # group_members
    # ------------------------------------------------------------------

    async def save_group_member(
        self, group_id: str, public_key: str, added_at: int
    ) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO group_members VALUES (?, ?, ?)",
            (group_id, public_key, added_at),
        )
        await self._conn.commit()

    async def get_group_members(self, group_id: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM group_members WHERE group_id = ?", (group_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_group_member(self, group_id: str, public_key: str) -> None:
        await self._conn.execute(
            "DELETE FROM group_members WHERE group_id = ? AND public_key = ?",
            (group_id, public_key),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # group_posts
    # ------------------------------------------------------------------

    async def save_group_post(
        self,
        id: str,
        group_id: str,
        author_key: str,
        payload: bytes,
        signature: bytes,
        timestamp: int,
        expires_at: int,
    ) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO group_posts VALUES (?, ?, ?, ?, ?, ?, ?)",
            (id, group_id, author_key, payload, signature, timestamp, expires_at),
        )
        await self._conn.commit()

    async def get_group_posts(self, group_id: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM group_posts WHERE group_id = ? ORDER BY timestamp",
            (group_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def delete_expired_group_posts(self, now: int) -> int:
        cur = await self._conn.execute(
            "DELETE FROM group_posts WHERE expires_at < ?", (now,)
        )
        await self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # delivery_queue
    # ------------------------------------------------------------------

    async def enqueue(
        self,
        id: str,
        message_id: str,
        destination_key: str,
        destination_onion: str,
        next_retry_at: int,
        via_relay: bool = False,
    ) -> None:
        await self._conn.execute(
            "INSERT OR IGNORE INTO delivery_queue "
            "(id, message_id, destination_key, destination_onion, next_retry_at, retry_count, via_relay) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (id, message_id, destination_key, destination_onion, next_retry_at, int(via_relay)),
        )
        await self._conn.commit()

    async def get_due(self, now: int) -> list[dict]:
        """Return delivery queue entries that are due for retry."""
        async with self._conn.execute(
            "SELECT * FROM delivery_queue WHERE next_retry_at <= ? ORDER BY next_retry_at",
            (now,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def update_retry(self, id: str, next_retry_at: int) -> None:
        await self._conn.execute(
            "UPDATE delivery_queue SET retry_count = retry_count + 1, next_retry_at = ? WHERE id = ?",
            (next_retry_at, id),
        )
        await self._conn.commit()

    async def dequeue(self, id: str) -> None:
        await self._conn.execute(
            "DELETE FROM delivery_queue WHERE id = ?", (id,)
        )
        await self._conn.commit()


# ------------------------------------------------------------------
# internal helpers
# ------------------------------------------------------------------

async def _apply_schema(conn: aiosqlite.Connection) -> None:
    sql = _SCHEMA.read_text()
    await conn.executescript(sql)
