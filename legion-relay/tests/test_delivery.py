
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


"""Tests for relay/delivery.py."""

import asyncio
import time
from unittest.mock import patch

import pytest

from relay.delivery import DeliveryQueue, RETRY_SCHEDULE
from relay.storage import Database

NOW = int(time.time())
EXPIRES = NOW + 7 * 86400


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


@pytest.fixture
async def queue(db):
    return DeliveryQueue(db, socks_host="127.0.0.1", socks_port=9999, hs_port=80)


async def _enqueue(q, db, msg_id="msg1", payload=b"blob"):
    await q.enqueue(
        message_id=msg_id,
        sender_key="alice",
        for_key="bob",
        destination_onion="bob.onion",
        payload=payload,
        expires_at=EXPIRES,
    )


# ------------------------------------------------------------------
# enqueue
# ------------------------------------------------------------------

async def test_enqueue_stores_message(queue, db):
    await _enqueue(queue, db)
    row = await db.get_message("msg1")
    assert row is not None
    assert row["status"] == "queued"
    assert row["payload"] == b"blob"


async def test_enqueue_duplicate_ignored(queue, db):
    await _enqueue(queue, db, "msg1")
    await _enqueue(queue, db, "msg1")
    assert await db.count_queued() == 1


async def test_enqueue_different_ids(queue, db):
    await _enqueue(queue, db, "msg1")
    await _enqueue(queue, db, "msg2")
    assert await db.count_queued() == 2


# ------------------------------------------------------------------
# process_due — success
# ------------------------------------------------------------------

async def test_process_due_delivers_message(queue, db):
    await _enqueue(queue, db)

    async def noop(*a):
        pass

    with patch.object(queue, "_send_payload", new=noop):
        delivered, failed = await queue.process_due(NOW + 1)

    assert delivered == 1
    assert failed == 0
    row = await db.get_message("msg1")
    assert row["status"] == "delivered"


async def test_process_due_calls_send_with_correct_args(queue, db):
    await _enqueue(queue, db, payload=b"original blob")
    calls = []

    async def capture(onion, payload):
        calls.append((onion, payload))

    with patch.object(queue, "_send_payload", new=capture):
        await queue.process_due(NOW + 1)

    assert calls == [("bob.onion", b"original blob")]


async def test_process_due_empty_queue(queue, db):
    delivered, failed = await queue.process_due(NOW + 1)
    assert delivered == 0
    assert failed == 0


async def test_process_due_skips_future_entries(queue, db):
    await _enqueue(queue, db)
    # next_retry_at = NOW, process with NOW - 1 → not due yet
    delivered, failed = await queue.process_due(NOW - 1)
    assert delivered == 0
    assert failed == 0


# ------------------------------------------------------------------
# process_due — failure and retry
# ------------------------------------------------------------------

async def test_process_due_schedules_retry_on_failure(queue, db):
    await _enqueue(queue, db)

    async def fail(onion, payload):
        raise ConnectionError("offline")

    with patch.object(queue, "_send_payload", new=fail):
        now = int(time.time())
        delivered, failed = await queue.process_due(now + 1)

    assert delivered == 0
    assert failed == 1

    row = await db.get_message("msg1")
    assert row["status"] == "queued"
    assert row["retry_count"] == 1
    assert row["next_retry_at"] > now + 1


async def test_process_due_follows_retry_schedule(queue, db):
    await _enqueue(queue, db)

    async def fail(onion, payload):
        raise ConnectionError("offline")

    current = NOW + 1
    with patch.object(queue, "_send_payload", new=fail):
        for i, interval in enumerate(RETRY_SCHEDULE):
            await queue.process_due(current)
            row = await db.get_message("msg1")
            assert row["retry_count"] == i + 1
            current = row["next_retry_at"] + 1

    # After exhausting schedule: status = failed
    with patch.object(queue, "_send_payload", new=fail):
        await queue.process_due(current)

    row = await db.get_message("msg1")
    assert row["status"] == "failed"


async def test_process_due_marks_failed_after_schedule_exhausted(queue, db):
    await _enqueue(queue, db)

    async def fail(onion, payload):
        raise ConnectionError("offline")

    # Run through all retries
    current = NOW + 1
    with patch.object(queue, "_send_payload", new=fail):
        for interval in RETRY_SCHEDULE:
            await queue.process_due(current)
            row = await db.get_message("msg1")
            current = row["next_retry_at"] + 1
        # One more after exhausting
        await queue.process_due(current)

    row = await db.get_message("msg1")
    assert row["status"] == "failed"


# ------------------------------------------------------------------
# start / stop lifecycle
# ------------------------------------------------------------------

async def test_start_stop(queue):
    await queue.start()
    assert queue._task is not None
    assert not queue._task.done()
    await queue.stop()
    assert queue._task is None


async def test_stop_before_start_safe(queue):
    await queue.stop()  # must not raise


async def test_background_loop_runs(queue, db):
    await _enqueue(queue, db)
    delivered_ids = []

    async def capture(onion, payload):
        delivered_ids.append(onion)

    with patch.object(queue, "_send_payload", new=capture):
        await queue.start()
        await asyncio.sleep(0.1)
        await queue.stop()

    assert "bob.onion" in delivered_ids
