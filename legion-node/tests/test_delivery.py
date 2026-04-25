
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


"""Tests for messaging/delivery.py."""

import asyncio
import time

import pytest

from core.identity import generate as gen
from core.storage import Database
from messaging.delivery import RETRY_SCHEDULE, DeliveryQueue, _entry_id, _load_message_json
from messaging.private import send

ALICE = gen("alice")
BOB = gen("bob")
NOW = int(time.time())


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


async def _send_msg(db):
    return await send(db, ALICE, BOB.public_key, "hello")


# ------------------------------------------------------------------
# _entry_id
# ------------------------------------------------------------------

def test_entry_id_is_deterministic():
    assert _entry_id("msg1", "key1") == _entry_id("msg1", "key1")


def test_entry_id_differs_on_different_destination():
    assert _entry_id("msg1", "key1") != _entry_id("msg1", "key2")


def test_entry_id_differs_on_different_message():
    assert _entry_id("msg1", "key1") != _entry_id("msg2", "key1")


# ------------------------------------------------------------------
# _load_message_json
# ------------------------------------------------------------------

def test_load_message_json_valid():
    import json
    msg = {"v": 1, "type": "msg", "id": "abc"}
    entry = {"message_json": json.dumps(msg)}
    assert _load_message_json(entry) == msg


def test_load_message_json_empty_returns_none():
    assert _load_message_json({"message_json": ""}) is None


def test_load_message_json_missing_key_returns_none():
    assert _load_message_json({}) is None


def test_load_message_json_invalid_json_returns_none():
    assert _load_message_json({"message_json": "not json"}) is None


# ------------------------------------------------------------------
# DeliveryQueue.enqueue
# ------------------------------------------------------------------

async def test_enqueue_adds_to_queue(db):
    msg = await _send_msg(db)
    q = DeliveryQueue(db, sender=None)
    await q.enqueue(msg, "bob.onion")
    due = await db.get_due(NOW + 1)
    assert len(due) == 1
    assert due[0]["message_id"] == msg["id"]


async def test_enqueue_duplicate_ignored(db):
    msg = await _send_msg(db)
    q = DeliveryQueue(db, sender=None)
    await q.enqueue(msg, "bob.onion")
    await q.enqueue(msg, "bob.onion")
    due = await db.get_due(NOW + 1)
    assert len(due) == 1


async def test_enqueue_via_relay_flag(db):
    msg = await _send_msg(db)
    q = DeliveryQueue(db, sender=None)
    await q.enqueue(msg, "relay.onion", via_relay=True)
    due = await db.get_due(NOW + 1)
    assert due[0]["via_relay"] == 1


# ------------------------------------------------------------------
# DeliveryQueue.process_due — successful delivery
# ------------------------------------------------------------------

async def test_process_due_calls_sender(db):
    msg = await _send_msg(db)
    calls = []

    async def fake_sender(m, onion):
        calls.append((m["id"], onion))

    q = DeliveryQueue(db, sender=fake_sender)
    await q.enqueue(msg, "bob.onion")
    sent, failed = await q.process_due(NOW + 1)

    assert sent == 1
    assert failed == 0
    assert calls == [(msg["id"], "bob.onion")]


async def test_process_due_dequeues_on_success(db):
    msg = await _send_msg(db)

    async def fake_sender(m, onion):
        pass

    q = DeliveryQueue(db, sender=fake_sender)
    await q.enqueue(msg, "bob.onion")
    await q.process_due(NOW + 1)

    due = await db.get_due(NOW + 10)
    assert due == []


async def test_process_due_marks_message_delivered(db):
    msg = await _send_msg(db)

    async def fake_sender(m, onion):
        pass

    q = DeliveryQueue(db, sender=fake_sender)
    await q.enqueue(msg, "bob.onion")
    await q.process_due(NOW + 1)

    row = await db.get_message_by_id(msg["id"])
    assert row["status"] == "delivered"


# ------------------------------------------------------------------
# DeliveryQueue.process_due — failed delivery (retry)
# ------------------------------------------------------------------

async def test_process_due_schedules_retry_on_failure(db):
    msg = await _send_msg(db)

    async def failing_sender(m, onion):
        raise ConnectionError("offline")

    q = DeliveryQueue(db, sender=failing_sender)
    await q.enqueue(msg, "bob.onion")

    now = int(time.time())
    sent, failed = await q.process_due(now + 1)  # +1 ensures entry is due

    assert sent == 0
    assert failed == 1

    due_now = await db.get_due(now + 1)
    assert due_now == []  # next_retry_at is in the future

    due_after = await db.get_due(now + RETRY_SCHEDULE[0] + 2)
    assert len(due_after) == 1
    assert due_after[0]["retry_count"] == 1


async def test_process_due_follows_full_retry_schedule(db):
    msg = await _send_msg(db)

    async def failing_sender(m, onion):
        raise ConnectionError("offline")

    q = DeliveryQueue(db, sender=failing_sender)
    await q.enqueue(msg, "bob.onion")

    current_time = NOW
    for i, interval in enumerate(RETRY_SCHEDULE):
        current_time += interval + 1
        await q.process_due(current_time)
        due = await db.get_due(current_time)
        if i < len(RETRY_SCHEDULE) - 1:
            assert due == [], f"should not be due immediately after retry {i}"

    # After last retry, message stays in queue without further retries
    late = current_time + 999_999
    due = await db.get_due(late)
    assert len(due) == 1  # still in queue
    assert due[0]["retry_count"] == len(RETRY_SCHEDULE)


async def test_process_due_removes_orphaned_entry(db):
    """Entry with empty message_json is treated as orphan and removed."""
    import json as _json
    # Manually insert an entry with empty message_json (legacy/corrupt entry)
    await db._conn.execute(
        "INSERT INTO delivery_queue "
        "(id, message_id, destination_key, destination_onion, message_json, next_retry_at) "
        "VALUES ('eid1', 'mid1', 'key1', 'bob.onion', '', ?)",
        (NOW,),
    )
    await db._conn.commit()

    q = DeliveryQueue(db, sender=None)
    sent, failed = await q.process_due(NOW + 1)
    assert sent == 0
    assert failed == 0  # orphan: removed, not counted as failure
    assert await db.get_due(NOW + 999) == []


# ------------------------------------------------------------------
# DeliveryQueue.start / stop
# ------------------------------------------------------------------

async def test_start_stop_lifecycle(db):
    q = DeliveryQueue(db, sender=None)
    assert q._task is None

    await q.start()
    assert q._task is not None
    assert not q._task.done()

    await q.stop()
    assert q._task is None


async def test_stop_before_start_is_safe(db):
    q = DeliveryQueue(db, sender=None)
    await q.stop()  # must not raise


async def test_background_loop_processes_queue(db):
    msg = await _send_msg(db)
    delivered = []

    async def fake_sender(m, onion):
        delivered.append(m["id"])

    q = DeliveryQueue(db, sender=fake_sender)
    await q.enqueue(msg, "bob.onion")
    await q.start()
    await asyncio.sleep(0.1)  # let loop run at least once
    await q.stop()

    assert msg["id"] in delivered
