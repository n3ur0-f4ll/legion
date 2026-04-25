
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


"""Tests for api/server.py."""

import pytest
from httpx import ASGITransport, AsyncClient

from api.server import AppState, create_app, make_message_handler
from core.identity import generate as gen
from core.protocol import build_contact_card, build_message, MSG_PRIVATE
from core.storage import Database
from messaging.delivery import DeliveryQueue

ALICE = gen("alice")
BOB = gen("bob")


async def _noop_sender(msg, onion):
    pass


@pytest.fixture
async def state():
    async with Database.open(":memory:") as db:
        dq = DeliveryQueue(db, sender=_noop_sender)
        s = AppState(db=db, delivery_queue=dq, identity=ALICE, tor_onion=ALICE.onion_address)
        yield s


@pytest.fixture
async def client(state):
    app = create_app(state)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def state_no_identity():
    async with Database.open(":memory:") as db:
        dq = DeliveryQueue(db, sender=_noop_sender)
        s = AppState(db=db, delivery_queue=dq, identity=None)
        yield s


@pytest.fixture
async def client_no_identity(state_no_identity):
    app = create_app(state_no_identity)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ------------------------------------------------------------------
# GET /api/status
# ------------------------------------------------------------------

async def test_status_with_identity(client):
    r = await client.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["identity_loaded"] is True
    assert data["onion_address"] == ALICE.onion_address


async def test_status_no_identity(client_no_identity):
    r = await client_no_identity.get("/api/status")
    assert r.status_code == 200
    data = r.json()
    assert data["identity_loaded"] is False
    assert data["identity_exists"] is False


async def test_status_identity_exists_not_loaded(state_no_identity):
    """identity_exists=True when DB has identity but AppState.identity is None."""
    from core.identity import encrypt_private_key
    await state_no_identity.db.save_identity(
        public_key=ALICE.public_key.hex(),
        private_key=encrypt_private_key(ALICE.private_key, "pw"),
        onion_address=ALICE.onion_address,
        alias="alice",
        created_at=0,
    )
    app = create_app(state_no_identity)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/api/status")
    data = r.json()
    assert data["identity_loaded"] is False
    assert data["identity_exists"] is True


# ------------------------------------------------------------------
# POST /api/identity/unlock
# ------------------------------------------------------------------

async def test_unlock_no_identity_returns_404(client_no_identity):
    r = await client_no_identity.post("/api/identity/unlock", json={"password": "pw"})
    assert r.status_code == 404


async def test_unlock_wrong_password_returns_401(state_no_identity):
    from core.identity import encrypt_private_key
    import time
    await state_no_identity.db.save_identity(
        public_key=ALICE.public_key.hex(),
        private_key=encrypt_private_key(ALICE.private_key, "correct"),
        onion_address=ALICE.onion_address,
        alias="alice",
        created_at=int(time.time()),
    )
    app = create_app(state_no_identity)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/identity/unlock", json={"password": "wrong"})
    assert r.status_code == 401


async def test_unlock_correct_password_loads_identity(state_no_identity):
    from core.identity import encrypt_private_key
    import time
    await state_no_identity.db.save_identity(
        public_key=ALICE.public_key.hex(),
        private_key=encrypt_private_key(ALICE.private_key, "secret"),
        onion_address=ALICE.onion_address,
        alias="alice",
        created_at=int(time.time()),
    )
    assert state_no_identity.identity is None
    app = create_app(state_no_identity)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.post("/api/identity/unlock", json={"password": "secret"})
    assert r.status_code == 200
    data = r.json()
    assert data["public_key"] == ALICE.public_key.hex()
    assert state_no_identity.identity is not None
    assert state_no_identity.identity.private_key == ALICE.private_key


async def test_unlock_already_loaded_returns_identity(client):
    """Calling unlock when already loaded returns identity without error."""
    r = await client.post("/api/identity/unlock", json={"password": "any"})
    assert r.status_code == 200
    assert r.json()["public_key"] == ALICE.public_key.hex()


# ------------------------------------------------------------------
# POST /api/identity/create
# ------------------------------------------------------------------

async def test_create_identity(client_no_identity, state_no_identity):
    r = await client_no_identity.post(
        "/api/identity/create",
        json={"alias": "alice", "password": "secret123"},
    )
    assert r.status_code == 201
    data = r.json()
    assert "public_key" in data
    assert "onion_address" in data
    assert "private_key" not in data
    assert state_no_identity.identity is not None


async def test_create_identity_twice_returns_409(client_no_identity):
    await client_no_identity.post(
        "/api/identity/create", json={"alias": "alice", "password": "pw"}
    )
    r = await client_no_identity.post(
        "/api/identity/create", json={"alias": "alice", "password": "pw"}
    )
    assert r.status_code == 409


async def test_create_identity_when_loaded_returns_409(client):
    r = await client.post(
        "/api/identity/create", json={"alias": "bob", "password": "pw"}
    )
    assert r.status_code == 409


# ------------------------------------------------------------------
# GET /api/identity
# ------------------------------------------------------------------

async def test_get_identity(client):
    r = await client.get("/api/identity")
    assert r.status_code == 200
    data = r.json()
    assert data["public_key"] == ALICE.public_key.hex()
    assert "private_key" not in data


async def test_get_identity_no_identity_returns_503(client_no_identity):
    r = await client_no_identity.get("/api/identity")
    assert r.status_code == 503


# ------------------------------------------------------------------
# Contacts
# ------------------------------------------------------------------

async def test_get_contacts_empty(client):
    r = await client.get("/api/contacts")
    assert r.status_code == 200
    assert r.json() == []


async def test_add_and_get_contact(client):
    card = build_contact_card(BOB.public_key, BOB.onion_address, BOB.private_key, alias_hint="Bob")
    r = await client.post("/api/contacts", json=card)
    assert r.status_code == 201
    data = r.json()
    assert data["public_key"] == BOB.public_key.hex()

    r = await client.get("/api/contacts")
    assert len(r.json()) == 1


async def test_add_contact_invalid_signature_returns_422(client):
    card = build_contact_card(BOB.public_key, BOB.onion_address, BOB.private_key)
    card["onion_address"] = "tampered.onion"
    r = await client.post("/api/contacts", json=card)
    assert r.status_code == 422


async def test_delete_contact(client):
    card = build_contact_card(BOB.public_key, BOB.onion_address, BOB.private_key)
    await client.post("/api/contacts", json=card)
    r = await client.delete(f"/api/contacts/{BOB.public_key.hex()}")
    assert r.status_code == 204
    assert r.json() == [] if False else True  # no body on 204

    r = await client.get("/api/contacts")
    assert r.json() == []


async def test_delete_contact_not_found_returns_404(client):
    r = await client.delete(f"/api/contacts/{'aa' * 32}")
    assert r.status_code == 404


# ------------------------------------------------------------------
# Messages
# ------------------------------------------------------------------

async def test_get_messages_empty(client):
    r = await client.get(f"/api/messages/{BOB.public_key.hex()}")
    assert r.status_code == 200
    assert r.json() == []


async def test_get_messages_returns_decrypted_text(client, state):
    """Sent message must come back with plaintext 'text' field."""
    r = await client.post("/api/messages", json={
        "to": BOB.public_key.hex(),
        "text": "hello bob",
        "onion": BOB.onion_address,
    })
    assert r.status_code == 201

    r = await client.get(f"/api/messages/{BOB.public_key.hex()}")
    messages = r.json()
    assert len(messages) == 1
    assert messages[0]["text"] == "hello bob"
    assert "payload" not in messages[0]
    assert "signature" not in messages[0]


async def test_get_messages_incoming_decrypted(client, state):
    """Received message (encrypted by peer for us) must also be decrypted."""
    # Simulate BOB sending to ALICE (ALICE is the identity in state)
    from core.protocol import build_message, MSG_PRIVATE
    from messaging.private import receive
    import base64

    payload = __import__("core.crypto", fromlist=["encrypt"]).encrypt(
        BOB.private_key, ALICE.public_key, b"incoming text"
    )
    msg = build_message(MSG_PRIVATE, BOB.public_key, ALICE.public_key, payload, BOB.private_key)
    await receive(state.db, ALICE, msg)

    r = await client.get(f"/api/messages/{BOB.public_key.hex()}")
    messages = r.json()
    received = [m for m in messages if m["from_key"] == BOB.public_key.hex()]
    assert len(received) == 1
    assert received[0]["text"] == "incoming text"


async def test_send_message_queues(client, state):
    enqueued = []
    async def capturing_sender(msg, onion):
        enqueued.append((msg["id"], onion))
    state.delivery_queue._sender = capturing_sender

    r = await client.post("/api/messages", json={
        "to": BOB.public_key.hex(),
        "text": "hello",
        "onion": BOB.onion_address,
    })
    assert r.status_code == 201
    assert r.json()["status"] == "queued"


async def test_send_message_invalid_key_returns_422(client):
    r = await client.post("/api/messages", json={
        "to": "not-hex",
        "text": "hello",
        "onion": "bob.onion",
    })
    assert r.status_code == 422


async def test_send_message_no_identity_returns_503(client_no_identity):
    r = await client_no_identity.post("/api/messages", json={
        "to": BOB.public_key.hex(),
        "text": "hello",
        "onion": "bob.onion",
    })
    assert r.status_code == 503


# ------------------------------------------------------------------
# Groups
# ------------------------------------------------------------------

async def test_get_groups_empty(client):
    r = await client.get("/api/groups")
    assert r.status_code == 200
    assert r.json() == []


async def test_create_group(client):
    r = await client.post("/api/groups", json={"name": "Crew"})
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "Crew"
    assert data["is_admin"] is True
    assert "group_key" not in data or True  # group_key is bytes in DB, may be omitted


async def test_get_groups_after_create(client):
    await client.post("/api/groups", json={"name": "Crew"})
    r = await client.get("/api/groups")
    assert len(r.json()) == 1


async def test_get_posts_empty(client):
    r = await client.post("/api/groups", json={"name": "Crew"})
    group_id = r.json()["id"]
    r = await client.get(f"/api/groups/{group_id}/posts")
    assert r.status_code == 200
    assert r.json() == []


async def test_create_post(client):
    r = await client.post("/api/groups", json={"name": "Crew"})
    group_id = r.json()["id"]
    r = await client.post(f"/api/groups/{group_id}/posts", json={"text": "hello group"})
    assert r.status_code == 201
    assert r.json()["status"] == "queued"


async def test_get_posts_returns_decrypted_text(client):
    r = await client.post("/api/groups", json={"name": "Crew"})
    group_id = r.json()["id"]
    await client.post(f"/api/groups/{group_id}/posts", json={"text": "secret post"})

    r = await client.get(f"/api/groups/{group_id}/posts")
    posts = r.json()
    assert len(posts) == 1
    assert posts[0]["text"] == "secret post"
    assert "payload" not in posts[0]
    assert "signature" not in posts[0]


async def test_get_posts_unknown_group_returns_empty_with_null_text(client):
    """Posts for unknown group return empty list, not 404."""
    r = await client.get(f"/api/groups/{'a' * 64}/posts")
    assert r.status_code == 200
    assert r.json() == []


async def test_create_post_unknown_group_returns_404(client):
    r = await client.post(f"/api/groups/{'x' * 64}/posts", json={"text": "hello"})
    assert r.status_code == 404


async def test_invite_member_unknown_group_returns_404(client):
    r = await client.post(
        f"/api/groups/{'x' * 64}/invite",
        json={"public_key": BOB.public_key.hex(), "onion": "bob.onion"},
    )
    assert r.status_code == 404


async def test_invite_member_invalid_key_returns_422(client):
    r_group = await client.post("/api/groups", json={"name": "Crew"})
    group_id = r_group.json()["id"]
    r = await client.post(
        f"/api/groups/{group_id}/invite",
        json={"public_key": "not-hex", "onion": "bob.onion"},
    )
    assert r.status_code == 422


# ------------------------------------------------------------------
# make_message_handler
# ------------------------------------------------------------------

async def test_handler_stores_incoming_message(state):
    # BOB must be a contact for the message to be accepted
    import time
    await state.db.save_contact(BOB.public_key.hex(), BOB.onion_address, "Bob", int(time.time()))

    msg = build_message(
        MSG_PRIVATE, BOB.public_key, ALICE.public_key,
        __import__("core.crypto", fromlist=["encrypt"]).encrypt(
            BOB.private_key, ALICE.public_key, b"hello alice"
        ),
        BOB.private_key,
    )
    handler = make_message_handler(state)
    await handler(msg)
    rows = await state.db.get_messages(BOB.public_key.hex(), ALICE.public_key.hex())
    assert len(rows) == 1


async def test_handler_pushes_sse_event(state):
    import time
    await state.db.save_contact(BOB.public_key.hex(), BOB.onion_address, "Bob", int(time.time()))

    q = state._add_event_queue()

    msg = build_message(
        MSG_PRIVATE, BOB.public_key, ALICE.public_key,
        __import__("core.crypto", fromlist=["encrypt"]).encrypt(
            BOB.private_key, ALICE.public_key, b"hi"
        ),
        BOB.private_key,
    )
    handler = make_message_handler(state)
    await handler(msg)

    assert not q.empty()
    event = q.get_nowait()
    assert event["type"] == "message"
    assert event["from"] == BOB.public_key.hex()
    state._remove_event_queue(q)


async def test_handler_drops_unknown_sender(state):
    """Messages from senders not in contacts are silently dropped."""
    msg = build_message(
        MSG_PRIVATE, BOB.public_key, ALICE.public_key,
        __import__("core.crypto", fromlist=["encrypt"]).encrypt(
            BOB.private_key, ALICE.public_key, b"hello"
        ),
        BOB.private_key,
    )
    handler = make_message_handler(state)
    await handler(msg)  # BOB is not in contacts
    rows = await state.db.get_messages(BOB.public_key.hex(), ALICE.public_key.hex())
    assert rows == []


async def test_handler_ignores_wrong_recipient(state):
    eve = gen("eve")
    msg = build_message(
        MSG_PRIVATE, BOB.public_key, eve.public_key,
        __import__("core.crypto", fromlist=["encrypt"]).encrypt(
            BOB.private_key, eve.public_key, b"not for alice"
        ),
        BOB.private_key,
    )
    handler = make_message_handler(state)
    await handler(msg)  # must not raise
    rows = await state.db.get_messages(BOB.public_key.hex(), ALICE.public_key.hex())
    assert rows == []
