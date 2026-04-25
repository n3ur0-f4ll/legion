
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
Lokalny API serwer FastAPI dla interfejsu GUI.

Nasłuchuje wyłącznie na 127.0.0.1 — nigdy na 0.0.0.0.
Udostępnia REST API do zarządzania tożsamością, kontaktami,
wiadomościami i grupami. Strumień SSE /api/events informuje GUI
o przychodzących wiadomościach i zdarzeniach stanu węzła.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core import crypto
from core.identity import (
    Identity,
    decrypt_private_key,
    derive_onion_address,
    encrypt_private_key,
    generate as generate_identity,
)
from core.protocol import (
    validate_contact_card,
    MalformedMessage,
    InvalidSignature,
)
from core.storage import Database
from messaging import private, groups
from messaging.delivery import DeliveryQueue
from network.relay import choose_destination


# ------------------------------------------------------------------
# Application state
# ------------------------------------------------------------------

@dataclass
class AppState:
    """Runtime state shared across all request handlers."""

    db: Database
    delivery_queue: DeliveryQueue
    identity: Identity | None = None
    tor_onion: str = ""
    _event_queues: list[asyncio.Queue] = field(default_factory=list)

    def push_event(self, event_type: str, data: dict) -> None:
        payload = {"type": event_type, **data}
        for q in self._event_queues:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def _add_event_queue(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._event_queues.append(q)
        return q

    def _remove_event_queue(self, q: asyncio.Queue) -> None:
        try:
            self._event_queues.remove(q)
        except ValueError:
            pass


# ------------------------------------------------------------------
# Request / Response models
# ------------------------------------------------------------------

class CreateIdentityRequest(BaseModel):
    alias: str
    password: str


class ContactCardRequest(BaseModel):
    v: int
    public_key: str
    onion_address: str
    alias_hint: str | None = None
    signature: str


class SendMessageRequest(BaseModel):
    to: str        # hex public key of recipient
    text: str
    onion: str     # recipient's .onion address


class CreateGroupRequest(BaseModel):
    name: str


class InviteMemberRequest(BaseModel):
    public_key: str  # hex
    onion: str       # member's .onion address for delivery


class PostGroupRequest(BaseModel):
    text: str


# ------------------------------------------------------------------
# App factory
# ------------------------------------------------------------------

def create_app(state: AppState) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(title="Legion Node API", docs_url=None, redoc_url=None)
    app.state.app_state = state

    # Allow pywebview's local HTTP server (any localhost port) to access the API
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_state() -> AppState:
        return app.state.app_state

    def require_identity(s: AppState = Depends(get_state)) -> tuple[AppState, Identity]:
        if s.identity is None:
            raise HTTPException(status_code=503, detail="Identity not loaded")
        return s, s.identity

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    @app.post("/api/identity/create", status_code=201)
    async def create_identity(
        req: CreateIdentityRequest,
        s: AppState = Depends(get_state),
    ):
        if s.identity is not None:
            raise HTTPException(status_code=409, detail="Identity already exists")

        identity = generate_identity(req.alias)
        encrypted = encrypt_private_key(identity.private_key, req.password)
        await s.db.save_identity(
            public_key=identity.public_key.hex(),
            private_key=encrypted,
            onion_address=identity.onion_address,
            alias=identity.alias,
            created_at=int(time.time()),
        )
        s.identity = identity
        return {
            "public_key": identity.public_key.hex(),
            "onion_address": identity.onion_address,
            "alias": identity.alias,
        }

    @app.get("/api/identity")
    async def get_identity(deps=Depends(require_identity)):
        _, identity = deps
        return {
            "public_key": identity.public_key.hex(),
            "onion_address": identity.onion_address,
            "alias": identity.alias,
        }

    # ------------------------------------------------------------------
    # Contacts
    # ------------------------------------------------------------------

    @app.get("/api/contacts")
    async def get_contacts(s: AppState = Depends(get_state)):
        return await s.db.get_contacts()

    @app.post("/api/contacts", status_code=201)
    async def add_contact(req: ContactCardRequest, s: AppState = Depends(get_state)):
        # exclude_none so alias_hint absence doesn't break signature verification
        card = req.model_dump(exclude_none=True)
        try:
            validate_contact_card(card)
        except (MalformedMessage, InvalidSignature) as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        await s.db.save_contact(
            public_key=card["public_key"],
            onion_address=card["onion_address"],
            alias=card.get("alias_hint"),
            trusted_since=int(time.time()),
        )
        return await s.db.get_contact(card["public_key"])

    @app.delete("/api/contacts/{public_key}", status_code=204)
    async def delete_contact(public_key: str, s: AppState = Depends(get_state)):
        if await s.db.get_contact(public_key) is None:
            raise HTTPException(status_code=404, detail="Contact not found")
        await s.db.delete_contact(public_key)

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    @app.get("/api/messages/{public_key}")
    async def get_messages(public_key: str, deps=Depends(require_identity)):
        s, identity = deps
        return await private.get_conversation(s.db, identity.public_key, bytes.fromhex(public_key))

    @app.post("/api/messages", status_code=201)
    async def send_message(req: SendMessageRequest, deps=Depends(require_identity)):
        s, identity = deps
        try:
            recipient_key = bytes.fromhex(req.to)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid public key")

        msg = await private.send(s.db, identity, recipient_key, req.text)
        destination_onion, via_relay = await choose_destination(s.db, req.onion)
        await s.delivery_queue.enqueue(msg, destination_onion, via_relay=via_relay)
        return {"id": msg["id"], "status": "queued"}

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    @app.get("/api/groups")
    async def get_groups(s: AppState = Depends(get_state)):
        return [_group_safe(g) for g in await s.db.get_groups()]

    @app.post("/api/groups", status_code=201)
    async def create_group(req: CreateGroupRequest, deps=Depends(require_identity)):
        s, identity = deps
        return _group_safe(await groups.create_group(s.db, identity, req.name))

    @app.post("/api/groups/{group_id}/invite", status_code=201)
    async def invite_member(
        group_id: str,
        req: InviteMemberRequest,
        deps=Depends(require_identity),
    ):
        s, identity = deps
        try:
            member_key = bytes.fromhex(req.public_key)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid public key")

        try:
            msg = await groups.invite_member(s.db, identity, group_id, member_key)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

        await s.delivery_queue.enqueue(msg, req.onion, via_relay=False)
        return {"id": msg["id"], "status": "queued"}

    @app.get("/api/groups/{group_id}/posts")
    async def get_posts(group_id: str, s: AppState = Depends(get_state)):
        return await groups.get_posts(s.db, group_id)

    @app.post("/api/groups/{group_id}/posts", status_code=201)
    async def create_post(
        group_id: str,
        req: PostGroupRequest,
        deps=Depends(require_identity),
    ):
        s, identity = deps
        try:
            msg = await groups.post(s.db, identity, group_id, req.text)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        # Deliver to all group members
        members = await s.db.get_group_members(group_id)
        our_hex = identity.public_key.hex()
        for member in members:
            if member["public_key"] == our_hex:
                continue
            contact = await s.db.get_contact(member["public_key"])
            if contact:
                dst, via_relay = await choose_destination(s.db, contact["onion_address"])
                await s.delivery_queue.enqueue(msg, dst, via_relay=via_relay)

        return {"id": msg["id"], "status": "queued"}

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @app.get("/api/status")
    async def get_status(s: AppState = Depends(get_state)):
        return {
            "identity_loaded": s.identity is not None,
            "onion_address": s.tor_onion or (s.identity.onion_address if s.identity else ""),
            "relay_configured": await _relay_active(s.db),
        }

    # ------------------------------------------------------------------
    # SSE events
    # ------------------------------------------------------------------

    @app.get("/api/events")
    async def sse_events(s: AppState = Depends(get_state)):
        async def stream() -> AsyncIterator[str]:
            q = s._add_event_queue()
            try:
                while True:
                    event = await q.get()
                    yield f"data: {json.dumps(event)}\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                s._remove_event_queue(q)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


# ------------------------------------------------------------------
# Incoming message handler (called by NodeServer)
# ------------------------------------------------------------------

def make_message_handler(state: AppState):
    """Return an async handler to pass to NodeServer.start().

    Decrypts incoming messages, stores them, and pushes SSE events.
    """
    async def handler(msg: dict) -> None:
        if state.identity is None:
            return

        msg_type = msg.get("type")

        if msg_type == "msg":
            try:
                plaintext = await private.receive(state.db, state.identity, msg)
                state.push_event("message", {
                    "from": msg["from"],
                    "id": msg["id"],
                })
            except Exception:
                pass  # bad decryption or wrong recipient — silent drop

        elif msg_type == "group_invite":
            try:
                group = await groups.accept_invite(state.db, state.identity, msg)
                state.push_event("group_invite", {"group_id": group["id"]})
            except Exception:
                pass

        # group_post and delivery_ack are handled by the relay/delivery layer

    return handler


# ------------------------------------------------------------------
# Runner
# ------------------------------------------------------------------

async def run_app(state: AppState, port: int = 8080) -> None:
    """Start uvicorn bound to 127.0.0.1 only."""
    app = create_app(state)
    config = uvicorn.Config(
        app,
        host="127.0.0.1",  # NEVER 0.0.0.0
        port=port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    await server.serve()


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _group_safe(group: dict) -> dict:
    """Strip group_key (binary secret) from API responses."""
    return {k: v for k, v in group.items() if k != "group_key"}


async def _relay_active(db: Database) -> bool:
    config = await db.load_relay_config()
    return config is not None and bool(config["enabled"])
