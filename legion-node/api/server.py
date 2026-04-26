
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
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)

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
from messaging.files import FileError
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
    tor_manager: object | None = None   # TorManager — typed as object to avoid circular import
    node_port: int = 8765
    _tor_starting: bool = False
    tor_error: str = ""
    _event_queues: list[asyncio.Queue] = field(default_factory=list)

    async def on_message_delivered(self, message_id: str) -> None:
        """Called by DeliveryQueue when a message is successfully delivered."""
        self.push_event("delivery_status", {"id": message_id, "status": "delivered"})

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
    to: str           # hex public key of recipient
    onion: str        # recipient's .onion address
    text: str | None = None
    file_data: str | None = None   # base64-encoded file bytes
    file_name: str | None = None
    mime_type: str | None = None


class CreateGroupRequest(BaseModel):
    name: str


class InviteMemberRequest(BaseModel):
    public_key: str  # hex
    onion: str       # member's .onion address for delivery


class PostGroupRequest(BaseModel):
    text: str


class UnlockRequest(BaseModel):
    password: str


class AliasRequest(BaseModel):
    alias: str


# ------------------------------------------------------------------
# App factory
# ------------------------------------------------------------------

async def _start_tor_background(state: AppState) -> None:
    """Start Tor hidden service in background after identity becomes available."""
    if state._tor_starting or not state.tor_manager or not state.identity:
        return
    tm = state.tor_manager
    if hasattr(tm, "is_running") and tm.is_running:
        return
    state._tor_starting = True
    state.tor_error = ""
    state.push_event("tor_status", {"status": "starting"})
    try:
        onion = await tm.start(state.identity.private_key, hs_port=state.node_port)
        state.tor_onion = onion
        logger.info("Hidden service started: %s", onion)
        state.push_event("tor_ready", {"onion_address": onion})
    except Exception as exc:
        state.tor_error = str(exc)
        logger.error("Tor start failed: %s", exc)
        state.push_event("tor_status", {"status": "error", "error": str(exc)})
    finally:
        state._tor_starting = False


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

    @app.post("/api/identity/unlock")
    async def unlock_identity(req: UnlockRequest, s: AppState = Depends(get_state)):
        if s.identity is not None:
            return {
                "public_key": s.identity.public_key.hex(),
                "onion_address": s.identity.onion_address,
                "alias": s.identity.alias,
            }
        row = await s.db.load_identity()
        if row is None:
            raise HTTPException(status_code=404, detail="No identity found")
        try:
            private_key = decrypt_private_key(row["private_key"], req.password)
        except Exception:
            raise HTTPException(status_code=401, detail="Wrong password")
        s.identity = Identity(
            public_key=bytes.fromhex(row["public_key"]),
            private_key=private_key,
            onion_address=row["onion_address"],
            alias=row["alias"],
        )
        asyncio.create_task(_start_tor_background(s))
        return {
            "public_key": s.identity.public_key.hex(),
            "onion_address": s.identity.onion_address,
            "alias": s.identity.alias,
        }

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
        asyncio.create_task(_start_tor_background(s))
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

    @app.delete("/api/identity", status_code=204)
    async def panic_delete(s: AppState = Depends(get_state)):
        """Panic button — wipe all data, clear in-memory identity."""
        await s.db.panic_wipe()
        s.identity = None

    @app.patch("/api/identity/alias")
    async def update_alias(req: AliasRequest, deps=Depends(require_identity)):
        s, identity = deps
        alias = req.alias.strip()
        if not alias:
            raise HTTPException(status_code=422, detail="Alias cannot be empty")
        await s.db.update_identity_alias(alias)
        # Update in-memory identity
        s.identity = identity.__class__(
            public_key=identity.public_key,
            private_key=identity.private_key,
            onion_address=identity.onion_address,
            alias=alias,
        )
        return {"alias": alias}

    @app.get("/api/identity/card")
    async def get_contact_card(deps=Depends(require_identity)):
        """Return a signed contact card ready to share with other users."""
        from core.protocol import build_contact_card
        _, identity = deps
        return build_contact_card(
            identity.public_key,
            identity.onion_address,
            identity.private_key,
            alias_hint=identity.alias,
        )

    # ------------------------------------------------------------------
    # Contacts
    # ------------------------------------------------------------------

    @app.get("/api/contacts")
    async def get_contacts(s: AppState = Depends(get_state)):
        contacts = await s.db.get_contacts()
        if s.identity:
            unread = await s.db.get_unread_counts(s.identity.public_key.hex())
            for c in contacts:
                c["unread_count"] = unread.get(c["public_key"], 0)
        return contacts

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

    @app.patch("/api/contacts/{public_key}/alias")
    async def update_contact_alias(
        public_key: str, req: AliasRequest, s: AppState = Depends(get_state)
    ):
        if await s.db.get_contact(public_key) is None:
            raise HTTPException(status_code=404, detail="Contact not found")
        alias = req.alias.strip()
        if not alias:
            raise HTTPException(status_code=422, detail="Alias cannot be empty")
        await s.db.update_contact_alias(public_key, alias)
        return {"alias": alias}

    @app.delete("/api/contacts/{public_key}", status_code=204)
    async def delete_contact(public_key: str, s: AppState = Depends(get_state)):
        if await s.db.get_contact(public_key) is None:
            raise HTTPException(status_code=404, detail="Contact not found")
        await s.db.delete_contact(public_key)
        await s.db.delete_messages_with_peer(public_key)

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    @app.post("/api/messages/{public_key}/read", status_code=204)
    async def mark_read(public_key: str, deps=Depends(require_identity)):
        s, identity = deps
        await s.db.mark_conversation_read(public_key, identity.public_key.hex())

    @app.get("/api/messages/{public_key}")
    async def get_messages(public_key: str, deps=Depends(require_identity)):
        s, identity = deps
        rows = await private.get_conversation(
            s.db, identity.public_key, bytes.fromhex(public_key)
        )
        return [_decrypt_message(row, identity) for row in rows]

    @app.post("/api/messages", status_code=201)
    async def send_message(req: SendMessageRequest, deps=Depends(require_identity)):
        s, identity = deps
        try:
            recipient_key = bytes.fromhex(req.to)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid public key")

        if req.file_data is not None:
            if not req.file_name or not req.mime_type:
                raise HTTPException(status_code=422, detail="file_name and mime_type required")
            try:
                file_bytes = base64.b64decode(req.file_data)
                msg = await private.send_file(
                    s.db, identity, recipient_key,
                    file_bytes, req.file_name, req.mime_type,
                )
            except FileError as exc:
                raise HTTPException(status_code=422, detail=str(exc))
        else:
            msg = await private.send(s.db, identity, recipient_key, req.text or "")

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

    @app.delete("/api/groups/{group_id}", status_code=204)
    async def delete_group(group_id: str, s: AppState = Depends(get_state)):
        if await s.db.get_group(group_id) is None:
            raise HTTPException(status_code=404, detail="Group not found")
        await s.db.delete_group(group_id)

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
        group = await s.db.get_group(group_id)
        group_key = group["group_key"] if group else None
        posts = await groups.get_posts(s.db, group_id)
        return [_decrypt_post(row, group_key) for row in posts]

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

    @app.post("/api/tor/retry", status_code=202)
    async def retry_tor(deps=Depends(require_identity)):
        s, _ = deps
        if s._tor_starting:
            return {"status": "already_starting"}
        if s.tor_onion:
            return {"status": "already_running"}
        asyncio.create_task(_start_tor_background(s))
        return {"status": "starting"}

    @app.get("/api/status")
    async def get_status(s: AppState = Depends(get_state)):
        row = await s.db.load_identity()
        tor_running = bool(s.tor_onion)
        tor_starting = s._tor_starting
        return {
            "identity_loaded": s.identity is not None,
            "identity_exists": row is not None,
            "onion_address": s.tor_onion,
            "tor_running": tor_running,
            "tor_starting": tor_starting,
            "tor_error": s.tor_error,
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

    Only processes messages from known contacts or group members.
    Unknown senders are silently dropped — no response, no log.
    """
    async def handler(msg: dict) -> None:
        if state.identity is None:
            return

        sender = msg.get("from", "")
        msg_type = msg.get("type")

        if msg_type == "msg":
            if not await state.db.is_contact(sender):
                return  # silent drop — unknown sender
            try:
                await private.receive(state.db, state.identity, msg)
                state.push_event("message", {"from": sender, "id": msg["id"]})
            except Exception:
                pass

        elif msg_type == "group_invite":
            if not await state.db.is_contact(sender):
                return  # only accept invites from known contacts
            try:
                group = await groups.accept_invite(state.db, state.identity, msg)
                state.push_event("group_invite", {"group_id": group["id"]})
            except Exception:
                pass

        elif msg_type == "group_post":
            group_id = msg.get("to", "")
            if not await state.db.is_group_member(group_id, sender):
                return  # not a member of this group — silent drop
            try:
                await groups.receive_post(state.db, state.identity, group_id, msg)
                state.push_event("group_post", {
                    "group_id": group_id,
                    "from": sender,
                    "id": msg["id"],
                })
            except Exception:
                pass

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


def _decrypt_message(row: dict, identity) -> dict:
    """Decrypt message payload, return text or file_data in result dict."""
    import json as _json
    result = dict(row)
    result.pop("payload", None)
    result.pop("signature", None)
    result["text"] = None
    result["file_data"] = None

    try:
        our_hex = identity.public_key.hex()
        peer_hex = row["from_key"] if row["from_key"] != our_hex else row["to_key"]
        raw = crypto.decrypt(identity.private_key, bytes.fromhex(peer_hex), row["payload"])
        try:
            envelope = _json.loads(raw)
            if "f" in envelope:
                result["file_data"] = envelope["f"]   # base64
            else:
                result["text"] = envelope.get("t", "")
        except Exception:
            result["text"] = raw.decode(errors="replace")  # legacy
    except Exception:
        result["text"] = None

    return result


def _decrypt_post(row: dict, group_key: bytes | None) -> dict:
    """Add decrypted 'text' field to a group post row. Sets text=None on failure."""
    result = dict(row)
    try:
        if group_key is None:
            raise ValueError("no group key")
        result["text"] = crypto.decrypt_group(group_key, row["payload"]).decode()
    except Exception:
        result["text"] = None
    result.pop("payload", None)
    result.pop("signature", None)
    return result


async def _relay_active(db: Database) -> bool:
    config = await db.load_relay_config()
    return config is not None and bool(config["enabled"])
