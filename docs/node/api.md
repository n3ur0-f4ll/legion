# API server

`api/server.py` contains the FastAPI application, all REST endpoints, the SSE event
stream, the incoming message handler, and the `AppState` shared runtime object.

---

## AppState

```python
@dataclass
class AppState:
    db: Database
    delivery_queue: DeliveryQueue
    identity: Identity | None = None
    tor_onion: str = ""
    tor_manager: object | None = None
    node_port: int = 8765
    _tor_starting: bool = False
    tor_error: str = ""
    _event_queues: list[asyncio.Queue] = field(default_factory=list)
    _log_ring: deque = field(default_factory=lambda: deque(maxlen=200))
```

One instance is created in `main.py` and passed to the FastAPI app. Every request
handler receives it via `Depends(get_state)`.

#### `push_event(event_type, data) → None`
Pushes a dict into every active SSE subscriber's queue (`maxsize=100` per subscriber).
`QueueFull` is silently ignored — the GUI will refresh on the next user action.

#### `push_network_log(level, category, text) → None`
Appends a `network_log` entry to `_log_ring` (for SSE backfill on reconnect)
and calls `push_event()`. Bandwidth events (`level="bw"`) are streamed but not persisted
in the ring — too frequent to be useful in history.

#### `on_message_delivered(message_id) → None`
Async callback passed to `DeliveryQueue`. Pushes `delivery_status` SSE event and
a delivery log entry.

---

## `create_app(state) → FastAPI`

Factory function. Creates and configures the FastAPI application:

- `docs_url=None, redoc_url=None` — API documentation endpoints disabled
- Adds `CORSMiddleware` with `allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?"`
  — allows only localhost origins (pywebview's embedded HTTP server)

### Dependency functions

#### `get_state() → AppState`
Returns `app.state.app_state`. Injected into every endpoint.

#### `require_identity(s) → tuple[AppState, Identity]`
Returns `(state, state.identity)` or raises HTTP 503 if identity is not loaded.
Used by all endpoints that require an unlocked identity.

---

## Endpoints

### Identity

#### `POST /api/identity/unlock`
Unlocks an existing identity with a password:

1. Returns current identity if already unlocked (idempotent)
2. Loads identity row from DB
3. Calls `decrypt_private_key(row["private_key"], password)`
4. Raises HTTP 401 on wrong password
5. Sets `state.identity`
6. Launches `_start_tor_background(state)` as an asyncio task
7. Returns `{public_key, onion_address, alias, default_ttl}`

#### `POST /api/identity/create` (201)
Creates a new identity:

1. Raises HTTP 409 if identity already exists
2. Calls `generate_identity(alias)`
3. Encrypts private key with `encrypt_private_key(private_key, password)`
4. Saves to DB
5. Sets `state.identity`, launches Tor background task
6. Returns `{public_key, onion_address, alias, default_ttl}`

#### `GET /api/identity`
Returns identity info including `default_ttl`.

#### `PATCH /api/identity/alias`
Updates alias in DB and replaces the in-memory `Identity` instance (frozen dataclass).

#### `PATCH /api/identity/default_ttl`
Updates `default_ttl`. Clamps to `[3600, 2592000]` (1 hour – 30 days).

#### `GET /api/identity/card`
Returns a signed contact card via `protocol.build_contact_card()`.

#### `DELETE /api/identity` (204) — Panic Button
1. `db.panic_wipe()` — deletes all rows from all tables, then runs `VACUUM`
2. Sets `state.identity = None`

No authentication required — by design, so it can be triggered in an emergency
even if the identity flow is in an unusual state.

---

### Contacts

#### `GET /api/contacts`
Returns all contacts. If identity is loaded, enriches each with `unread_count`
(count of unread incoming messages).

#### `POST /api/contacts` (201)
Adds a contact from a contact card JSON:

1. Calls `validate_contact_card(card)` — verifies Ed25519 signature
2. Raises HTTP 422 on invalid card
3. Saves contact with `alias = card.alias_hint` and `trusted_since = now`

#### `PATCH /api/contacts/{public_key}/alias`
Updates the local alias for a contact.

#### `DELETE /api/contacts/{public_key}` (204)
Deletes contact and all message history with that contact.

---

### Messages

#### `DELETE /api/messages/{message_id}` (204)
Cancels delivery retries for a queued message:

1. `db.cancel_queued(message_id)` — removes from delivery queue
2. `db.update_message_status(message_id, "failed")`

#### `POST /api/messages/{public_key}/read` (204)
Marks all incoming messages from `public_key` as read (`read_at = now`).

#### `GET /api/messages/{public_key}`
Returns all messages in a conversation, decrypted on-the-fly by `_decrypt_message()`.
Each message includes `text` (plaintext or null) and `file_data` (base64 or null).

#### `POST /api/messages` (201)
Sends a message:

1. Resolves TTL: `req.ttl` → `identity.default_ttl` → `DEFAULT_TTL` (7 days)
2. If `file_data`: decodes base64, calls `private.send_file()` (includes sanitization)
3. Otherwise: calls `private.send()`
4. Calls `choose_destination()` to decide direct vs relay routing
5. Enqueues in delivery queue

---

### Groups

#### `GET /api/groups`
Returns all groups with `unread_count` (posts since `last_read_at`, excluding own posts).

#### `POST /api/groups` (201)
Creates a group via `groups.create_group()`.

#### `DELETE /api/groups/{id}` (204)
Leaves or dissolves the group:

1. Calls `groups.leave_group()` to build leave notifications
2. Enqueues all notifications in delivery queue
3. Calls `db.delete_group()` to remove locally

#### `GET /api/groups/{id}/members`
Returns member list enriched with `alias` (priority: `contacts.alias` → `group_members.alias_hint`)
and `is_admin` flag.

#### `DELETE /api/groups/{id}/members/{member_key}` (204)
Admin removes a member:

1. Calls `groups.remove_member()` — generates new key, builds broadcasts
2. Enqueues all broadcasts

#### `POST /api/groups/{id}/invite` (201)
Invites a member:

1. Calls `groups.invite_member()` — builds invite + update broadcasts
2. Enqueues invite to the new member
3. Enqueues `group_member_update(op=add)` to all existing members

#### `POST /api/groups/{id}/read` (204)
Sets `last_read_at = now` for the group.

#### `GET /api/groups/{id}/posts`
Returns all posts decrypted on-the-fly. Enriches each with `author_alias`
(priority: `contacts.alias` → `group_members.alias_hint`).

#### `POST /api/groups/{id}/posts` (201)
Posts to a group:

1. Calls `groups.post()` — SecretBox encrypts, signs, saves locally
2. Delivers to every member using `group_members.onion_address` (peer-to-peer routing)

---

### Status and Tor

#### `GET /api/status`
Returns node state:
```json
{
  "identity_loaded": true,
  "identity_exists": true,
  "onion_address": "xxx.onion",
  "tor_running": true,
  "tor_starting": false,
  "tor_error": "",
  "relay_configured": false
}
```

#### `POST /api/tor/retry` (202)
Retries Tor startup if it previously failed.

---

### SSE event stream

#### `GET /api/events`
Server-Sent Events stream. On connection:

1. **Backfill:** sends all entries from `_log_ring` (up to 200 past `network_log` events)
2. **Live:** streams events as they arrive

Each event is `data: {json}\n\n`.

| Event type | Fields | Trigger |
|---|---|---|
| `message` | `from, id` | Incoming private message received |
| `group_post` | `group_id, from, id` | Incoming group post received |
| `group_invite` | `group_id` | Group invite accepted |
| `group_member_update` | `from, op, group_id, public_key, alias_hint, group_name, voluntary?, dissolved?` | Roster change |
| `group_key_update` | `from, group_id` | Group key rotated |
| `delivery_status` | `id, status` | Message delivered |
| `tor_ready` | `onion_address` | Hidden Service published |
| `tor_status` | `status, error?` | Tor starting or failed |
| `network_log` | `level, category, text, ts` | Network activity log entry |

---

## `_start_tor_background(state) → None`

Async function launched as `asyncio.create_task()` after identity unlock.

1. Guards against double-start (`_tor_starting` flag, `tm.is_running` check)
2. Pushes `tor_status(starting)` SSE event
3. Pushes `network_log` entry
4. Calls `await tm.start(identity.private_key, hs_port=state.node_port)`
5. On success: updates `state.tor_onion`, pushes `tor_ready` event, attaches Stem event listener
6. On failure: stores error in `state.tor_error`, pushes `tor_status(error)`

The Stem listener callback wraps `state.push_network_log` with `loop.call_soon_threadsafe()`
to safely cross the thread boundary from Stem's event thread.

---

## `make_message_handler(state) → MessageHandler`

Returns the async handler passed to `NodeServer.start()`. Called for every valid
incoming WebSocket message.

Dispatch by `msg_type`:

| Type | Action |
|---|---|
| `"msg"` | Verify sender is in contacts → `private.receive()` → push `message` SSE |
| `"group_invite"` | Verify sender is in contacts → `groups.accept_invite()` → push `group_invite` SSE |
| `"group_post"` | Verify sender is a group member → `groups.receive_post()` → push `group_post` SSE |
| `"group_member_update"` | `groups.handle_member_update()` → push SSE; if admin receives voluntary leave → auto-rotate key via `groups.remove_member()` |
| `"group_key_update"` | `groups.handle_key_update()` → push `group_key_update` SSE |

**Unknown type or failed authorization:** silent drop, no response.
`state.identity is None` check at entry — drops all messages if the identity is not loaded.

---

## `run_app(state, port) → None`

Starts uvicorn bound to `127.0.0.1` only:
```python
uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
```
Never binds to `0.0.0.0`. Uvicorn access logs are suppressed.

---

## Helper functions

#### `_decrypt_message(row, identity) → dict`
Decrypts a message row for API response:

1. Determines peer key: if `from_key == our_key` then peer is `to_key`, and vice versa
2. Calls `crypto.decrypt(our_private, peer_public, payload)`
3. Parses the JSON envelope
4. Returns dict with `text` (str or null) and `file_data` (base64 str or null)
5. Removes raw `payload` and `signature` from the response

#### `_decrypt_post(row, group_key) → dict`
Decrypts a group post row. Returns `text` field (or null on failure).

#### `_group_safe(group) → dict`
Removes `group_key` from the group dict before returning to the GUI.
The raw 32-byte symmetric key is never sent to the frontend.

#### TTL resolution constants
```python
_TTL_MIN = 3_600      # 1 hour
_TTL_MAX = 2_592_000  # 30 days
```
