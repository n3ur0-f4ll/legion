# Messaging layer

The messaging layer implements the application-level message semantics on top of the
core cryptography and storage. It handles payload construction, encryption, sanitization,
group lifecycle management, and the delivery queue.

---

## private.py

Private message exchange between two users. All payloads use a JSON envelope inside
the encrypted blob so the same message type can carry text or files.

### Payload envelope

The plaintext inside every private message ciphertext is a JSON object:

```json
{ "t": "hello world" }           // text message
{ "f": "<base64>", "n": "photo.jpg", "m": "image/jpeg" }  // file
```

This envelope is **inside** the Box ciphertext — the outer protocol layer only sees
an opaque encrypted blob.

### Functions

#### `send(db, identity, recipient_public_key, plaintext, ttl) → dict`
Sends a text message:

1. Encodes `{"t": plaintext}` to bytes
2. Encrypts with `crypto.encrypt(identity.private_key, recipient_public_key, payload)`
3. Calls `protocol.build_message()` to sign and create the protocol dict
4. Saves to `messages` table with `status="queued"`
5. Returns the message dict (caller enqueues it for delivery)

#### `send_file(db, identity, recipient_public_key, file_data, file_name, mime_type, ttl) → dict`
Sends a file:

1. Calls `files.prepare_outgoing_async()` — sanitizes and validates the file
2. Encodes `{"f": base64(sanitized), "n": file_name, "m": mime_type}`
3. Encrypts, builds message, saves with `file_name` and `mime_type` columns populated
4. Returns the message dict

Raises `FileError` if the file fails sanitization.

#### `receive(db, identity, msg) → dict`
Processes an incoming message after protocol validation:

1. Verifies `msg["to"] == identity.public_key.hex()`
2. Decrypts: `crypto.decrypt(identity.private_key, sender_public_key, ciphertext)`
3. Decodes the JSON envelope
4. If it's a file (`"f"` key): runs `files.sanitize_incoming_async()` — defense-in-depth
5. Saves to `messages` table with `status="delivered"`
6. Explicitly calls `update_message_status()` to ensure delivery status is set even if
   the message was already in the DB (e.g. from a sent copy — `INSERT OR IGNORE` would
   leave the old status)
7. Returns the decoded payload dict

#### `get_conversation(db, our_key, peer_key) → list[dict]`
Returns all messages between two users ordered by timestamp.
The result contains raw database rows with encrypted `payload` — decryption is done
on-the-fly in the API layer.

#### `_decode_payload(raw: bytes) → dict`
Decodes the JSON envelope. Falls back to raw text in two cases:

1. `raw` is not valid JSON (`json.JSONDecodeError` or `UnicodeDecodeError`)
2. `raw` is valid JSON but the result is not a dict with a `"t"` or `"f"` key

In both cases returns `{"t": raw.decode(errors="replace")}` for compatibility with any
pre-envelope messages.

---

## groups.py

Full group lifecycle: creation, invitations, posting, member management, and dissolution.
Groups use symmetric SecretBox encryption; all roster management messages use asymmetric
Box encryption (one copy per recipient).

### Data model

A group is stored as:
- One row in `groups`: `id, name, group_key (32 bytes), admin_key, is_admin, created_at`
- One row per member in `group_members`: `group_id, public_key, onion_address, alias_hint, added_at`

The `group_key` is the shared SecretBox key. `admin_key` is the public key of the creator.
`is_admin` is a local flag (True on the admin's node, False on members' nodes).

### Group ID

```python
group_id = SHA256(admin_public_key || name_bytes || timestamp_bytes).hexdigest()
```

64-character hex string. Deterministic from the admin's key, group name and creation time.
Used as the `to` field in `group_post` messages.

### Functions

#### `create_group(db, identity, name) → dict`
Creates a new group:

1. Generates a random 32-byte `group_key`
2. Computes `group_id`
3. Saves group to DB
4. Saves admin as first member with `onion_address=identity.onion_address` and
   `alias_hint=identity.alias` — the admin's onion must be in the roster for new
   members to be able to post back to them

#### `invite_member(db, identity, group_id, member_public_key, member_onion, ttl) → tuple[dict, list]`
Builds the invite and broadcasts the roster update to existing members:

1. Fetches current member list with `onion_address` and `alias_hint`
2. Resolves alias hints (prefer `contacts.alias`, fall back to stored `alias_hint`)
3. Builds invite JSON payload:
   ```json
   { "group_id": "...", "name": "...", "key": "<base64>", "members": [...] }
   ```
4. Box-encrypts the entire payload for the invitee — group metadata is not visible on wire
5. Builds a `group_member_update(op=add)` message for each existing member (Box-encrypted
   per recipient) containing the new member's key, onion and alias_hint
6. Saves new member to admin's `group_members` with their `onion_address` and `alias_hint`
7. Returns `(invite_msg, [(update_msg, destination_onion), ...])`

**Why Box-encrypt the invite payload?** The original approach stored group_id and name
in plaintext inside the payload. The current implementation Box-encrypts the entire
payload — only the invitee can read group metadata.

#### `accept_invite(db, identity, msg) → dict`
Processes a received `group_invite` after protocol validation:

1. Box-decrypts the payload (sender is admin)
2. Extracts group_id, name, group_key, member roster
3. Saves group to DB
4. Saves all roster members with their `onion_address` and `alias_hint`
5. Adds self if not already present (avoids overwriting admin's stored onion for us)
6. Returns group record (without group_key — not exposed to API callers)

#### `remove_member(db, identity, group_id, member_public_key, ttl) → tuple[bytes, list]`
Removes a member and rotates the group key:

1. Saves removed member's onion address **before** deleting (needed for notification)
2. Deletes member from `group_members`
3. Generates new `group_key` with `crypto.generate_group_key()`
4. Saves new key to DB
5. Builds notification to the removed member: `group_member_update(op=remove, public_key=their_key)`
6. For each remaining member builds:
   - `group_key_update`: new key Box-encrypted for them, TTL=30 days
   - `group_member_update(op=remove)`: notify that removed member is gone
7. Returns `(new_key, broadcasts)`

The removed member receives their notification and calls `delete_group` on their node.
Remaining members receive the new key and update their roster.

#### `leave_group(db, identity, group_id, ttl) → list`
Called before `DELETE /api/groups/{id}`. Two different paths:

**Admin dissolving the group:**
Sends each member a `group_member_update(op=remove, public_key=their_own_key, dissolved=True)`.
Each member receives a message where the public_key is their own → `removed_self` →
`delete_group`. The `dissolved=True` flag lets the GUI show "Group was dissolved by the admin"
instead of "You were removed".

**Regular member leaving:**
Sends each member `group_member_update(op=remove, public_key=self, voluntary=True)`.
The member signs their own departure — only they can claim to be leaving.
Upon receiving this, the admin's node automatically calls `remove_member()` to rotate the key.

#### `handle_member_update(db, identity, msg) → dict | None`
Processes an incoming `group_member_update`:

1. Box-decrypts payload
2. Looks up the group — ignores if unknown
3. **Authorization check:**
   - Accept from admin for any operation
   - Also accept `op=remove` where `public_key==msg["from"]` and `voluntary=True`
     (self-removal signed by the departing member)
4. For `op=add`: saves new member to `group_members`
5. For `op=remove` where `public_key==own_key`: calls `delete_group` (we were removed)
6. For `op=remove` other member: calls `delete_group_member`
7. Returns info dict for SSE event, including `voluntary` and `dissolved` flags

#### `handle_key_update(db, identity, msg) → str | None`
Processes an incoming `group_key_update`:

1. Box-decrypts payload
2. Verifies sender is the group admin
3. Validates new key is exactly 32 bytes
4. Calls `update_group_key()` to replace the key in DB
5. Returns `group_id` for SSE event, or None if ignored

#### `post(db, identity, group_id, plaintext, ttl) → dict`
Sends a group post:

1. Encrypts `plaintext.encode()` with `crypto.encrypt_group(group_key, plaintext)`
2. Builds protocol message with `to = bytes.fromhex(group_id)`
3. Saves to `group_posts`
4. Returns message dict — caller delivers to all members via `group_members.onion_address`

**Key difference from private messages:** posts use **SecretBox** (symmetric key shared by all
members), not Box (asymmetric per-recipient). One ciphertext is sent to all members.

#### `receive_post(db, identity, group_id, msg) → str`
Decrypts and stores an incoming post. Returns plaintext.
Raises `LookupError` if the group is unknown, `CryptoError` if decryption fails
(e.g. after receiving a `group_key_update` out of order).

---

## files.py

File validation and sanitization. CPU-bound Pillow operations run in an executor.

### Constants

| Constant | Value |
|---|---|
| `MAX_FILE_SIZE` | 5 MB |
| Supported MIME types | `image/jpeg`, `image/png`, `image/webp` |
| Blocked MIME types | `image/svg+xml`, `text/html`, `application/xhtml+xml` |

SVG is explicitly blocked because it can contain JavaScript.

### Functions

#### `prepare_outgoing(data, file_name, mime_type) → bytes`
Called on the sender side before encryption:

1. `_validate_size(data)` — rejects files over 5 MB
2. `_validate_file_name(file_name)` — rejects names with path separators, null bytes,
   hidden files (starting with `.`)
3. Rejects blocked MIME types
4. For image types: calls `_sanitize_image()`
5. For other types: passes through (size and name already validated)

#### `sanitize_incoming(data, mime_type) → bytes`
Called on the receiver side after decryption — defense-in-depth:
Even if the sender skipped sanitization or used a modified client, the receiver
sanitizes before saving. Re-validates size and re-sanitizes images.

#### `prepare_outgoing_async` / `sanitize_incoming_async`
Async wrappers using `asyncio.get_running_loop().run_in_executor(None, ...)`.
Pillow image operations are CPU-bound and must not block the event loop.

#### `_sanitize_image(data, mime_type) → bytes`
Core sanitization:

1. Checks magic bytes against declared MIME type (e.g. `\xff\xd8\xff` for JPEG)
2. `Image.open(io.BytesIO(data))` + `img.load()` — full decode, catches truncated images
3. Converts JPEG to RGB or L mode if needed
4. Saves to a new `BytesIO` buffer with **no** `exif`, `icc_profile` or metadata kwargs
5. Returns the new bytes

Re-encoding from scratch is more thorough than clearing specific metadata fields —
it is impossible to smuggle data in format-specific metadata structures that Pillow
does not understand.

### `FileError` (exception)
Raised on size violation, invalid filename, blocked type, magic bytes mismatch,
or image decode failure.

---

## delivery.py

Persistent background queue that retries message delivery every 10 seconds until
the message is delivered or the user cancels it. State is stored in SQLite so
the queue survives application restarts.

### `DeliveryQueue` (class)

```python
DeliveryQueue(db: Database, sender: Sender, on_delivered: OnDelivered | None)
```

`sender` is `async (msg_dict: dict, onion: str) → None` — the actual network send function.
`on_delivered` is `async (message_id: str) → None` — called after successful delivery
(used by `AppState.on_message_delivered` to push `delivery_status` SSE event).

#### `enqueue(msg, destination_onion, via_relay) → None`
Adds a message to the delivery queue for immediate first attempt:

1. Computes deterministic entry id: `SHA256(message_id:destination_key)`
2. Sets `next_retry_at = int(time.time())` (due immediately)
3. `INSERT OR IGNORE` — duplicate entries for the same message+destination are silently dropped
4. Calls `self._wake.set()` — wakes the delivery loop immediately rather than waiting 10 seconds

#### `process_due(now) → tuple[int, int]`
Fetches all due entries (`next_retry_at <= now`) and calls `_try_deliver()` for each.
Returns `(sent, failed)` counts.

#### `start() / stop()`
Starts/stops the background `asyncio.Task` running `_loop()`.

#### `_loop() → None`
Main delivery loop:
```python
while running:
    await process_due()
    self._wake.clear()
    try:
        await asyncio.wait_for(self._wake.wait(), timeout=10)
    except asyncio.TimeoutError:
        pass
```
Sleeps 10 seconds OR wakes immediately if `_wake` is set by `enqueue()`.

#### `_try_deliver(entry, now) → bool | None`
Attempts delivery of one queue entry:

1. Loads `msg_dict` from `entry["message_json"]`
2. Checks if the message has expired (`now - timestamp > ttl`) — removes orphans silently
3. Calls `await self._sender(msg_dict, entry["destination_onion"])`
4. **On success:** dequeues, updates message status to `"delivered"`, calls `on_delivered`
5. **On failure:** updates `next_retry_at = now + 10` and increments `retry_count`

Returns `True` (sent), `False` (failed, retry scheduled), or `None` (orphan removed).

There is no maximum retry count — the queue retries indefinitely until the message
is delivered or the user cancels via `DELETE /api/messages/{id}`.

### Type aliases

```python
Sender      = Callable[[dict, str], Awaitable[None]]   # (msg_dict, onion) → None
OnDelivered = Callable[[str], Awaitable[None]]          # (message_id) → None
```
