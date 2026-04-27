# Core layer

The core layer provides the fundamental building blocks: cryptographic identity,
all cryptographic operations, database access, and the network message protocol.
No module in this layer initiates network connections or holds application state.

---

## identity.py

Manages the user's Ed25519 keypair and its storage. All operations are pure functions
or dataclass methods — no side effects beyond what the caller requests.

### `Identity` (dataclass, frozen)

```python
@dataclass(frozen=True)
class Identity:
    public_key: bytes       # 32 bytes — Ed25519 verify key, also encodes the .onion address
    private_key: bytes      # 32 bytes — Ed25519 seed, never leaves the device in plaintext
    onion_address: str      # deterministic v3 .onion derived from public_key
    alias: str              # local display name, not transmitted unless included in contact card
```

Frozen — once created the object is immutable. When the alias changes, a new `Identity`
instance is constructed from the same keys.

### Functions

#### `generate(alias: str) → Identity`
Generates a fresh Ed25519 keypair using `nacl.signing.SigningKey.generate()` (CSPRNG).
Derives the `.onion` address deterministically. Returns a new `Identity`.
Called once, during `POST /api/identity/create`.

#### `encrypt_private_key(private_key: bytes, password: str) → bytes`
Protects the private key seed for storage on disk:

1. Generates 16 random bytes of salt (`nacl.utils.random`)
2. Derives a 32-byte encryption key from the password using **Argon2id**
   (`OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`)
3. Encrypts the seed with **XSalsa20-Poly1305 (SecretBox)**
4. Returns `salt (16 bytes) || ciphertext`

Raises `ValueError` if `private_key` is not 32 bytes.

#### `decrypt_private_key(blob: bytes, password: str) → bytes`
Reverses `encrypt_private_key`. Splits `blob` into salt and ciphertext, re-derives
the encryption key with Argon2id, decrypts with SecretBox.
Raises `nacl.exceptions.CryptoError` on wrong password or corrupted blob.
Called during `POST /api/identity/unlock`.

#### `signing_key(identity: Identity) → nacl.signing.SigningKey`
Reconstructs a libsodium `SigningKey` from the stored 32-byte seed.
Used by `crypto.sign()` and wherever Tor needs the expanded private key.

#### `derive_onion_address(public_key: bytes) → str`
Implements the Tor v3 Hidden Service address specification:
```
address = base32(public_key || SHA3-256(".onion checksum" || public_key || \x03)[0:2] || \x03) + ".onion"
```
The address is a pure function of the public key — identical input always produces
identical output. Called at identity generation and at Tor HS registration to verify
the address matches.

---

## crypto.py

Thin wrappers around libsodium (PyNaCl) operations. No state, no I/O.
Every function either succeeds or raises a `nacl.exceptions` error.

### Key type notes

Legion identity keys are Ed25519. For Box encryption (asymmetric), they are converted
to Curve25519 via libsodium's `crypto_sign_ed25519_sk_to_curve25519` and
`crypto_sign_ed25519_pk_to_curve25519`. This conversion is a well-established technique
used by OpenSSH and other protocols. The conversion is transparent — callers always
pass Ed25519 keys.

### Functions

#### `sign(private_key: bytes, data: bytes) → bytes`
Signs `data` with an Ed25519 private key seed. Returns 64-byte signature.

#### `verify(public_key: bytes, data: bytes, signature: bytes) → None`
Verifies an Ed25519 signature. Raises `nacl.exceptions.BadSignatureError` on failure.
Callers treat any exception as invalid and drop the message silently.

#### `encrypt(sender_private_key: bytes, recipient_public_key: bytes, plaintext: bytes) → bytes`
Asymmetric authenticated encryption (Box):

1. Converts both Ed25519 keys to Curve25519
2. Performs X25519 key exchange
3. Encrypts with XSalsa20-Poly1305 with a random nonce
4. Returns `nonce (24 bytes) || ciphertext`

Used for: private messages, group invites, group roster updates, key rotation messages.

#### `decrypt(recipient_private_key: bytes, sender_public_key: bytes, ciphertext: bytes) → bytes`
Reverses `encrypt()`. Raises `nacl.exceptions.CryptoError` on authentication failure
or wrong keys.

#### `encrypt_group(group_key: bytes, plaintext: bytes) → bytes`
Symmetric authenticated encryption (SecretBox) with a 32-byte group key.
Returns `nonce (24 bytes) || ciphertext`. Used for group posts.

#### `decrypt_group(group_key: bytes, ciphertext: bytes) → bytes`
Reverses `encrypt_group()`.

#### `generate_group_key() → bytes`
Returns 32 cryptographically random bytes. Used when creating a group or rotating
the group key after member removal.

---

## storage.py

Async SQLite wrapper using `aiosqlite`. All public methods are `async`.
The schema is defined in `data/schema.sql`; migrations run automatically at startup.

### `Database` (class)

Single connection wrapper. All methods commit immediately after each write.
WAL journal mode is enabled for better concurrent read performance.

#### Opening a connection

```python
async with Database.open(path) as db:
    ...
```

`open()` is an async context manager that:
1. Opens the aiosqlite connection
2. Sets `row_factory = aiosqlite.Row` (rows as dict-like objects)
3. Enables `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`
4. Runs `schema.sql` via `executescript`
5. Applies any pending column migrations (idempotent `ALTER TABLE` calls)

#### Schema migrations

Handled by `_apply_schema()` with a list of `ALTER TABLE ... ADD COLUMN` statements.
Each migration is wrapped in `try/except` — `duplicate column name` errors are silently
ignored, making the migration idempotent across restarts and upgrades.

### Methods by table

#### Identity

| Method | Purpose |
|---|---|
| `save_identity(public_key, private_key, ...)` | INSERT OR REPLACE — called once at identity creation |
| `load_identity() → dict \| None` | SELECT first row — called at startup and unlock |
| `update_identity_alias(alias)` | UPDATE alias field |
| `update_identity_default_ttl(ttl)` | UPDATE default_ttl (1h–30d, validated at API layer) |
| `panic_wipe()` | DELETE all rows from all tables, then VACUUM |

#### Relay config

Single-row table (`id=1` enforced by CHECK constraint). Stores the optional relay node
configuration for the current user.

| Method | Purpose |
|---|---|
| `save_relay_config(onion_address, public_key, enabled)` | INSERT OR REPLACE with id=1 |
| `load_relay_config() → dict \| None` | SELECT WHERE id=1 |
| `delete_relay_config()` | DELETE WHERE id=1 |

`panic_wipe()` runs `VACUUM` after deletion. SQLite `VACUUM` rewrites the entire
database file from scratch — freed pages (deleted rows) are not present in the new file.

#### Contacts

| Method | Purpose |
|---|---|
| `save_contact(public_key, onion_address, alias, trusted_since)` | INSERT OR REPLACE |
| `get_contacts() → list[dict]` | SELECT all |
| `get_contact(public_key) → dict \| None` | SELECT by PK |
| `is_contact(public_key) → bool` | EXISTS check — used in message filtering |
| `update_contact_alias(public_key, alias)` | UPDATE |
| `delete_contact(public_key)` | DELETE |
| `delete_messages_with_peer(peer_key)` | DELETE FROM messages WHERE from_key=? OR to_key=? |

#### Messages

| Method | Purpose |
|---|---|
| `save_message(id, from_key, to_key, payload, signature, timestamp, expires_at, status, file_name, mime_type)` | INSERT OR IGNORE — deduplicates by SHA256 id |
| `get_message_by_id(id) → dict \| None` | SELECT by PK |
| `get_messages(peer_key, our_key) → list[dict]` | SELECT conversation ordered by timestamp |
| `update_message_status(id, status)` | UPDATE status field |
| `mark_conversation_read(peer_key, our_key)` | UPDATE read_at = now WHERE read_at IS NULL |
| `get_unread_counts(our_key) → dict` | {sender_key: count} for unread incoming |
| `cancel_queued(message_id)` | DELETE FROM delivery_queue WHERE message_id=? |
| `delete_expired_messages(now)` | DELETE WHERE expires_at < now |

#### Groups

| Method | Purpose |
|---|---|
| `save_group(id, name, group_key, admin_key, is_admin, created_at)` | INSERT OR REPLACE — explicit column names to handle added columns |
| `get_groups() → list[dict]` | SELECT all |
| `get_group(id) → dict \| None` | SELECT by PK |
| `delete_group(id)` | DELETE from groups + group_members + group_posts |
| `update_group_key(group_id, new_key)` | UPDATE after key rotation |
| `mark_group_read(group_id, now)` | UPDATE last_read_at |
| `get_group_unread_count(group_id, our_key) → int` | COUNT posts after last_read_at, excluding own posts |

#### Group members

| Method | Purpose |
|---|---|
| `save_group_member(group_id, public_key, added_at, onion_address, alias_hint)` | INSERT OR REPLACE |
| `get_group_members(group_id) → list[dict]` | SELECT all for group |
| `is_group_member(group_id, public_key) → bool` | EXISTS check — used in message filtering |
| `delete_group_member(group_id, public_key)` | DELETE |

`onion_address` is stored per-member so posts can be routed peer-to-peer without
requiring a contact record. `alias_hint` is the display name suggested at invite time.

#### Group posts

| Method | Purpose |
|---|---|
| `save_group_post(id, group_id, author_key, payload, signature, timestamp, expires_at)` | INSERT OR IGNORE |
| `get_group_posts(group_id) → list[dict]` | SELECT ordered by timestamp |
| `delete_expired_group_posts(now) → int` | DELETE WHERE expires_at < now |

#### Cleanup

| Method | Purpose |
|---|---|
| `delete_expired_messages(now) → int` | DELETE messages WHERE expires_at < now; returns row count |
| `delete_expired_group_posts(now) → int` | DELETE group_posts WHERE expires_at < now; returns row count |

These are not called on a schedule in the current implementation — they are available
for future use by a maintenance task.

#### Delivery queue

| Method | Purpose |
|---|---|
| `enqueue(id, message_id, destination_key, destination_onion, next_retry_at, message_json, via_relay)` | INSERT OR IGNORE |
| `get_due(now) → list[dict]` | SELECT WHERE next_retry_at <= now |
| `update_retry(id, next_retry_at)` | UPDATE next_retry_at + increment retry_count |
| `dequeue(id)` | DELETE on successful delivery |

`message_json` stores the complete serialised protocol message (JSON string).
This avoids reconstructing messages from the `messages` table, which would not work
for `group_invite`, `group_key_update` and other types that are not stored there.

---

## protocol.py

Defines the wire format for all network messages, builds them, parses them,
and validates them. No I/O, no state.

### Message types (constants)

| Constant | Wire value | Used for |
|---|---|---|
| `MSG_PRIVATE` | `"msg"` | Private text/file messages |
| `MSG_GROUP_POST` | `"group_post"` | Group chat posts |
| `MSG_GROUP_INVITE` | `"group_invite"` | Inviting a new group member |
| `MSG_GROUP_MEMBER_UPDATE` | `"group_member_update"` | Roster changes (add/remove/leave) |
| `MSG_GROUP_KEY_UPDATE` | `"group_key_update"` | Key rotation after member removal |
| `MSG_DELIVERY_ACK` | `"delivery_ack"` | Delivery acknowledgement (reserved) |
| `MSG_CONTACT_CARD` | `"contact_card"` | Contact card exchange (reserved) |

### Wire format

Every message sent over the network is a JSON object:

```json
{
  "v": 1,
  "type": "msg",
  "id": "<SHA256 of payload, hex>",
  "from": "<sender public key, hex>",
  "to": "<recipient public key or group id, hex>",
  "payload": "<base64-encoded ciphertext>",
  "signature": "<base64-encoded Ed25519 signature>",
  "timestamp": 1714000000,
  "ttl": 604800
}
```

The **signature** covers: `type|id|from|to|timestamp` (pipe-separated, UTF-8 encoded).
This binds the signature to the message identity and prevents cross-type replay.

### Functions

#### `build_message(type, from_key, to_key, payload, private_key, ttl) → dict`
Constructs and signs a protocol message:

1. Computes `id = SHA256(payload).hexdigest()`
2. Sets `timestamp = int(time.time())`
3. Signs `type|id|from_hex|to_hex|timestamp` with the sender's private key
4. Returns the complete message dict

`payload` is expected to be already encrypted by the caller.

#### `parse_message(raw: str | bytes) → dict`
Parses JSON and checks required fields are present.
Raises `MalformedMessage` on invalid JSON or missing fields.
Does **not** verify the signature — that is done by `validate_message()`.

#### `validate_message(msg: dict, now: int | None) → None`
Full validation pipeline:

1. Version check (`v == 1`)
2. Type must be in `_VALID_TYPES`
3. Payload must be valid base64
4. `SHA256(payload) == id`
5. `timestamp` must not be more than 300 seconds in the future (clock skew guard)
6. `now - timestamp` must not exceed `ttl` (expiry check)
7. `from` must be a valid 32-byte hex public key
8. Ed25519 signature must verify against the signed data

Any failure raises a `ProtocolError` subclass. The caller is responsible for silently
dropping the message without sending any response.

### Contact card functions

#### `build_contact_card(public_key, onion_address, private_key, alias_hint) → dict`
Builds a signed JSON contact card for sharing with potential contacts.
Signs the entire card (without the `signature` field) with the owner's private key.

#### `validate_contact_card(card: dict) → None`
Verifies the Ed25519 signature on a received contact card.
Raises `ProtocolError` on failure. Called before adding any contact.

### Exceptions

| Exception | Raised when |
|---|---|
| `MalformedMessage` | Invalid JSON, missing fields, bad encoding |
| `InvalidSignature` | Ed25519 verification failed |
| `ExpiredMessage` | Age > TTL or timestamp too far in future |
| `InvalidMessageId` | SHA256(payload) ≠ declared id |
