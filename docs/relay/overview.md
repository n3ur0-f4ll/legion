# legion-relay — Overview

!!! warning "Work in progress"
    `legion-relay` is architecturally designed and partially implemented, but the
    integration with `legion-node` is not yet fully operational. This page documents
    the intended design and current implementation status.

---

## Purpose

A relay node is an always-online server operated by the message sender (not a third party).
It accepts encrypted message blobs from the owner, stores them, and attempts to deliver
them to the recipient 24/7 — even when the sender's desktop node is offline.

The relay is **not** a trusted party. It stores only encrypted blobs and never has access
to the encryption keys. The recipient cannot tell whether a message was routed through a
relay.

```
Sender node ──► relay node ──► recipient node
   (offline)    (always on)
```

---

## What the relay knows

| The relay knows | The relay does not know |
|---|---|
| Which sender authorized it | Message content (only encrypted blobs) |
| The recipient's `.onion` address | The sender's IP address (all traffic via Tor) |
| When messages arrive and leave | Who the recipient is in real life |
| How many retry attempts were made | |

---

## Current implementation status

### Implemented

- `relay/server.py` — WebSocket server accepting `relay_send` and `relay_status` requests
- `relay/storage.py` — SQLite wrapper for relay-specific tables
- `relay/delivery.py` — retry logic and scheduling
- `relay/cleanup.py` — periodic deletion of expired messages
- `relay/tor.py` — Tor process management for the relay node
- `config.py` / `main.py` — entry point and configuration

### Not yet operational

The integration between `legion-node` and `legion-relay` is incomplete:
`legion-node/network/relay.py:send_via_relay()` currently sends standard Legion protocol
messages to the relay's onion address. The relay server, however, only accepts messages
of type `relay_send` with an authorization signature. This mismatch means relay delivery
does not function end-to-end in the current version.

The relay configuration can be stored in `legion-node`'s database via `relay_config`,
and the `choose_destination()` function in `network/relay.py` correctly selects relay
routing — but the actual relay wire protocol is not yet implemented on the sender side.

---

## Wire protocol (relay server expects)

### `relay_send` — store and forward a message

```json
{
    "v": 1,
    "type": "relay_send",
    "sender_key": "<hex Ed25519 public key of owner>",
    "auth": "<base64 Ed25519 signature over canonical JSON without 'auth' field>",
    "destination_key": "<hex public key of recipient>",
    "destination_onion": "<recipient's .onion address>",
    "payload": "<base64 original Legion protocol message>",
    "message_id": "<SHA256 of payload>",
    "ttl": 604800
}
```

### `relay_status` — query delivery status

```json
{
    "v": 1,
    "type": "relay_status",
    "sender_key": "<hex>",
    "auth": "<base64 signature>",
    "message_id": "<SHA256>"
}
```

### Authorization

The relay verifies:
1. `sender_key` is in the `authorized_senders` table
2. The Ed25519 signature over canonical JSON (sorted keys, no `auth` field) is valid

Invalid signature or unauthorized sender: connection closed silently with no response.

---

## Relay database schema

```sql
CREATE TABLE relay_identity (
    public_key    TEXT PRIMARY KEY,
    private_key   BLOB NOT NULL,
    onion_address TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE authorized_senders (
    public_key TEXT PRIMARY KEY,
    alias      TEXT,
    added_at   INTEGER NOT NULL
);

CREATE TABLE stored_messages (
    id                TEXT PRIMARY KEY,
    sender_key        TEXT NOT NULL,
    for_key           TEXT NOT NULL,
    destination_onion TEXT NOT NULL,
    payload           BLOB NOT NULL,
    received_at       INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    next_retry_at     INTEGER NOT NULL,
    retry_count       INTEGER DEFAULT 0,
    status            TEXT NOT NULL CHECK (status IN ('queued', 'delivered', 'failed'))
);
```

---

## Configuration defaults

| Parameter | Default | Description |
|---|---|---|
| `MAX_MESSAGE_SIZE_KB` | 512 | Maximum accepted message size |
| `MAX_STORED_MESSAGES` | 10000 | Hard cap on queue depth |
| `MAX_TTL_DAYS` | 30 | TTL capped at 30 days regardless of request |
| `DEFAULT_TTL_DAYS` | 7 | Default TTL if not specified |
| `CLEANUP_INTERVAL_SECONDS` | 3600 | Cleanup runs every hour |
| `DATA_DIR` | `~/.local/share/legion-relay/` | Data directory |

---

## Deployment

The relay is a standalone Python process intended to run on a server (VPS, home server)
with a stable internet connection. It creates its own Tor Hidden Service with its own
Ed25519 keypair, independent of any user's identity.

After first run, the operator notes the relay's `.onion` address and public key,
then enters these in `legion-node`'s Settings → Relay section.
