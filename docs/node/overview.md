# legion-node — Overview

`legion-node` is the core component of Legion. It manages cryptographic identity,
Tor network integration, message delivery, SQLite storage and exposes a local REST API
for the GUI. It runs as a background process spawned by `legion-gui`.

## Module structure

```
legion-node/
├── core/
│   ├── identity.py     — Ed25519 keypair generation, private key encryption at rest
│   ├── crypto.py       — signing, Box encryption, SecretBox encryption
│   ├── storage.py      — aiosqlite wrapper, all database operations
│   └── protocol.py     — message format, construction, validation
│
├── network/
│   ├── tor.py          — Tor subprocess management, Hidden Service creation
│   ├── node.py         — incoming WebSocket server (one message per connection)
│   ├── client.py       — outgoing WebSocket client via Tor SOCKS5
│   └── relay.py        — relay selection and routing logic
│
├── messaging/
│   ├── private.py      — private message send/receive, payload envelope
│   ├── groups.py       — group lifecycle: create, invite, post, leave, dissolve
│   ├── files.py        — file sanitization (Pillow), format verification
│   └── delivery.py     — persistent delivery queue with 10-second retry loop
│
├── api/
│   └── server.py       — FastAPI application, all endpoints, SSE stream, AppState
│
├── data/
│   └── schema.sql      — SQLite schema definition
│
├── config.py           — Config dataclass, XDG-compliant data directory
└── main.py             — CLI entry point, startup/shutdown orchestration
```

## Layer responsibilities

```
main.py / config.py
      │  orchestration, CLI args, graceful shutdown
      ▼
api/server.py  ←──── SSE events ────────────────┐
      │  AppState, REST endpoints               │
      ▼                                         │
messaging/           network/                   │
  private.py    ←──  node.py (incoming)         │
  groups.py     ───► client.py (outgoing)       │
  files.py           tor.py (Tor process)       │
  delivery.py   ───► relay.py (routing)         │
      │                                         │
      ▼                                         │
core/                                           │
  identity.py   ── keypair generation           │
  crypto.py     ── libsodium operations         │
  storage.py    ── SQLite (aiosqlite)           │
  protocol.py   ── message format/validation    │
```

## Config (config.py)

```python
@dataclass
class Config:
    data_dir: Path      # default: $XDG_DATA_HOME/legion or ~/.local/share/legion
    socks_port: int = 9050    # Tor SOCKS5 proxy port
    control_port: int = 9051  # Tor control port
    node_port: int = 8765     # WebSocket server (Tor HS maps to this)
    api_port: int = 8080      # FastAPI port (GUI connects here)
    log_level: str = "INFO"
```

Derived properties: `db_path = data_dir / "node.db"`, `tor_data_dir = data_dir / "tor"`.

CLI overrides (from `main.py`): `--data-dir`, `--api-port`, `--node-port`, `--log-level`,
`--no-interactive` (skips password prompt, used by GUI).

## AppState — shared runtime state

`AppState` (defined in `api/server.py`) is a dataclass passed to every request handler
and to the message handler. It holds:

| Field | Type | Purpose |
|---|---|---|
| `db` | `Database` | open aiosqlite connection |
| `delivery_queue` | `DeliveryQueue` | background retry loop |
| `identity` | `Identity \| None` | decrypted keypair (None until unlocked) |
| `tor_onion` | `str` | active `.onion` address (empty until Tor starts) |
| `tor_manager` | `TorManager` | Tor subprocess handle |
| `node_port` | `int` | WebSocket server port (default 8765) |
| `_tor_starting` | `bool` | Tor bootstrap in progress |
| `tor_error` | `str` | last Tor error message |
| `_event_queues` | `list[Queue]` | one per active SSE client |
| `_log_ring` | `deque` | ring buffer of last 200 network log entries |

## Concurrency model

All I/O is async (`asyncio`). The event loop runs:

- **uvicorn** — handles HTTP requests on the main loop
- **DeliveryQueue._loop** — `asyncio.Task`, wakes every 10 seconds or on `_wake.set()`
- **NodeServer** — `asyncio.Task` per incoming WebSocket connection
- **Stem event listeners** — run in Stem's thread; use `loop.call_soon_threadsafe()` to push into the main loop

No `threading.Thread` is created by Legion code. Stem creates its own thread internally.
