# Legion — Technical Overview

Legion is a decentralized, anonymous messaging platform built on the Tor network.
Users run their own nodes; there are no central servers, no accounts, and no phone numbers.
Every message is end-to-end encrypted with libsodium (PyNaCl) and delivered peer-to-peer
through Tor Hidden Services.

---

## Component architecture

```
┌─────────────────────────────────────────────────────────────┐
│  User's machine                                             │
│                                                             │
│  ┌──────────────┐   HTTP/SSE    ┌──────────────────────┐    │
│  │  legion-gui  │ ◄──────────►  │    legion-node       │    │
│  │  (pywebview) │  127.0.0.1    │  FastAPI + uvicorn   │    │
│  └──────────────┘   :8080       │                      │    │
│                                 │  WebSocket server    │    │
│                                 │  127.0.0.1:8765      │    │
│                                 └──────────┬───────────┘    │
│                                            │ SOCKS5         │
│                                    ┌───────▼────────┐       │
│                                    │  Tor process   │       │
│                                    │  (subprocess)  │       │
│                                    └───────┬────────┘       │
└────────────────────────────────────────────┼────────────────┘
                                             │ Tor network
                               ┌─────────────▼──────────────┐
                               │  Other Legion nodes        │
                               │  (contact's .onion)        │
                               └────────────────────────────┘
```

## Communication paths

| Path | Protocol | Purpose |
|---|---|---|
| `legion-gui` ↔ `legion-node` | HTTP REST + SSE | GUI sends commands, node pushes live events |
| `legion-node` → remote node | WebSocket over Tor SOCKS5 | Outgoing message delivery |
| Remote node → `legion-node` | WebSocket via Tor HS | Incoming message reception |
| `legion-node` → `legion-relay` | WebSocket over Tor (optional) | Relay-assisted delivery |

## Technology stack

| Component | Key libraries |
|---|---|
| `legion-node` | FastAPI, uvicorn, aiosqlite, PyNaCl, Stem, websockets |
| `legion-gui` | pywebview (GTK/WebKit2), PyGObject |
| `legion-relay` | websockets, aiosqlite, Stem, PyNaCl |

**Python:** ≥ 3.12 · **OS:** Linux only · **License:** AGPL-3.0

## Startup sequence

1. `legion-gui/app/main.py` spawns `legion-node/main.py --no-interactive`
2. Node opens SQLite database, applies schema migrations
3. Node starts WebSocket server on `127.0.0.1:8765`
4. Node starts delivery queue background loop
5. Node starts FastAPI/uvicorn on `127.0.0.1:8080`
6. GUI polls `GET /api/status` until node responds
7. GUI opens pywebview window — user sees Unlock or Onboarding screen
8. User enters password → `POST /api/identity/unlock`
9. Node decrypts private key, stores in `AppState.identity`
10. Node launches Tor as background task, creates v3 Hidden Service
11. Tor emits `tor_ready` → SSE pushes to GUI → status bar turns green
