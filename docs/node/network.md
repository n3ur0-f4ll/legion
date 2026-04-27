# Network layer

The network layer handles all communication between nodes: managing the Tor process,
accepting incoming messages, sending outgoing messages through Tor SOCKS5, and selecting
whether to send directly or via a relay.

---

## tor.py

Manages the Tor subprocess lifecycle and the v3 Hidden Service registration.
All blocking Stem calls are run in an executor to avoid blocking the asyncio event loop.

### `TorManager` (class)

```python
TorManager(data_dir: Path, socks_port: int = 9050, control_port: int = 9051)
```

#### `start(private_key: bytes, hs_port: int) → str`
Full startup sequence:

1. Creates data directory if needed
2. Runs `_launch()` in executor with `asyncio.wait_for(timeout=120s)`
3. Connects to Tor control port via Stem
4. Authenticates to the controller
5. Calls `_create_hidden_service()` in executor
6. Returns the `.onion` address

If any step fails, calls `stop()` to clean up before raising `TorError`.

#### `stop() → None`
Closes the Stem controller connection, then terminates the Tor subprocess.
If `terminate()` doesn't work within 5 seconds, escalates to `kill()`.

#### `attach_log_listener(callback: LogCallback) → None`
Registers Stem event listeners after `start()` succeeds.
`callback(level, category, text)` is called from **Stem's event thread**.
The caller must wrap it with `loop.call_soon_threadsafe()` to safely push
events into the asyncio event loop (done in `api/server.py:_start_tor_background`).

Registered event types:

| Event | Handler | Purpose |
|---|---|---|
| `CIRC` | `_on_circ` | HS circuit establishment/failure |
| `BW` | `_on_bw` | Bandwidth stats (bytes/s read:written) |
| `STATUS_CLIENT` | `_on_status` | Bootstrap state changes |
| `WARN`, `ERR` | `_on_warn` | Tor warning and error messages |

#### Properties

| Property | Type | Description |
|---|---|---|
| `onion_address` | `str` | `.onion` address — raises `TorError` if not running |
| `socks_port` | `int` | SOCKS5 port for outgoing connections |
| `is_running` | `bool` | True if both process and controller are active |

### Internal helpers

#### `_launch() → process`
Called in an executor. Runs `stem.process.launch_tor_with_config()` **without** a
`timeout=` parameter — Stem's timeout uses `signal.SIGALRM` which only works from the
main thread. The 120-second timeout is handled by `asyncio.wait_for` in `start()`.

Tor config:
```python
{
    "SocksPort": str(socks_port),
    "ControlPort": str(control_port),
    "DataDirectory": str(data_dir),
    "Log": "notice stderr",
    "ExitPolicy": "reject *:*",    # not an exit node
}
```

`take_ownership=True` — Tor shuts down automatically if the controlling process dies.

#### `_create_hidden_service(private_key: bytes, hs_port: int) → str`
Converts the 32-byte Ed25519 seed to the 64-byte expanded key format Tor expects,
then calls `controller.create_ephemeral_hidden_service()` with:

- `ports={80: hs_port}` — external port 80 maps to internal `hs_port`
- `key_type="ED25519-V3"`
- `await_publication=True` — blocks until the HS descriptor is published to the
  Tor DHT and the service is reachable

Returns `service_id + ".onion"`.

#### `_ed25519_seed_to_expanded(seed: bytes) → bytes`
Derives the 64-byte expanded Ed25519 private key from a 32-byte seed.
Implements RFC 8032 clamping:
```python
h = bytearray(sha512(seed))
h[0] &= 248
h[31] &= 127
h[31] |= 64
```
The resulting public key is identical to `nacl.signing.SigningKey(seed).verify_key`,
ensuring the `.onion` address matches `identity.derive_onion_address(public_key)`.

### `TorError` (exception)
Raised for any Tor startup, bootstrap, or Hidden Service creation failure.

---

## node.py

Incoming WebSocket server. Accepts one message per connection, validates it,
and dispatches it to the application handler.

### `NodeServer` (class)

```python
NodeServer(host: str = "127.0.0.1", port: int = 8765)
```

Binds exclusively to `127.0.0.1` — not accessible from the network directly.
Tor's Hidden Service maps the external `.onion:80` to this port.

#### `start(handler: MessageHandler) → None`
Starts the websockets server. `handler` is an async callable `(msg: dict) → None`
called for every valid, authenticated message.

#### `stop() → None`
Closes the server and waits for active handler coroutines to finish.

#### `_handle(websocket, handler) → None`
Per-connection coroutine:

1. `await websocket.recv()` with 30-second timeout — idle connections are dropped
2. `parse_message(raw)` — invalid JSON: silent drop
3. `validate_message(msg)` — invalid signature/TTL/id: silent drop
4. `await handler(msg)` — application-level processing

`max_size = 12 MB` — accommodates 5 MB files after base64 encoding and encryption overhead.

Any `ProtocolError` in steps 2–3 results in a **silent drop with no response**.
This is intentional: not responding reveals nothing about whether the address is active.

### `MessageHandler` type alias
```python
MessageHandler = Callable[[dict], Awaitable[None]]
```

---

## client.py

Outgoing WebSocket client. Connects to a remote `.onion` address through Tor's SOCKS5
proxy and sends a single message.

### `send_message(msg, onion_address, *, socks_host, socks_port, hs_port) → None`

Main entry point. Called by `DeliveryQueue._try_deliver()` for each delivery attempt.

1. Opens a SOCKS5 connection to `onion_address:hs_port` through the Tor proxy
   (`asyncio.wait_for` with 60-second timeout)
2. Hands the socket to `websockets.asyncio.client.connect()`
3. Sends `json.dumps(msg)` over the WebSocket
4. Closes the connection

Raises `NodeClientError` on any connection or send failure.

### SOCKS5 implementation

A minimal SOCKS5 client is implemented from scratch to avoid introducing extra
dependencies and to keep the connection fully under application control.

#### `_socks5_connect(host, port, proxy_host, proxy_port) → socket`
1. Opens TCP connection to the Tor SOCKS5 proxy
2. Calls `_socks5_handshake()` with no-auth method
3. Sets the socket to non-blocking mode
4. Returns the connected socket (ready for websockets handover)

#### `_socks5_handshake(sock, host, port) → None`
Implements SOCKS5 protocol (RFC 1928):

1. Sends greeting: `[VER=5, NMETHODS=1, METHOD=0 (no auth)]`
2. Verifies server accepts no-auth method
3. Sends CONNECT request with `ATYP=DOMAIN` and hostname as bytes
4. Reads and validates the response header (4 bytes)
5. Discards the bound address (IPv4, domain, or IPv6)

The domain name is sent as bytes — Tor resolves the `.onion` address internally
via its own DHT, never using the operating system's DNS.

#### `_recv_exact(sock, n) → bytes`
Reads exactly `n` bytes from a blocking socket, looping until all bytes arrive.
Raises `OSError` if the connection closes unexpectedly.

---

## relay.py

Selects between direct delivery and relay-assisted delivery.
Does not implement the relay wire protocol — that is handled by `client.py` (which
sends the message to the relay's onion address like any other node).

!!! warning "Relay protocol not yet active"
    The relay WebSocket server (`legion-relay`) expects `relay_send`-type messages,
    but `send_via_relay()` currently sends standard Legion protocol messages.
    Relay functionality is architecturally present but not fully operational.
    See `legion-relay` documentation for the planned protocol.

### Functions

#### `is_relay_configured(db) → bool`
Returns `True` if a relay is configured and enabled in the database.

#### `get_relay_onion(db) → str`
Returns the relay's `.onion` address. Raises `RelayError` if not configured or disabled.

#### `send_via_relay(db, msg, *, socks_host, socks_port) → None`
Sends `msg` to the configured relay node via `send_message()`.
The relay is responsible for forwarding to the actual recipient.

#### `choose_destination(db, recipient_onion) → tuple[str, bool]`
Returns `(destination_onion, via_relay)`:

- If relay is configured and enabled: `(relay_onion, True)`
- Otherwise: `(recipient_onion, False)`

Called by the API layer when enqueuing a new message to determine routing.
The `via_relay` flag is stored in the delivery queue entry.
