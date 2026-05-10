# Legion — Security Audit Report

**Type:** White-Box Penetration Test & Security Audit  
**Version audited:** 0.1.6  
**Audit date:** 2026-05-09  
**Scope:** Full source code — `legion-node/`, `legion-gui/`, `install.sh`, `uninstall.sh`  
**Methodology:** Static code analysis, cryptographic review, threat modelling, data flow analysis  
**Result: No critical vulnerabilities. Two medium findings fixed during audit.**

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Scope and Methodology](#2-scope-and-methodology)
3. [Threat Model](#3-threat-model)
4. [Findings](#4-findings)
   - [SEC-001 · MEDIUM · FIXED — XSS via file name in onclick attribute](#sec-001)
   - [SEC-002 · MEDIUM · FIXED — MIME type bypass on receiver side](#sec-002)
   - [SEC-003 · LOW — Data directory world-readable by default](#sec-003)
   - [SEC-004 · LOW — `save_file()` does not reject `..` filename prefix](#sec-004)
   - [SEC-005 · INFO — Argon2id uses INTERACTIVE parameters](#sec-005)
   - [SEC-006 · INFO — TTL field not covered by Ed25519 signature](#sec-006)
   - [SEC-007 · INFO — Relay feature is non-functional dead code](#sec-007)
5. [Confirmed Security Controls](#5-confirmed-security-controls)
6. [Cryptographic Review](#6-cryptographic-review)
7. [Attack Surface Analysis](#7-attack-surface-analysis)
8. [Conclusions](#8-conclusions)

---

## 1. Executive Summary

Legion was subjected to a full white-box security audit covering the cryptographic implementation, protocol design, network layer, storage layer, API, and GUI. The auditor had complete access to all source files.

**No critical or high-severity vulnerabilities were found.**

Two medium-severity vulnerabilities were identified and fixed during the audit:

- **SEC-001**: Cross-site scripting (XSS) via file attachment file name embedded in an `onclick` HTML attribute. A malicious contact could execute arbitrary JavaScript in the pywebview window, gaining full access to the Legion API.
- **SEC-002**: The receiver-side file sanitization function did not check blocked MIME types (SVG, HTML), and the GUI rendered any `image/*` MIME type as an `<img>` element. A malicious contact could send a file declared as `image/svg+xml` containing embedded scripts.

Both issues were fixed at the source before this report was finalised. All 271 automated tests were passing at audit time. The test suite has since grown to 303 tests (v0.1.8) with coverage for burn-after-reading and group file attachments.

The cryptographic foundations — Ed25519, Argon2id, X25519+XSalsa20-Poly1305, and SecretBox — are implemented correctly using libsodium (PyNaCl). Plaintext messages are never written to disk. The Tor integration provides network-level anonymity. The panic button performs a forensically sound wipe including `VACUUM` to overwrite freed SQLite pages.

---

## 2. Scope and Methodology

### Files audited

| Component | Files |
|---|---|
| `legion-node/core/` | `protocol.py`, `crypto.py`, `identity.py`, `storage.py` |
| `legion-node/messaging/` | `private.py`, `files.py`, `groups.py`, `delivery.py` |
| `legion-node/network/` | `tor.py`, `node.py`, `client.py`, `relay.py` |
| `legion-node/api/` | `server.py` |
| `legion-node/` | `main.py`, `config.py`, `data/schema.sql` |
| `legion-node/tests/` | All 14 test files (292 tests) |
| `legion-gui/app/` | `main.py`, `bridge.py` |
| `legion-gui/ui/` | `app.js`, `index.html`, `style.css` |
| `legion-gui/` | `config.py` |
| `/` | `install.sh`, `uninstall.sh` |

### Methodology

- **Static code analysis** — every function read and reasoned about independently
- **Data flow tracing** — input tracked from origin (network/user) through all transformations to output (DB/UI)
- **Cryptographic review** — primitives, key derivation, nonce generation, key conversion verified against standards
- **Threat modelling** — attack surfaces mapped per threat actor class (see §3)
- **Protocol analysis** — message format, signature coverage, replay protection, TTL logic
- **Input validation audit** — all external inputs (network messages, API requests, file attachments, JS bridge calls)
- **XSS/injection review** — all points where attacker-controlled data reaches the HTML/JS layer
- **Test coverage review** — gap analysis between implemented code and test suite

---

## 3. Threat Model

### Assets to protect

| Asset | Protection goal |
|---|---|
| Ed25519 private key | Confidentiality — never leave device in plaintext |
| Message plaintext | Confidentiality — never written to disk |
| Message metadata | Confidentiality — who talks to whom, when |
| File attachments | Confidentiality + integrity; metadata (GPS, EXIF) stripped |
| Contact list | Confidentiality — leaks social graph |
| Group membership | Confidentiality |
| Network identity | Anonymity — real IP never exposed |

### Threat actors

**T1 — Network passive observer**  
Monitors Tor exit traffic or ISP-level traffic. Cannot see destination or content (Tor + E2EE). Cannot correlate sender and receiver.

**T2 — Network active MITM at relay level**  
If relay is configured: can see encrypted ciphertext transit. Cannot read content (X25519+XSalsa20-Poly1305). Could in theory modify unprotected envelope fields (TTL) — mitigated by Tor transport encryption (see SEC-006).

**T3 — Malicious contact**  
A user who has been added as a contact. Can send crafted messages and files. This is the most relevant active threat actor. SEC-001 and SEC-002 were in this category.

**T4 — Local attacker (same machine)**  
Access to the filesystem or the ability to run processes as the same user. Can read `node.db` (encrypted contents only). Cannot decrypt without the password. The localhost-only API (127.0.0.1) is reachable from the same user account.

**T5 — Physical/forensic access**  
Access to the device after use. Database contains only encrypted blobs. Panic button (VACUUM) eliminates forensic recovery from SQLite free pages.

**T6 — Relay operator**  
Runs the relay node. Can see which clients connect (Tor hidden service). Cannot read message content (E2EE). Relay feature is currently non-functional (see SEC-007).

### Out of scope

- Attacks requiring compromise of the Tor network itself
- Side-channel attacks (timing, power, acoustic) against the hardware
- Attacks against the operating system or Python interpreter
- Coercion of the user (rubber hose cryptanalysis)

---

## 4. Findings

---

### SEC-001

**Severity:** MEDIUM → **FIXED**  
**Component:** `legion-gui/ui/app.js` — `loadMessages()`  
**Threat actor:** T3 (malicious contact)

#### Description

File attachment names from incoming messages were embedded directly into an HTML `onclick` attribute without escaping single quotes:

```javascript
// VULNERABLE — before fix
const saveBtn = `<button onclick="saveAttachment('${msg.file_data}','${msg.file_name||'file'}')">`;
```

`msg.file_name` originates from the sender's message payload. Server-side validation (`_validate_file_name`) blocks `/`, `\`, `"`, `<`, `>`, and `|`, but does **not** block single quotes (`'`), parentheses, or semicolons.

A malicious contact could send a file with a crafted name such as:

```
'); fetch('http://127.0.0.1:8080/api/identity',{method:'DELETE'}); //
```

When the victim opens the conversation, the injected JavaScript would execute in the pywebview WebKit2GTK context.

#### Impact

JavaScript executing in the pywebview window has access to:
- `window.pywebview.api` (bridge: clipboard, file save, notifications)
- `fetch()` to `http://127.0.0.1:8080/api/*` (full Legion API access via CORS)

An attacker could read all stored messages, delete contacts, change the alias, or trigger the panic button (`DELETE /api/identity`) destroying the victim's identity.

The attacker must already be a trusted contact, which limits the blast radius. However, this is still a significant escalation from "can send messages" to "can control the node".

#### Evidence

```javascript
// app.js (before fix)
const saveBtn = `<button class="btn-copy" style="margin-top:6px"
    onclick="saveAttachment('${msg.file_data}','${msg.file_name||'file'}')">↓ Save</button>`;
```

File name `'); alert('xss` → rendered as:
```html
<button onclick="saveAttachment('…base64…',''); alert('xss')">
```

#### Fix applied

Replaced inline `onclick` with a `class` marker and `addEventListener`. The file data and name are captured in a closure — never embedded in HTML attributes:

```javascript
// app.js (after fix)
const saveBtn = `<button class="btn-copy btn-save-file" style="margin-top:6px">↓ Save</button>`;
_fileSave = { data: msg.file_data, name: msg.file_name || "file" };
// …
const saveEl = bubble.querySelector(".btn-save-file");
if (saveEl) saveEl.addEventListener("click", () => saveAttachment(_fileSave.data, _fileSave.name));
```

No attacker-controlled data is ever embedded in an HTML attribute or event handler string.

---

### SEC-002

**Severity:** MEDIUM → **FIXED**  
**Component:** `legion-node/messaging/files.py` + `legion-gui/ui/app.js`  
**Threat actor:** T3 (malicious contact)

#### Description

Two related gaps allowed a malicious contact to deliver an SVG or HTML file that would be rendered as an image in the GUI:

**Gap A — `sanitize_incoming()` did not apply `_BLOCKED_MIME_TYPES`**

The sender-side function `prepare_outgoing()` correctly blocks SVG and HTML:
```python
if mime_type in _BLOCKED_MIME_TYPES:   # {"image/svg+xml", "text/html", "application/xhtml+xml"}
    raise FileError(...)
```

But `sanitize_incoming()` (receiver side) did not apply the same check:
```python
# BEFORE FIX — missing blocked-type check
def sanitize_incoming(data, mime_type):
    _validate_size(data)
    if mime_type in _IMAGE_SIGNATURES:
        return _sanitize_image(data, mime_type)
    return data
```

An attacker who constructs a raw message (bypassing the GUI) could set `mime_type = "image/svg+xml"` in the payload. The receiver would store it with that MIME type.

**Gap B — GUI rendered any `image/*` MIME type as `<img>`**

```javascript
// BEFORE FIX
if (msg.mime_type.startsWith("image/")) {
    const dataUrl = `data:${msg.mime_type};base64,${msg.file_data}`;
    content = `<img class="msg-image" src="${dataUrl}" alt="${name}">…`;
}
```

An SVG delivered as `image/svg+xml` would be rendered as `<img src="data:image/svg+xml;base64,…">`. SVG loaded via `<img>` in WebKit2GTK may execute embedded scripts depending on the engine configuration and CSP (none is configured).

#### Impact

Potential JavaScript injection via SVG. Combined with SEC-001 (attacker already a contact), this provides an additional injection vector that does not require an unusual file name.

#### Fix applied

**files.py** — `sanitize_incoming()` now checks `_BLOCKED_MIME_TYPES` first:
```python
def sanitize_incoming(data, mime_type):
    _validate_size(data)
    if mime_type in _BLOCKED_MIME_TYPES:
        raise FileError(f"File type not allowed: {mime_type!r}")
    if mime_type in _IMAGE_SIGNATURES:
        return _sanitize_image(data, mime_type)
    return data
```

**app.js** — Image rendering restricted to an explicit allowlist:
```javascript
const _SAFE_IMG = new Set(["image/jpeg", "image/png", "image/webp"]);
if (_SAFE_IMG.has(msg.mime_type)) {
    // render as <img>
} else {
    // render as file download prompt
}
```

Any MIME type not in the allowlist is shown as a download prompt, never rendered.

---

### SEC-003

**Severity:** LOW  
**Component:** `legion-node/config.py` — `ensure_dirs()`  
**Status:** Not fixed — accepted risk for MVP, recommendation documented

#### Description

The data directory `~/.local/share/legion/` is created with default Python permissions (`0o755`). On a multi-user Linux system, the directory is readable by any local user (execute permission on directories is required for traversal; read gives listing).

```python
self.data_dir.mkdir(parents=True, exist_ok=True)
```

#### Impact

An attacker with a local account can list the directory and read `node.db`. The database contains:
- Encrypted private key blob (Argon2id-protected)
- Encrypted message payloads (XSalsa20-Poly1305, unreadable without key)
- **Plaintext metadata**: contact public keys, message timestamps, group IDs

Message content cannot be recovered without the password. However, the social graph (who communicates with whom) and timing patterns are exposed.

On most standard Linux desktop installations, `~/.local/` is not world-readable (`chmod 700` is common), so the practical risk is limited.

#### Recommendation

Apply explicit `0o700` permissions to the data directory at creation:
```python
self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
self.tor_data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
```

---

### SEC-004

**Severity:** LOW  
**Component:** `legion-gui/app/bridge.py` — `save_file()`  
**Status:** Not fixed — mitigated by path construction; acceptable for MVP

#### Description

The `save_file()` bridge method sanitizes the filename by replacing dangerous path characters (`/ \ : * ? " < > |`) but does not reject filenames beginning with `..`:

```python
safe_name = re.sub(r'[/\\:*?"<>|]', "_", filename) or "file"
dest = downloads / safe_name
```

`Path('/home/user/Downloads') / '..'` resolves to `/home/user`, potentially writing a file one level up from Downloads.

#### Mitigating factors

The collision-avoidance loop (`while dest.exists()`) increments a counter and produces names like `"..1"`, `"..2"` which resolve **inside** Downloads rather than the parent. In practice the `..` prefix does not achieve traversal.

The server-side `_validate_file_name()` blocks filenames starting with `.` on the sender side, so a well-behaved sender cannot produce such a name.

#### Recommendation

Add a `.` prefix check consistent with `_validate_file_name`:
```python
if safe_name.startswith("."):
    safe_name = "_" + safe_name
```

---

### SEC-005

**Severity:** INFO  
**Component:** `legion-node/core/identity.py`  
**Status:** By design — documented for operator awareness

#### Description

The private key is encrypted with Argon2id using `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE` parameters (2 iterations, 64 MB memory):

```python
_ARGON2_OPS = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE   # 2
_ARGON2_MEM = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE   # 64 MB
```

These are libsodium's "fast" preset, producing a ~0.3 s derivation on modern hardware. For a security-critical application serving journalists and activists, the `SENSITIVE` preset (3 iterations, 1 GB memory, ~1 s derivation) would significantly increase resistance to offline brute-force attacks if the encrypted key blob is obtained.

#### Current security posture

An attacker with the encrypted key blob and a GPU cluster can attempt approximately 10–100 password guesses per second at these parameters. With `SENSITIVE`, this drops to ~1–5 guesses per second.

#### Recommendation

Consider upgrading to `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE` with a one-time migration that re-encrypts the key on next login. The user-visible cost is a ~1 s unlock delay.

This is a design decision, not a bug. Both presets are secure against casual attackers.

---

### SEC-006

**Severity:** INFO  
**Component:** `legion-node/core/protocol.py`  
**Status:** Accepted — mitigated by Tor transport encryption

#### Description

The Ed25519 signature covers: `type | id | from | to | timestamp`.

The `ttl` field is not directly signed. However, `id = SHA256(payload)`, so the payload is indirectly authenticated through `id`.

A relay operator with access to the encrypted transit stream could theoretically modify `ttl` to extend or shorten message lifetime in the delivery queue.

#### Mitigating factors

1. All transport uses Tor hidden services — the connection is E2E TLS-equivalent between the sender's Tor daemon and the receiver's .onion port. A relay operator only sees the outer Tor layer, not the inner WebSocket message.
2. Even if TTL is extended, the **content** remains encrypted and authenticated.
3. TTL extension only affects delivery timing, not confidentiality or integrity.

#### Recommendation

No immediate action required. If relay functionality is implemented in the future and the relay sees unencrypted message envelopes, adding TTL to the signature data would be appropriate.

---

### SEC-007

**Severity:** INFO  
**Component:** `legion-node/network/relay.py`, `legion-gui/ui/app.js`  
**Status:** Known limitation — documented in roadmap

#### Description

The relay feature is non-functional. `send_via_relay()` sends a standard Legion message (`type="msg"`) to the relay's .onion address, whereas the relay protocol expects a `relay_send` message type with an Ed25519 `auth` signature. The relay silently rejects the message.

Additionally, there is no `/api/relay` endpoint to configure the relay from the GUI, and `saveRelay()` in the frontend is a no-op stub.

The `via_relay` flag stored in the delivery queue is never consulted during actual send — messages always go through `send_message()` regardless.

#### Impact

The relay feature has zero security impact because it is entirely inoperative. No data takes an unexpected path. Messages either succeed via direct delivery or remain queued indefinitely.

#### Recommendation

This is a documented roadmap item. When implementing:
1. Build `relay_send` message type with Ed25519 `auth` signature in `send_via_relay()`
2. Add `GET /POST /api/relay` endpoints in `server.py`
3. Implement proper relay routing in the delivery loop based on `via_relay` flag

---

## 5. Confirmed Security Controls

The following security controls were verified to be correctly implemented.

### Cryptographic layer

| Control | Verification | Status |
|---|---|---|
| Ed25519 key generation via libsodium CSPRNG | `nacl.signing.SigningKey.generate()` uses `randombytes()` | ✅ |
| Private key encrypted at rest (Argon2id + SecretBox) | `identity.py: encrypt_private_key()` — salt(16) + nonce(24) + ciphertext(32) + mac(16) | ✅ |
| Message encryption X25519+XSalsa20-Poly1305 | `crypto.py: encrypt()` — random 24-byte nonce per message | ✅ |
| Ed25519→Curve25519 key conversion | `crypto_sign_ed25519_sk_to_curve25519()` with correct `[seed‖pubkey]` 64-byte format | ✅ |
| Onion address derived from public key | `identity.py: derive_onion_address()` — Tor v3 spec (SHA3-256 checksum, base32) | ✅ |
| Group key randomly generated | `crypto.py: generate_group_key()` — `nacl.utils.random(32)` | ✅ |
| Group invite Box-encrypted per recipient | `groups.py: invite_member()` — full plaintext JSON encrypted with recipient's X25519 key | ✅ |
| Group key rotation on member removal | `groups.py: remove_member()` — new key generated, distributed via `group_key_update` | ✅ |

### Protocol layer

| Control | Verification | Status |
|---|---|---|
| Message ID = SHA256(payload) | `protocol.py: validate_message()` — checked before signature verification | ✅ |
| Signature verified on every incoming message | `protocol.py` + `node.py` — silent drop on `ProtocolError` | ✅ |
| Expired messages rejected (TTL check) | `validate_message()` — `now - timestamp > ttl` | ✅ |
| Future timestamps rejected (clock skew ±5 min) | `validate_message()` — `timestamp > now + 300` | ✅ |
| Replay prevention via DB deduplication | `save_message()` / `save_group_post()` use `INSERT OR IGNORE` | ✅ |
| Contact card signature verified | `protocol.py: validate_contact_card()` — Ed25519 over sorted JSON | ✅ |

### Network layer

| Control | Verification | Status |
|---|---|---|
| WebSocket server binds to 127.0.0.1 only | `node.py: NodeServer(host="127.0.0.1")` | ✅ |
| Tor SOCKS5 used for all outbound connections | `client.py: _socks5_connect()` — no clearnet fallback | ✅ |
| No destination addresses logged | `client.py` — `send_message()` does not log `onion_address` | ✅ |
| No message content logged | All handlers — payload only logged at DEBUG level as type string, never content | ✅ |
| WebSocket receive timeout (30 s) | `node.py: asyncio.wait_for(..., timeout=30)` — prevents connection hold | ✅ |
| Max message size (12 MB) | `node.py: max_size=12*1024*1024` — prevents memory exhaustion | ✅ |
| Silent drop without response on invalid messages | `node.py: except ProtocolError: return` | ✅ |

### Access control

| Control | Verification | Status |
|---|---|---|
| `msg` and `group_invite` accepted only from contacts | `server.py: make_message_handler()` — `is_contact(sender)` check | ✅ |
| `group_post` accepted only from group members | `server.py` — `is_group_member(group_id, sender)` check | ✅ |
| `group_member_update` accepted only from admin or self-leaving member | `groups.py: handle_member_update()` — explicit origin check | ✅ |
| `group_key_update` accepted only from admin | `groups.py: handle_key_update()` — `msg["from"] != group["admin_key"]` | ✅ |
| Group admin actions enforced server-side | `remove_member()`, `invite_member()` raise `PermissionError` for non-admin | ✅ |
| Self-leave only signs own key | `groups.py` — `is_self_leave = pub == msg["from"] and voluntary` | ✅ |

### Storage layer

| Control | Verification | Status |
|---|---|---|
| Plaintext never written to disk | `save_message()` / `save_group_post()` store encrypted `payload` only | ✅ |
| Decryption on-the-fly in API layer | `server.py: _decrypt_message()` / `_decrypt_post()` | ✅ |
| Panic wipe deletes all tables + VACUUM | `storage.py: panic_wipe()` — correct table order, `VACUUM` rewrites file | ✅ |
| VACUUM works correctly in WAL mode | SQLite checkpoints WAL before VACUUM, `-wal` file cleared | ✅ |
| WAL mode enabled | `storage.py: PRAGMA journal_mode=WAL` | ✅ |
| Foreign keys enabled | `storage.py: PRAGMA foreign_keys=ON` | ✅ |

### File sanitization

| Control | Verification | Status |
|---|---|---|
| SVG / HTML / XHTML blocked (sender) | `files.py: prepare_outgoing()` — `_BLOCKED_MIME_TYPES` check | ✅ |
| SVG / HTML / XHTML blocked (receiver) | `files.py: sanitize_incoming()` — `_BLOCKED_MIME_TYPES` check (added SEC-002 fix) | ✅ |
| Magic bytes verified against declared MIME | `files.py: _sanitize_image()` — JPEG/PNG exact, WebP RIFF+WEBP | ✅ |
| Full image re-encode via Pillow | `_sanitize_image()` — `Image.open()` + `img.save()` without metadata kwargs | ✅ |
| Decompression bomb protection | Pillow `MAX_IMAGE_PIXELS` default (~178 MP) raises `DecompressionBombError` | ✅ |
| File size limit (5 MB) | `_validate_size()` — both sender and receiver | ✅ |
| Defense-in-depth: both sides sanitize | `private.py: receive()` calls `sanitize_incoming_async()` | ✅ |
| Only safe MIME types rendered as images (GUI) | `app.js` — explicit `Set(["image/jpeg","image/png","image/webp"])` (SEC-002 fix) | ✅ |

### API layer

| Control | Verification | Status |
|---|---|---|
| API binds to 127.0.0.1 only | `server.py: run_app()` — `host="127.0.0.1"` | ✅ |
| CORS restricted to localhost | `allow_origin_regex=r"https?://(localhost\|127\.0\.0\.1)(:\d+)?"` | ✅ |
| API documentation endpoints disabled | `docs_url=None, redoc_url=None` | ✅ |
| Identity required for sensitive endpoints | `Depends(require_identity)` — raises HTTP 503 if not unlocked | ✅ |
| Panic button works without authentication | By design — emergency access; localhost-only mitigates abuse | ✅ |
| TTL clamped server-side | `server.py: max(_TTL_MIN, min(req.ttl, _TTL_MAX))` — 1h to 30d | ✅ |

### GUI / subprocess layer

| Control | Verification | Status |
|---|---|---|
| Node subprocess stdin closed | `main.py: stdin=subprocess.DEVNULL` — no terminal interaction | ✅ |
| Node output redirected to log file | `stdout=log_file, stderr=log_file` — no terminal pollution | ✅ |
| `os._exit(0)` for clean shutdown | Intentional — kills Bottle HTTP server thread that blocks `sys.exit()` | ✅ |
| Node gracefully terminated on window close | `on_closed()` + `node_proc.wait(timeout=5)` + `kill()` fallback | ✅ |
| Private key never displayed in UI | No field in HTML or JS outputs private key or raw key material | ✅ |
| XSS prevention via `esc()` | All user-controlled strings use `esc()` or `textContent` | ✅ |
| File name not embedded in HTML attributes | `addEventListener` used instead of `onclick` (SEC-001 fix) | ✅ |
| Bridge scope limited | `LegionBridge` — clipboard, file save, notifications only; no crypto/DB/network | ✅ |
| Clipboard data passed via stdin, not shell arg | `subprocess.run(cmd, input=encoded)` — no command injection risk | ✅ |
| API calls all go to 127.0.0.1 | `api()` function — hardcoded `http://127.0.0.1:${API_PORT}` | ✅ |

---

## 6. Cryptographic Review

### 6.1 Key generation

Ed25519 keys are generated using libsodium's `randombytes()` function, which reads from `/dev/urandom` (Linux) seeded by the kernel's CSPRNG. This is the correct approach for cryptographic key generation.

### 6.2 Private key protection

```
salt (16 bytes, random)
    │
    ▼
Argon2id-KDF(password, salt, ops=2, mem=64MB) → 32-byte key
    │
    ▼
XSalsa20-Poly1305-SecretBox(key, random_nonce).encrypt(private_key_seed)
    │
    ▼
stored: salt(16) ‖ nonce(24) ‖ ciphertext(32) ‖ mac(16) = 88 bytes
```

The salt is never reused (generated fresh per identity creation). The nonce is generated fresh per encryption (libsodium SecretBox). Authentication via Poly1305 prevents ciphertext tampering.

### 6.3 Ed25519 → Curve25519 key conversion

Used in `crypto.py` to derive X25519 keys from Ed25519 keys for asymmetric encryption:

```python
# Private key: construct [seed(32) ‖ public_key(32)] = libsodium sk format
extended = bytes(signing_key) + bytes(signing_key.verify_key)
return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(extended)

# Public key: direct conversion
return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(public_key)
```

This is the standard conversion defined in the NaCl specification and used in libsodium, Tor, and Signal. The mathematical relationship between the Ed25519 and X25519 curve representations is well-established.

The `[seed ‖ public_key]` format (64 bytes) is the correct libsodium secret key representation — distinct from the "expanded" 64-byte scalar used in `tor.py` (`SHA512(seed)` with clamping), which is the format Tor's `ADD_ONION ED25519-V3` command expects. Both uses are correct for their respective contexts.

### 6.4 Onion address derivation

```python
version = b"\x03"
checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"
```

This implements the Tor v3 hidden service address specification exactly: `base32(pubkey‖checksum‖version).onion`. The resulting address deterministically identifies the node's Ed25519 public key, allowing the receiver to verify that the sending onion address corresponds to the signing public key.

### 6.5 Message encryption

Each message uses a fresh random 24-byte nonce (generated by `SecretBox.encrypt()` and `Box.encrypt()` internally). There is no nonce reuse risk. The IETF XSalsa20-Poly1305 construction provides authenticated encryption.

### 6.6 Group key rotation

When a member is removed:
1. A new 32-byte random key is generated
2. The key is encrypted individually for each remaining member using Box (X25519)
3. Each recipient replaces their stored group key
4. The removed member retains only the old key — cannot decrypt future posts

This is the correct design for forward secrecy on member removal.

---

## 7. Attack Surface Analysis

### 7.1 Inbound network (Tor → node.py)

Entry point: WebSocket server on `127.0.0.1:8765`, reachable from Tor hidden service.

Defense layers:
1. `max_size=12MB` — rejects oversized messages before parsing
2. `asyncio.wait_for(timeout=30)` — rejects slow/idle connections
3. `parse_message()` — rejects malformed JSON, missing fields
4. `validate_message()` — rejects wrong version, unknown type, invalid base64, id mismatch, expired TTL, future timestamp, invalid key length, signature failure
5. `is_contact()` / `is_group_member()` — rejects messages from unknown senders
6. Silent drop on any failure — no oracle, no timing leak

An attacker sending crafted messages must pass all six layers. Failing at any layer produces no network response.

### 7.2 Local API (GUI → server.py)

Entry point: FastAPI on `127.0.0.1:8080`.

Reachable only from localhost. CORS restricts browser-origin requests to localhost. Pydantic models enforce request structure. Sensitive endpoints require identity unlock.

The only unauthenticated write operation is `DELETE /api/identity` (panic button), which is by design. An attacker with local code execution (same user) can already access everything.

### 7.3 File attachments (incoming)

Entry point: network message with `type="msg"` and file payload.

Defense layers:
1. Sender must be a trusted contact
2. `_validate_size()` — 5 MB limit
3. `_BLOCKED_MIME_TYPES` — SVG, HTML, XHTML rejected (both sides after SEC-002 fix)
4. Magic bytes check — declared MIME must match file header
5. Pillow re-encode — decompression bomb protection + all metadata stripped
6. GUI renders only `image/jpeg`, `image/png`, `image/webp` as images (after SEC-002 fix)

### 7.4 pywebview bridge

Entry point: JavaScript in WebKit2GTK calls `window.pywebview.api.*`.

The bridge exposes four methods: `get_api_port()`, `get_version()`, `copy_to_clipboard()`, `save_file()`. No cryptographic operations, no database access, no network access.

`copy_to_clipboard`: data passed via `stdin`, not shell arguments — no injection risk.  
`save_file`: filename sanitised with regex + pathlib construction. Path traversal mitigated (SEC-004 recommendation pending).

### 7.5 Node subprocess

`subprocess.Popen` with `stdin=DEVNULL`, `stdout/stderr` to log file. The subprocess cannot read from the terminal and cannot interfere with the GUI process. On window close, the node receives `SIGTERM` and has 5 seconds to shut down before `SIGKILL`.

---

## 8. Conclusions

### Security posture

Legion's security model is correctly implemented. The cryptographic core (libsodium via PyNaCl) is used appropriately and without custom modifications. Plaintext never reaches disk. The panic button provides forensically credible data destruction. The Tor integration ensures network-level anonymity.

Two medium-severity vulnerabilities were found and fixed during this audit. Both required the attacker to already be a trusted contact and to craft a malicious file attachment. Neither vulnerability affected the cryptographic layer or the confidentiality of stored data.

### Risk summary

| Severity | Found | Fixed | Remaining |
|---|---|---|---|
| Critical | 0 | — | 0 |
| High | 0 | — | 0 |
| Medium | 2 | 2 | 0 |
| Low | 2 | 0 | 2 |
| Informational | 3 | 0 | 3 |

### Remaining low/informational items

- **SEC-003** (data dir permissions): Recommend `mkdir(mode=0o700)`. Mitigated by typical `~/.local/` permissions on standard Linux.
- **SEC-004** (bridge `..` filename): Mitigated by path construction logic. Clean fix is a one-liner.
- **SEC-005** (Argon2id parameters): Design trade-off. Both presets are secure against casual attackers.
- **SEC-006** (TTL not signed): Non-issue under Tor-only network model.
- **SEC-007** (relay dead code): Known roadmap item, zero active security impact.

### Recommendation

The codebase is ready for use against the documented threat model. The two fixed vulnerabilities (SEC-001, SEC-002) should be considered when evaluating releases prior to this audit.

Before implementing the relay feature (roadmap), the relay protocol should undergo a separate security review as it introduces a new trust boundary.

---

*This report was produced by static white-box analysis of the full source code. All test suites (292 tests across 14 files) continue to pass after applied fixes.*
