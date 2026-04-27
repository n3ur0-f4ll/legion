# Legion — Security Model

This document explains how Legion protects your messages, files and identity.
Every mechanism described here is directly derived from the source code.

---

## What Legion is

Legion is a messaging application designed from the ground up for privacy and security.
It uses no central servers. There is no company storing your data.
Your node communicates directly with your contact's node — through the Tor network.

---

## Network Anonymity — Tor

Every message and file travels through the **Tor network**, a decentralized overlay that
hides the origin and destination of each connection.

- Your real IP address is never visible to contacts or relay operators
- Your contact's IP address is never visible to you
- Tor relay nodes see only encrypted traffic — never its content
- Every Legion node operates as a Tor v3 Hidden Service (`.onion` address)
- The node only accepts connections from within Tor — clearnet connections are impossible
- The `.onion` address is derived deterministically from your Ed25519 public key,
  so it is stable across restarts and consistent with your identity

---

## Private Message Encryption

Every private message is encrypted with the recipient's public key.

**Algorithm:** X25519 (Diffie-Hellman key exchange) + XSalsa20-Poly1305 (authenticated
encryption) — implemented via **libsodium** (PyNaCl).

Both keys are Ed25519 keypairs; libsodium converts them to Curve25519 internally for
the Box construction. This conversion is a well-established, safe technique.

In practice:

- Only you and your contact can decrypt the message
- No intermediary — relay operator, Tor node, or anyone else — can read it
- Any tampering with the ciphertext in transit is detected and the message is silently dropped
- Every message uses a unique random nonce, so identical plaintexts produce different ciphertexts

---

## Digital Signatures and Message Validation

Every message is signed by the sender's private key before transmission.

**Signing algorithm:** Ed25519 — the same algorithm used by OpenSSH and many TLS
implementations.

Before any incoming message is processed, the receiving node verifies:

1. **Ed25519 signature** — the message was created by the claimed sender
2. **Payload integrity** — `id == SHA256(payload)` — the payload was not altered
3. **Timestamp validity** — messages with a timestamp more than 5 minutes in the future
   are rejected (prevents future-dated replay)
4. **TTL check** — messages older than their declared TTL are discarded

A message failing any of these checks is silently dropped with no response to the sender.
This prevents information leakage about which addresses are active.

---

## Private Key Protection

Your Ed25519 private key is your identity. Legion protects it in two ways.

**1. Never leaves the device.**
The private key is never transmitted over the network and never stored on any external server.

**2. Encrypted at rest.**
The key is encrypted before being written to disk:

- **Argon2id** (OWASP-recommended password hashing) derives a 256-bit encryption key from
  your password. It is resistant to dictionary attacks and GPU/ASIC acceleration.
- **XSalsa20-Poly1305 (SecretBox)** encrypts the private key seed.
- A unique random 16-byte salt is generated per password — identical passwords produce
  different encryption keys.

The password is required at **every launch** — intentionally, as an additional layer of
protection in case of device theft. The decrypted private key lives in RAM only while the
application is running.

---

## Files and Images

Files are encrypted with the **same algorithm as private messages**
(X25519 + XSalsa20-Poly1305). A file is treated as a byte sequence — the cryptography
does not distinguish between text, images or PDF documents.

### Two-sided Sanitization

Every file additionally passes through **bidirectional sanitization**:

**Sender side (before encryption):**
The **Pillow** library (Python Imaging Library) re-encodes every image from scratch.
This removes all hidden data:

- GPS coordinates and location (EXIF)
- Camera model, lens, exposure settings
- Date and time of capture
- ICC color profiles
- XMP metadata (Adobe etc.)
- Embedded thumbnails
- Comments and descriptions

Re-encoding is not "clearing fields" — it constructs a new file from scratch, which is
more thorough than selective metadata removal.

**Receiver side (after decryption):**
The same sanitization process runs again after the file is decrypted. Even if the sender
skipped sanitization or used a modified client, your node cleans the file before saving it.

**Format verification:**
Before sanitization, the file's header bytes ("magic bytes") are checked.
A file cannot impersonate a different format than it declares.

---

## Plaintext Never on Disk

Messages are stored in the local SQLite database **in encrypted form only**.
Decryption happens exclusively at API read time — the plaintext result is never written
to disk.

This means that even full access to the `node.db` file does not allow reading message
content without knowing your password (which is needed to unlock the private key).

---

## Group Chats

### Encryption model

A group is a **shared symmetric key** (32 bytes, XSalsa20-Poly1305 / SecretBox)
generated randomly by the group creator. Every post is encrypted with this key and
individually signed with the author's Ed25519 private key.

- Post content is visible only to holders of the group key
- Each post is individually signed — impersonating another member is cryptographically impossible
- Relay operators, Tor nodes, and third parties cannot read posts

### Invitations

When an admin invites a new member, the invite payload contains:

- The group key encrypted with the new member's public key (X25519 + XSalsa20-Poly1305)
- The full member roster (`.onion` addresses and public keys of all current members)
- Group metadata (identifier, name)

**The entire invite payload is Box-encrypted for the recipient.**
Group metadata is not visible to any third party in the network layer.
Only the invited person can decrypt the invite contents.

After accepting, the new member has all other members' `.onion` addresses and can deliver
posts peer-to-peer without the admin acting as a router.

### Peer-to-peer routing

Group posts are delivered **peer-to-peer** from the sender directly to every member
through Tor. The admin is not a message router — admin unavailability does not prevent
communication between remaining members.

### Key rotation after member removal

When the admin forcibly removes a member:

1. A new random group key (K₂) is generated
2. K₂ is sent to every remaining member individually, Box-encrypted with their public key
3. All new posts use K₂ exclusively
4. The removed member can no longer decrypt new posts

**Boundary of protection:** the removed member retains the old key K₁ and can still read
posts from the period when they were a member. Full forward secrecy would require a
per-member ratchet mechanism (as in Signal) — that would be significantly more complex.
Key rotation protects **future** communication.

The receiver's node accepts a `group_key_update` only if the sender is recorded as the
admin of that group in the local database.

### Voluntary member departure

When a member leaves voluntarily, they sign and broadcast their own departure
(`group_member_update`) to all remaining members. The Ed25519 signature ensures only the
departing member can announce their own departure — they cannot remove others.

Upon receiving this, the admin's node automatically performs a key rotation, sending the
new key to all remaining members. The departing member receives no new posts.

### Group dissolution by admin

When the admin dissolves the group, every member receives a notification telling them they
have been removed (`dissolved=true`). Each member's node deletes the group from their local
database upon receiving this message.

### Roster change notifications

When a member joins or leaves, the admin sends a `group_member_update` message to all
remaining members, encrypted per-recipient with their public key. Each node updates its
local member list independently.

---

## Sender Filtering

Legion only accepts messages from **known senders**.

- Private messages: sender must be in your contacts list
- Group posts: author must be a member of the relevant group
- Group invitations: only from existing contacts

Messages from unknown addresses are silently dropped with no response.
This makes active node enumeration and scanning significantly harder.

---

## Contact Verification (Contact Cards)

A contact card — a signed JSON file exchanged when adding a contact — contains an
**Ed25519 digital signature**. The signature covers the public key, `.onion` address,
and suggested display name.

Your node verifies the signature before adding the contact — you cannot be impersonated
even if an attacker knows your `.onion` address.

---

## Message Expiry (TTL)

Every message carries a TTL (time-to-live) value, configurable by the sender from 1 hour
to 30 days (default: 7 days).

- The sender's delivery queue stops retrying once `now - timestamp > ttl`
- The receiver's node rejects messages where `now - timestamp > ttl` (message age exceeds TTL)
- Both checks use the `timestamp` field embedded in the message at creation time
- Messages with a `timestamp` more than 5 minutes in the future are also rejected —
  a future timestamp would make the age calculation negative, allowing a message to
  evade expiry indefinitely

---

## Panic Button

Available in **Settings → Danger zone**.

After double confirmation, the panic button:

1. Deletes all rows from every database table:
   identity, contacts, messages, groups, group_members, group_posts, delivery_queue, relay_config
2. Runs `VACUUM` — SQLite rewrites the database file from scratch, so freed pages
   (deleted rows) are not present in the new file and cannot be recovered from it
3. Clears the in-memory private key immediately
4. Returns the UI to the identity creation screen

The operation is **irreversible** and executes immediately.

**Note on disk-level forensics:** `VACUUM` ensures deleted data is not in the database
file. However, the original bytes may remain in unallocated sectors of the storage medium
until overwritten by the operating system. Full disk encryption (e.g. LUKS) eliminates
this residual risk.

---

## What Legion Does NOT Guarantee

An honest explanation of the protection limits:

- **Device security** — if your computer is infected with malware or someone has physical
  access while the application is running (key in memory), cryptographic protection is bypassed

- **Metadata anonymity** — Tor hides your IP, but the fact that you communicate with a
  specific `.onion` address may be inferred by a sufficiently powerful adversary controlling
  large portions of the Tor network through traffic correlation analysis

- **Your contact's security** — Legion cannot guarantee that the other end is secure

- **Resistance to coercion** — no technology protects against forced disclosure of
  your password

---

## Cryptographic Libraries

Legion uses only established, widely-audited libraries:

| Library | Use |
|---|---|
| **libsodium** (via PyNaCl) | X25519, Ed25519, XSalsa20-Poly1305, Argon2id |
| **Pillow** | Image sanitization, metadata stripping |
| **Stem** | Tor process management |

No custom cryptographic algorithms are implemented in this application.

---

## Source Code

Legion is **open source** software licensed under AGPL-3.0.
Anyone can review the code, verify the mechanisms described here, and report bugs.

Security through transparency, not obscurity.
