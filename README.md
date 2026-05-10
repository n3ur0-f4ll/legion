# Legion

**Decentralized. Anonymous. Yours.**

> Version `0.1.8` · Python `≥ 3.12` · Linux only · License: AGPL-3.0

> author: n3ur0-f4ll

Legion is a messaging application built from the ground up for privacy and security.
It requires no central servers, no accounts, and no phone numbers.
Every message travels end-to-end encrypted through the Tor network.

---

## Who it's for

Legion is built for people who need communication that cannot be intercepted,
blocked, or handed over to a third party — because there is no third party.

- **Journalists and sources** — exchange information without leaving a trail that can be
  subpoenaed, seized, or leaked through a company's servers
- **Lawyers and clients** — attorney-client privilege enforced at the cryptographic level,
  not just by contract
- **Activists and human rights workers** — no central server to block, no company to
  pressure, no account to suspend
- **Security researchers** — fully auditable, open source, no black boxes
- **Anyone in a high-risk environment** — people whose location, identity, or
  communications must remain private regardless of who is watching the network

If your threat model is "a company might get hacked or receive a legal order,"
Legion eliminates that threat at the architectural level.

---

## What makes Legion different

Most messaging applications protect the **content** of your messages. Legion protects
the content, the metadata, and the infrastructure itself.

| Property | How Legion achieves it |
|---|---|
| **No central server** | Every user runs their own node. There is no server to shut down, block, subpoena, or hack. |
| **No accounts** | No phone number, no email address, no registration of any kind. Your identity is a cryptographic key generated on your device. |
| **Network-level anonymity** | All traffic routes through the Tor network. Your IP address is never visible to your contacts, relay operators, or network observers. |
| **Metadata-free storage** | Plaintext is never written to disk. The local database stores only encrypted ciphertext — unreadable without your password. |
| **Image metadata stripped** | Photos are re-encoded from scratch before sending. GPS coordinates, camera model, timestamps and all EXIF data are permanently removed. |
| **Emergency destruction** | The panic button immediately and irreversibly destroys all local data including a database-level overwrite — no forensic recovery. |
| **Key rotation** | When a group member is removed, the group encryption key is automatically rotated and redistributed. Removed members cannot read future messages. |
| **Fully open source** | AGPL-3.0. Every line of code is auditable. No closed components, no telemetry, no update servers. |

---

## Features

- **End-to-end encryption** — X25519 + XSalsa20-Poly1305 (libsodium) for all messages and files
- **Tor Hidden Service** — every node operates as a `.onion` address; your real IP is never exposed
- **No central infrastructure** — peer-to-peer delivery, no company, no cloud
- **Private key encrypted at rest** — Argon2id password hashing, password required at every launch
- **Group chats** — shared symmetric key, peer-to-peer delivery, file and image sharing, automatic key rotation on member removal
- **File transfer** — images and files supported in both private chats and groups; images re-encoded by Pillow before sending (GPS, EXIF and all metadata stripped)
- **Burn after reading** — messages marked with 🔥 are deleted from the recipient's device when they leave the conversation (giving them time to read at their own pace), and from the sender's device once the recipient confirms they read it
- **Persistent delivery queue** — messages retry every 10 seconds while Legion is running; state is saved so retries resume after reopening the app
- **QR contact card** — generate a QR code of your contact card for easy sharing; others scan it with any phone camera
- **Panic button** — immediately and irreversibly destroys all local data (identity, messages, contacts, groups)
- **Open source** — AGPL-3.0, fully auditable

For a detailed explanation of the security model see **[SECURITY.md](SECURITY.md)**.

---

## Requirements

### Operating system

Linux only. Tested on Arch.

### System packages

```bash
sudo pacman -S python-gobject webkit2gtk-4.1 wl-clipboard tor
```

> **Wayland users** (default on modern Arch/Manjaro): `wl-clipboard` provides clipboard support.
> X11 users may substitute `xclip` or `xsel` instead.

### Python

Version 3.12 or newer. Check with:

```bash
python3 --version
```

---

## Installation

### Automatic (recommended)

```bash
git clone https://github.com/n3ur0-f4ll/legion.git
cd legion
bash install.sh
```

The installer supports **Arch / EndeavourOS / Manjaro**, **Debian / Ubuntu / Mint**
and **Fedora / RHEL / Rocky Linux**. It installs system packages, creates a virtual
environment, installs Python dependencies and links the system PyGObject into the venv.

### Uninstall

```bash
bash uninstall.sh
```

Removes the venv, launcher, desktop entry and icon. Optionally removes personal data
(identity, messages, contacts). System packages are not removed automatically.

### Manual installation

<details>
<summary>Expand for manual steps</summary>

#### 1. Clone the repository

```bash
git clone https://github.com/n3ur0-f4ll/legion.git
cd legion
```

#### 2. Install system packages

```bash
# Arch / EndeavourOS / Manjaro
sudo pacman -S python-gobject webkit2gtk-4.1 wl-clipboard tor

# Debian / Ubuntu / Mint
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 \
    gir1.2-webkit2-4.1 wl-clipboard tor python3-venv

# Fedora / RHEL / Rocky
sudo dnf install python3-gobject webkit2gtk4.1 wl-clipboard tor
```

#### 3. Create virtual environment and install dependencies

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

#### 4. Link PyGObject (gi) into the venv

```bash
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

# Arch / Fedora (site-packages)
ln -sf /usr/lib/python${PYVER}/site-packages/gi .venv/lib/python${PYVER}/site-packages/gi

# Debian / Ubuntu (dist-packages)
ln -sf /usr/lib/python3/dist-packages/gi .venv/lib/python${PYVER}/site-packages/gi
```

</details>

---

## Running

After installation with `install.sh`, use the launcher:

```bash
./legion
```

Or double-click the **Legion** entry in your application menu (installed automatically).

The launcher:

1. Starts `legion-node` in the background (no separate step needed)
2. Waits up to 30 seconds for the node API to become available
3. Opens the Legion window

On first launch you will be prompted to create an identity and set a password.
The password is required at every subsequent launch to unlock your private key.

> **Without the installer:** `python3 legion-gui/app/main.py` works as a fallback,
> provided the virtual environment is active and system dependencies are installed.

---

## First use

1. **Create identity** — choose a display name and a strong password (no recovery is possible if forgotten)
2. **Share your contact card** — go to Settings → copy JSON or show a QR code; your contact scans it or pastes the JSON to add you
3. **Add a contact** — paste their contact card JSON into "Add contact"
4. **Start messaging** — your node connects through Tor automatically

> The first connection to a new `.onion` address can take 60–180 seconds while Tor builds
> the necessary circuits and publishes the Hidden Service descriptor. Subsequent connections
> are faster.

---

## How message delivery works

Legion has no central server. Your device connects **directly** to the recipient's device
through the Tor network — there is no middleman holding your messages.

This means two things you need to understand before you start:

### Both sides need to be online at the same time

When you send a message, your Legion node attempts to reach the recipient's node directly.

- **Recipient is online** → message arrives within seconds (plus Tor circuit build time).
- **Recipient is offline** → the message stays in your outbox and Legion retries
  automatically every 10 seconds for as long as the app is running.

**If you close Legion, retries stop.** The message is saved locally and will resume
retrying the next time you open Legion. It will never be lost — but it will not be
delivered until either you or your contact (or both) come back online.

### Why does it work this way?

Because there is no server between you and your contact. No company, no cloud,
no infrastructure that can be shut down, hacked, or handed over to authorities.

Think of it like this: Legion is less like WhatsApp (where messages wait on a company's
server until you log in) and more like a direct call — you both need to be present.
The trade-off is real but intentional: **the absence of a server is the security guarantee.**

### Practical advice

- Keep Legion running in the background when you are expecting an important message.
- The unread badge updates automatically the moment your contact comes online and the
  message arrives — you do not need to do anything.
- The `…` status indicator on a sent message means it is still queued. A `✓` means it
  was delivered. You can cancel a queued message at any time by clicking `×` next to it.
- To send a message that deletes itself after being read, click the 🔥 button before
  sending. The message stays visible until the recipient leaves the conversation —
  giving them time to read — then disappears from both devices automatically.

### Relay node (coming soon)

We are working on an optional **relay node** — a small always-online server you can
self-host or share with trusted people. When configured, your messages are handed off
to the relay immediately, and the relay delivers them 24/7 regardless of whether your
own device is online. The relay never sees the content of your messages (they remain
end-to-end encrypted). This feature is in active development.

---

## Project structure

```
legion/
├── legion-node/    — user node: crypto, Tor HS, WebSocket server, local REST API
├── legion-relay/   — optional relay node for offline message delivery (WIP)
├── legion-gui/     — desktop GUI (pywebview + HTML/CSS/JS)
├── docs/           — full technical reference (MkDocs)
├── install.sh      — automated installer (Arch · Debian · Fedora/RHEL)
├── uninstall.sh    — uninstaller
├── requirements.txt
├── VERSION
├── LICENSE         — AGPL-3.0
├── SECURITY.md     — security model, threat analysis, cryptographic primitives
├── SEC_AUDIT.md    — white-box penetration test and security audit report
├── DECISIONS.md    — deliberately rejected features and the reasoning behind each
└── README.md
```

`legion-node` and `legion-gui` are the two components used by end users.
`legion-relay` is an optional self-hosted relay that delivers messages when the sender is offline — in active development.

---

## Technical documentation

Full technical reference (classes, functions, API endpoints, database schema) is in the
`docs/` directory and rendered with [MkDocs](https://www.mkdocs.org/) +
[Material theme](https://squidfunk.github.io/mkdocs-material/).

### Install

```bash
pip install mkdocs mkdocs-material
```

### Live preview (hot-reload)

```bash
mkdocs serve
# opens at http://127.0.0.1:8000
```

### Build static HTML

```bash
mkdocs build        # output: site/
```

### Deploy to GitHub Pages

```bash
mkdocs gh-deploy    # publishes to username.github.io/legion
```

---

## Security

| Document | Contents |
|---|---|
| **[SECURITY.md](SECURITY.md)** | Full security model — cryptographic primitives, threat analysis, group key rotation, limitations |
| **[SEC_AUDIT.md](SEC_AUDIT.md)** | White-box penetration test and security audit — findings, severity, fixes applied, confirmed controls |
| **[DECISIONS.md](DECISIONS.md)** | Deliberately rejected features with full reasoning — presence indicator, voice messages, duress password, and others |

The short version:

- All cryptography is implemented via **libsodium** (PyNaCl) — no custom algorithms
- Messages and files are end-to-end encrypted; plaintext is never written to disk
- Your private key never leaves your device; it is encrypted with Argon2id at rest
- The Tor network hides your IP address from contacts, relay operators, and network observers
- The panic button (`Settings → Danger zone`) irreversibly destroys all local data instantly,
  including a `VACUUM` pass on the database to overwrite freed pages

---

## License

Legion is free software: you can redistribute it and/or modify it under the terms of the
**GNU Affero General Public License v3.0** as published by the Free Software Foundation.

See [LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html> for the full text.

**Security through transparency, not obscurity.**
