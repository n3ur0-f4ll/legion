# Legion

**Decentralized. Anonymous. Yours.**

> Version `0.1.6` · Python `≥ 3.12` · Linux only · License: AGPL-3.0

Legion is a messaging application built from the ground up for privacy and security.
It requires no central servers, no accounts, and no phone numbers.
Every message travels end-to-end encrypted through the Tor network.

---

## Features

- **End-to-end encryption** — X25519 + XSalsa20-Poly1305 (libsodium) for all messages and files
- **Tor Hidden Service** — every node operates as a `.onion` address; your real IP is never exposed
- **No central infrastructure** — peer-to-peer delivery, no company, no cloud
- **Private key encrypted at rest** — Argon2id password hashing, password required at every launch
- **Group chats** — shared symmetric key, peer-to-peer delivery, key rotation on member removal
- **File transfer** — images re-encoded by Pillow before sending (GPS, EXIF and all metadata stripped)
- **Persistent delivery queue** — messages retry every 10 seconds until delivered, survive app restarts
- **Panic button** — immediately and irreversibly destroys all local data (identity, messages, contacts, groups)
- **Open source** — AGPL-3.0, fully auditable

For a detailed explanation of the security model see **[SECURITY.md](SECURITY.md)**.

---

## Requirements

### Operating system

Linux only. Tested on Arch / Manjaro.

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

### 1. Clone the repository

```bash
git clone https://github.com/n3ur0-f4ll/legion.git
cd legion
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Link the system PyGObject (gi) into the venv

`gi` (PyGObject) must be installed as a system package and linked into the venv.
Installing it via pip is not supported.

```bash
PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ln -sf /usr/lib/python${PYVER}/site-packages/gi \
       .venv/lib/python${PYVER}/site-packages/gi
```

---

## Running

```bash
python3 legion-gui/app/main.py
```

This single command:

1. Starts `legion-node` in the background (no separate step needed)
2. Waits for the node API to become available
3. Opens the Legion window

On first launch you will be prompted to create an identity and set a password.
The password is required at every subsequent launch to unlock your private key.

---

## First use

1. **Create identity** — choose a display name and a strong password (no recovery is possible if forgotten)
2. **Share your contact card** — go to Settings and copy your contact card JSON, send it to your contact through any channel
3. **Add a contact** — paste their contact card JSON into "Add contact"
4. **Start messaging** — your node connects through Tor automatically

> The first connection to a new `.onion` address can take 60–180 seconds while Tor builds
> the necessary circuits and publishes the Hidden Service descriptor. Subsequent connections
> are faster.

---

## Project structure

```
legion/
├── legion-node/    — user node: crypto, Tor HS, WebSocket server, local REST API
├── legion-relay/   — optional relay node for offline message delivery
├── legion-gui/     — desktop GUI (pywebview + HTML/CSS/JS)
├── requirements.txt
├── VERSION
├── SECURITY.md     — detailed security model
└── README.md
```

`legion-node` and `legion-gui` are the two components used by end users.
`legion-relay` is an optional self-hosted relay that delivers messages when you are offline.

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

Legion's security model is documented in detail in **[SECURITY.md](SECURITY.md)**.
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
