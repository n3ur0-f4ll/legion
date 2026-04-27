# legion-gui — Overview

`legion-gui` is the desktop interface for Legion. It is built with **pywebview** (GTK/WebKit2
backend on Linux) and renders a vanilla HTML/CSS/JS single-page application inside a native
window. It acts as a launcher for `legion-node` — the user only runs `legion-gui`.

---

## Architecture

```
python3 legion-gui/app/main.py
          │
          ├─ spawns ──► legion-node/main.py --no-interactive
          │              stdin=DEVNULL  stdout/stderr=node.log
          │              (subprocess, log → ~/.local/share/legion/node.log)
          │
          ├─ waits ───► GET /api/status (polls until HTTP 200)
          │
          └─ opens ───► pywebview window
                         ├── http_server=True   (Bottle serves ui/ directory)
                         ├── gui="gtk"
                         └── js_api=LegionBridge
                               │
                               ├── GET /api/*  ────► FastAPI (localhost:8080)
                               └── SSE /api/events  (live updates)
```

The node subprocess has `stdin=DEVNULL` and `stdout/stderr` redirected to a log file.
This prevents node output from appearing in the user's terminal and avoids terminal
state corruption.

---

## app/main.py

Entry point. Orchestrates startup and shutdown.

### Functions

#### `main() → None`
1. Parses CLI args (`--api-port`, `--debug`)
2. Checks if node is already running (`_wait_for_node(timeout=1)`) — attaches if so
3. Calls `_start_node()` and waits up to 30 seconds for it to become ready
4. Sets GTK app name and application name via `GLib.set_prgname("legion")` /
   `GLib.set_application_name("Legion")` — must be called **before** `create_window`
   so the Wayland compositor identifies the app correctly (taskbar icon)
5. Installs XDG resources if logo is present
6. Creates pywebview window with `LegionBridge` as `js_api`
7. Registers `on_closed` callback to terminate the node when window closes
8. Calls `webview.start(http_server=True, gui="gtk", func=_apply_gtk_icon)`
9. After `start()` returns (window closed): waits up to 5 seconds for node to exit,
   then kills if still running
10. Calls `os._exit(0)` — **intentional**, bypasses normal Python shutdown to kill the
    Bottle HTTP server thread that pywebview creates internally and which does not
    terminate via normal `sys.exit()`

#### `_start_node(api_port) → subprocess.Popen | None`
Spawns `legion-node/main.py --no-interactive --api-port={api_port}`:

```python
subprocess.Popen(
    [sys.executable, str(_NODE_MAIN), "--no-interactive", f"--api-port={api_port}"],
    cwd=str(_NODE_DIR),
    stdin=subprocess.DEVNULL,
    stdout=log_file,
    stderr=log_file,
)
```

Log file: `~/.local/share/legion/node.log`. The parent closes its copy of `log_file`
after `Popen()` — the child retains its own file descriptor (standard Unix fork behaviour).

#### `_wait_for_node(api_port, timeout) → bool`
Polls `GET http://127.0.0.1:{api_port}/api/status` every 300ms until a successful
response or timeout. Returns `True` if the node became reachable within the timeout.

#### `_install_xdg_resources(icon_path) → None`
Installs the application icon and `.desktop` file to `~/.local/share/` on every launch.
This is idempotent — safe to call repeatedly.

- Copies `icon_path` to `~/.local/share/icons/hicolor/256x256/apps/legion.png`
- Runs `gtk-update-icon-cache` (best-effort, failure ignored)
- Writes `~/.local/share/applications/legion.desktop`

Must be called **before** `create_window` so the Wayland compositor has the icon
available when the window first appears.

#### `_apply_gtk_icon() → None`
Called via `func=` parameter of `webview.start()` — runs after the GTK main loop starts.
Sets the window icon via `Gtk.Window.set_default_icon()` as an additional path for
environments that don't pick up the XDG icon immediately.

---

## app/bridge.py

The pywebview JS/Python bridge. Exposed as `window.pywebview.api` in the browser context.
All methods are called from JavaScript and execute in the Python process.

### `LegionBridge` (class)

#### `get_api_port() → int`
Returns the API port. Called once at boot from JavaScript to configure the base URL
for all API calls.

#### `get_version() → str`
Reads and returns the content of the `VERSION` file from the monorepo root.
Displayed in the sidebar as a version label.

#### `copy_to_clipboard(text: str) → bool`
Copies `text` to the system clipboard. Detects Wayland vs X11 automatically:

1. Tries `wl-copy` (Wayland)
2. Falls back to `xclip -selection clipboard` or `xsel --clipboard --input` (X11)

Returns `True` on success, `False` if no clipboard tool is available.
Runs synchronously (subprocess call) — acceptable for clipboard operations.

#### `save_file(base64_data: str, filename: str) → str`
Saves a base64-encoded file to `~/Downloads/`. Returns the full path, or `""` on failure.

1. Sanitizes filename with `re.sub(r'[/\\:*?"<>|]', "_", filename)` — replaces all
   path-unsafe characters, falls back to `"file"` if result is empty
2. Creates `~/Downloads/` if it does not exist
3. Avoids overwriting existing files by appending a counter (`photo_1.jpg`, `photo_2.jpg`)
4. Writes decoded bytes and returns the final path, or `""` on any exception

#### `show_notification(title: str, message: str) → None`
Sends a desktop notification via `notify-send`. Best-effort — failure is silently ignored.

---

## ui/ — Frontend

Single-page application: one `index.html`, one `style.css`, one `app.js`. No build tools,
no frameworks, no npm. Served by pywebview's embedded Bottle HTTP server.

### Startup sequence in JavaScript

```
DOMContentLoaded
    └─ if window.pywebview: boot()
       else: window.addEventListener("pywebviewready", boot)
               │
               ▼
             boot()
               ├─ API_PORT = await window.pywebview.api.get_api_port()
               └─ initApp()
                     ├─ GET /api/status
                     ├─ identity_loaded → showMain()
                     ├─ identity_exists → showView("unlock")
                     └─ neither        → showView("onboarding")
```

The bridge (`window.pywebview.api`) is not available at `DOMContentLoaded` — it becomes
available asynchronously and fires `pywebviewready`. Both paths are handled.

### Views

| View id | When shown |
|---|---|
| `view-unlock` | Identity exists, password not yet entered |
| `view-onboarding` | First launch, no identity |
| `view-main` | Identity loaded and Tor running/starting |

### Panels (inside `view-main`)

| Panel id | Content |
|---|---|
| `panel-welcome` | Empty state placeholder |
| `panel-messages` | Private conversation with current contact |
| `panel-group` | Group chat with member list |
| `panel-network` | Network log with bandwidth display |
| `panel-opsec` | OpSec guide |
| `panel-settings` | Settings: alias, TTL, relay, panic button |

### Key JavaScript state

| Variable | Type | Purpose |
|---|---|---|
| `API_PORT` | `number` | Port for all API calls |
| `identity` | `object \| null` | Current identity (public_key, alias, default_ttl, ...) |
| `currentContact` | `object \| null` | Open conversation contact |
| `currentGroup` | `object \| null` | Open group |
| `eventSource` | `EventSource \| null` | Active SSE connection |
| `pendingFile` | `object \| null` | File selected for attachment |
| `networkLog` | `array` | Ring buffer of last 200 network log entries |
| `defaultTtl` | `number` | Global default TTL in seconds |
| `msgTtl` | `number \| null` | Per-message TTL override (null = use default) |

### API helper

```javascript
async function api(method, path, body = null) → any
```

All API calls go through this function. Handles:
- JSON serialisation of request body
- HTTP error handling (including FastAPI Pydantic validation error arrays)
- Returns parsed JSON or null for HTTP 204

### SSE connection

`connectSSE()` opens `EventSource` to `/api/events`. On disconnect, retries after 5 seconds.
`handleEvent(event)` dispatches by `event.type` to update the relevant UI components.

### Message TTL picker

The `⏱` button in the message input row opens a dropdown with TTL presets.
State:
- `defaultTtl` — loaded from `identity.default_ttl` at login
- `msgTtl` — per-message override; null means use `defaultTtl`; reset to null after send

### Network log

`appendNetLog(entry)` adds entries to the DOM only if `panel-network` is visible.
`renderNetLog()` re-renders all entries when the filter changes or the panel is opened.
`netLogAutoScroll` pauses auto-scroll when the user has scrolled up.

---

## config.py

```python
@dataclass
class Config:
    api_port: int = 8080
    title: str = "Legion"
    width: int = 1100
    height: int = 720
    min_width: int = 800
    min_height: int = 550
    debug: bool = False
```

Simple dataclass, no external dependencies. Modified by CLI args in `main.py`.
