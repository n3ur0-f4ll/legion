
# Legion — decentralized, anonymous communication platform
# Copyright (C) 2026  n3ur0-f4ll
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


"""
Punkt wejścia legion-gui.

Uruchamia okno pywebview z interfejsem Legion.
Legion-node musi być uruchomiony zanim uruchomi się GUI.
"""

from __future__ import annotations

import argparse
import logging
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

# Ensure legion-gui/ root is on sys.path regardless of how this file is invoked
_root = pathlib.Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import webview  # noqa: E402

from app.bridge import LegionBridge  # noqa: E402
from config import Config  # noqa: E402

logger = logging.getLogger(__name__)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_NODE_DIR = _REPO_ROOT / "legion-node"
_NODE_MAIN = _NODE_DIR / "main.py"


def main() -> None:
    args = _parse_args()
    config = Config()
    if args.api_port:
        config.api_port = args.api_port
    if args.debug:
        config.debug = True

    logging.basicConfig(level=logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")

    # --- start legion-node as subprocess ---
    node_proc = _start_node(config.api_port)
    if not _wait_for_node(config.api_port):
        if node_proc:
            node_proc.terminate()
        print("Error: legion-node failed to start.", file=sys.stderr)
        sys.exit(1)

    # --- open GUI window ---
    ui_dir = pathlib.Path(__file__).parent.parent / "ui"
    index = ui_dir / "index.html"
    if not index.exists():
        if node_proc:
            node_proc.terminate()
        print(f"Error: UI files not found at {ui_dir}", file=sys.stderr)
        sys.exit(1)

    bridge = LegionBridge(api_port=config.api_port)
    window = webview.create_window(
        title=config.title,
        url=str(index),
        js_api=bridge,
        width=config.width,
        height=config.height,
        min_size=(config.min_width, config.min_height),
        background_color="#0f0f0f",
    )

    def on_closed():
        # Signal node to start shutting down immediately when window closes
        if node_proc and node_proc.poll() is None:
            node_proc.terminate()

    window.events.closed += on_closed

    webview.start(debug=config.debug, http_server=True, gui="gtk")

    # webview.start() returned — window is closed.
    # Wait for node to finish cleanly, then force-exit.
    # os._exit() is intentional: kills pywebview's HTTP server thread
    # (Bottle) which otherwise keeps the process alive indefinitely.
    if node_proc:
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()
            node_proc.wait()

    os._exit(0)


def _start_node(api_port: int) -> subprocess.Popen | None:
    if not _NODE_MAIN.exists():
        logger.warning("legion-node not found at %s", _NODE_MAIN)
        return None
    return subprocess.Popen(
        [sys.executable, str(_NODE_MAIN),
         "--no-interactive", f"--api-port={api_port}"],
        cwd=str(_NODE_DIR),
    )


def _wait_for_node(api_port: int, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{api_port}/api/status", timeout=1
            )
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="legion-gui", description="Legion")
    parser.add_argument("--api-port", type=int, metavar="PORT",
                        help="legion-node API port (default: 8080)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable WebView developer tools")
    return parser.parse_args()


if __name__ == "__main__":
    main()
