
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
import pathlib
import sys

import webview

from app.bridge import LegionBridge
from config import Config


def main() -> None:
    args = _parse_args()
    config = Config()

    if args.api_port:
        config.api_port = args.api_port
    if args.debug:
        config.debug = True

    bridge = LegionBridge(api_port=config.api_port)
    ui_dir = pathlib.Path(__file__).parent.parent / "ui"
    index = ui_dir / "index.html"

    if not index.exists():
        print(f"Error: UI files not found at {ui_dir}", file=sys.stderr)
        sys.exit(1)

    window = webview.create_window(
        title=config.title,
        url=str(index),
        js_api=bridge,
        width=config.width,
        height=config.height,
        min_size=(config.min_width, config.min_height),
        background_color="#0f0f0f",
    )

    webview.start(
        debug=config.debug,
        http_server=True,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="legion-gui", description="Legion GUI")
    parser.add_argument("--api-port", type=int, metavar="PORT",
                        help="legion-node API port (default: 8080)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable WebView developer tools")
    return parser.parse_args()


if __name__ == "__main__":
    main()
