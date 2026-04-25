
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
Pywebview JS/Python bridge.

Udostępnia minimlane API natywne: port API, schowek, powiadomienia.
Bridge nie ma dostępu do kryptografii, bazy danych ani sieci.
"""

from __future__ import annotations

import subprocess
import logging

logger = logging.getLogger(__name__)


class LegionBridge:
    """Exposed to JavaScript as window.pywebview.api."""

    def __init__(self, api_port: int) -> None:
        self._api_port = api_port

    def get_api_port(self) -> int:
        """Return the port on which legion-node API is listening."""
        return self._api_port

    def copy_to_clipboard(self, text: str) -> bool:
        """Copy text to system clipboard. Returns True on success."""
        encoded = text.encode()
        for cmd in (
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
            ["wl-copy"],
        ):
            try:
                subprocess.run(cmd, input=encoded, check=True, capture_output=True)
                return True
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
        logger.warning("No clipboard tool found (xclip/xsel/wl-copy)")
        return False

    def show_notification(self, title: str, message: str) -> None:
        """Display a system notification (best-effort)."""
        try:
            subprocess.run(
                ["notify-send", "--app-name=Legion", title, message],
                check=False,
                capture_output=True,
            )
        except FileNotFoundError:
            pass
