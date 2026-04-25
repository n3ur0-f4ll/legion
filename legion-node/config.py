
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
Konfiguracja węzła Legion.

Wszystkie wartości mają rozsądne domyślne. Nadpisywane przez argumenty
wiersza poleceń w main.py. Żadnych zewnętrznych bibliotek konfiguracyjnych.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "legion"
    return Path.home() / ".local" / "share" / "legion"


@dataclass
class Config:
    # Directories
    data_dir: Path = field(default_factory=_default_data_dir)

    # Network ports
    socks_port: int = 9050    # Tor SOCKS5 proxy
    control_port: int = 9051  # Tor control port
    node_port: int = 8765     # WebSocket server (Tor HS points here)
    api_port: int = 8080      # Local FastAPI (GUI connects here)

    # Logging
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------

    @property
    def db_path(self) -> Path:
        return self.data_dir / "node.db"

    @property
    def tor_data_dir(self) -> Path:
        return self.data_dir / "tor"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def ensure_dirs(self) -> None:
        """Create all required directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tor_data_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_args(cls, args) -> "Config":
        """Build Config from parsed argparse Namespace."""
        kwargs = {}
        if args.data_dir:
            kwargs["data_dir"] = Path(args.data_dir)
        if args.api_port:
            kwargs["api_port"] = args.api_port
        if args.node_port:
            kwargs["node_port"] = args.node_port
        if args.log_level:
            kwargs["log_level"] = args.log_level.upper()
        return cls(**kwargs)
