
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


"""Konfiguracja węzła relay Legion."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "legion-relay"
    return Path.home() / ".local" / "share" / "legion-relay"


@dataclass
class Config:
    data_dir: Path = field(default_factory=_default_data_dir)

    socks_port: int = 9052    # separate from node to allow co-location
    control_port: int = 9053
    relay_port: int = 8766    # WebSocket server (Tor HS points here)

    max_message_size_kb: int = 512
    max_stored_messages: int = 10_000
    max_ttl_days: int = 30
    cleanup_interval: int = 3600

    log_level: str = "INFO"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "relay.db"

    @property
    def tor_data_dir(self) -> Path:
        return self.data_dir / "tor"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tor_data_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_args(cls, args) -> "Config":
        kwargs = {}
        if getattr(args, "data_dir", None):
            kwargs["data_dir"] = Path(args.data_dir)
        if getattr(args, "relay_port", None):
            kwargs["relay_port"] = args.relay_port
        if getattr(args, "log_level", None):
            kwargs["log_level"] = args.log_level.upper()
        return cls(**kwargs)
