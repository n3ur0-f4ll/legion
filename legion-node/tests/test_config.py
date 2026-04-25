
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


"""Tests for config.py."""

import argparse
from pathlib import Path

from config import Config


def test_default_data_dir_is_under_home():
    cfg = Config()
    assert str(Path.home()) in str(cfg.data_dir)


def test_default_ports():
    cfg = Config()
    assert cfg.socks_port == 9050
    assert cfg.control_port == 9051
    assert cfg.node_port == 8765
    assert cfg.api_port == 8080


def test_default_log_level():
    cfg = Config()
    assert cfg.log_level == "INFO"


def test_db_path_inside_data_dir():
    cfg = Config(data_dir=Path("/tmp/test_legion"))
    assert cfg.db_path == Path("/tmp/test_legion/node.db")


def test_tor_data_dir_inside_data_dir():
    cfg = Config(data_dir=Path("/tmp/test_legion"))
    assert cfg.tor_data_dir == Path("/tmp/test_legion/tor")


def test_ensure_dirs_creates_directories(tmp_path):
    cfg = Config(data_dir=tmp_path / "legion")
    assert not cfg.data_dir.exists()
    cfg.ensure_dirs()
    assert cfg.data_dir.exists()
    assert cfg.tor_data_dir.exists()


def test_ensure_dirs_idempotent(tmp_path):
    cfg = Config(data_dir=tmp_path / "legion")
    cfg.ensure_dirs()
    cfg.ensure_dirs()  # must not raise


def test_from_args_data_dir():
    args = argparse.Namespace(
        data_dir="/tmp/custom", api_port=None, node_port=None, log_level=None
    )
    cfg = Config.from_args(args)
    assert cfg.data_dir == Path("/tmp/custom")


def test_from_args_ports():
    args = argparse.Namespace(
        data_dir=None, api_port=9090, node_port=9191, log_level=None
    )
    cfg = Config.from_args(args)
    assert cfg.api_port == 9090
    assert cfg.node_port == 9191


def test_from_args_log_level():
    args = argparse.Namespace(
        data_dir=None, api_port=None, node_port=None, log_level="debug"
    )
    cfg = Config.from_args(args)
    assert cfg.log_level == "DEBUG"


def test_from_args_all_none_uses_defaults():
    args = argparse.Namespace(
        data_dir=None, api_port=None, node_port=None, log_level=None
    )
    defaults = Config()
    cfg = Config.from_args(args)
    assert cfg.socks_port == defaults.socks_port
    assert cfg.api_port == defaults.api_port
    assert cfg.log_level == defaults.log_level


def test_xdg_data_home_respected(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    cfg = Config()
    assert cfg.data_dir == tmp_path / "legion"
