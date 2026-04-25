
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


"""Tests for network/relay.py."""

from unittest.mock import AsyncMock, patch

import pytest

from core.identity import generate as gen
from core.protocol import MSG_PRIVATE, build_message
from core.storage import Database
from network.client import NodeClientError
from network.relay import (
    RelayError,
    choose_destination,
    get_relay_onion,
    is_relay_configured,
    send_via_relay,
)

ALICE = gen("alice")
BOB = gen("bob")

RELAY_ONION = "relayrelayrela yrelayrelayrelayrelayrelayrelayrelayrelayrelay.onion".replace(" ", "")
RELAY_KEY = "a" * 64


@pytest.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


@pytest.fixture
async def db_with_relay(db):
    await db.save_relay_config(RELAY_ONION, RELAY_KEY, enabled=True)
    return db


@pytest.fixture
async def db_relay_disabled(db):
    await db.save_relay_config(RELAY_ONION, RELAY_KEY, enabled=False)
    return db


def valid_msg() -> dict:
    return build_message(MSG_PRIVATE, ALICE.public_key, BOB.public_key, b"data", ALICE.private_key)


# ------------------------------------------------------------------
# is_relay_configured
# ------------------------------------------------------------------

async def test_is_relay_configured_no_config(db):
    assert await is_relay_configured(db) is False


async def test_is_relay_configured_enabled(db_with_relay):
    assert await is_relay_configured(db_with_relay) is True


async def test_is_relay_configured_disabled(db_relay_disabled):
    assert await is_relay_configured(db_relay_disabled) is False


# ------------------------------------------------------------------
# get_relay_onion
# ------------------------------------------------------------------

async def test_get_relay_onion_no_config_raises(db):
    with pytest.raises(RelayError, match="No relay"):
        await get_relay_onion(db)


async def test_get_relay_onion_disabled_raises(db_relay_disabled):
    with pytest.raises(RelayError, match="disabled"):
        await get_relay_onion(db_relay_disabled)


async def test_get_relay_onion_returns_address(db_with_relay):
    onion = await get_relay_onion(db_with_relay)
    assert onion == RELAY_ONION


# ------------------------------------------------------------------
# send_via_relay
# ------------------------------------------------------------------

async def test_send_via_relay_no_config_raises(db):
    with pytest.raises(RelayError):
        await send_via_relay(db, valid_msg())


async def test_send_via_relay_calls_send_message(db_with_relay):
    msg = valid_msg()
    with patch("network.relay.send_message", new_callable=AsyncMock) as mock_send:
        await send_via_relay(db_with_relay, msg)
        mock_send.assert_awaited_once()
        call_args = mock_send.call_args
        assert call_args.args[0] is msg
        assert call_args.args[1] == RELAY_ONION


async def test_send_via_relay_passes_socks_params(db_with_relay):
    msg = valid_msg()
    with patch("network.relay.send_message", new_callable=AsyncMock) as mock_send:
        await send_via_relay(db_with_relay, msg, socks_host="127.0.0.1", socks_port=19050)
        _, kwargs = mock_send.call_args
        assert kwargs["socks_host"] == "127.0.0.1"
        assert kwargs["socks_port"] == 19050


async def test_send_via_relay_propagates_client_error(db_with_relay):
    msg = valid_msg()
    with patch(
        "network.relay.send_message",
        new_callable=AsyncMock,
        side_effect=NodeClientError("relay offline"),
    ):
        with pytest.raises(NodeClientError):
            await send_via_relay(db_with_relay, msg)


# ------------------------------------------------------------------
# choose_destination
# ------------------------------------------------------------------

async def test_choose_destination_no_relay(db):
    onion, via_relay = await choose_destination(db, "bob.onion")
    assert onion == "bob.onion"
    assert via_relay is False


async def test_choose_destination_with_relay(db_with_relay):
    onion, via_relay = await choose_destination(db_with_relay, "bob.onion")
    assert onion == RELAY_ONION
    assert via_relay is True


async def test_choose_destination_relay_disabled(db_relay_disabled):
    onion, via_relay = await choose_destination(db_relay_disabled, "bob.onion")
    assert onion == "bob.onion"
    assert via_relay is False


async def test_choose_destination_relay_returns_relay_onion_not_recipient(db_with_relay):
    recipient_onion = "recipient123.onion"
    onion, via_relay = await choose_destination(db_with_relay, recipient_onion)
    assert onion != recipient_onion
    assert onion == RELAY_ONION
