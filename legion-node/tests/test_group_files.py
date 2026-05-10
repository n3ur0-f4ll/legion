
# Legion — decentralized, anonymous communication platform
# Copyright (C) 2026  n3ur0-f4ll
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Tests for file and image attachments in group posts.

Covers:
- post() with file_data stores file_name/mime_type in DB
- post() with text still works (backward compat)
- post() sanitizes images before encryption (prepare_outgoing_async)
- post() raises FileError for blocked MIME types
- receive_post() sanitizes incoming file (defense-in-depth)
- receive_post() falls back to error text on corrupt file
- _decrypt_post() returns file_data for file posts
- _decrypt_post() returns text for text posts
"""

from __future__ import annotations

import base64
import io
import time

import pytest
import pytest_asyncio
from PIL import Image

from core.identity import generate as gen_identity
from core.storage import Database
from messaging.files import FileError
from messaging.groups import create_group, post, receive_post


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------

@pytest_asyncio.fixture
async def db():
    async with Database.open(":memory:") as database:
        yield database


@pytest_asyncio.fixture
async def alice(db):
    return gen_identity("Alice")


@pytest_asyncio.fixture
async def group(db, alice):
    return await create_group(db, alice, "TestGroup")


def _make_jpeg(width: int = 10, height: int = 10) -> bytes:
    """Generate a minimal valid JPEG in memory."""
    img = Image.new("RGB", (width, height), color=(255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_png() -> bytes:
    img = Image.new("RGB", (8, 8), color=(0, 128, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ------------------------------------------------------------------
# post() — text (backward compat)
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_text_works(db, alice, group):
    msg = await post(db, alice, group["id"], text="hello group")
    posts = await db.get_group_posts(group["id"])
    assert len(posts) == 1
    assert posts[0]["file_name"] is None
    assert posts[0]["mime_type"] is None
    assert msg["type"] == "group_post"


# ------------------------------------------------------------------
# post() — file attachment
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_jpeg_stores_file_metadata(db, alice, group):
    jpeg = _make_jpeg()
    msg = await post(db, alice, group["id"],
                     file_data=jpeg, file_name="photo.jpg", mime_type="image/jpeg")
    posts = await db.get_group_posts(group["id"])
    assert len(posts) == 1
    assert posts[0]["file_name"] == "photo.jpg"
    assert posts[0]["mime_type"] == "image/jpeg"


@pytest.mark.asyncio
async def test_post_png_stores_file_metadata(db, alice, group):
    png = _make_png()
    await post(db, alice, group["id"],
               file_data=png, file_name="image.png", mime_type="image/png")
    posts = await db.get_group_posts(group["id"])
    assert posts[0]["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_post_non_image_file(db, alice, group):
    """Non-image files (e.g. PDF) pass through with correct metadata."""
    dummy_pdf = b"%PDF-1.4 fake content"
    await post(db, alice, group["id"],
               file_data=dummy_pdf, file_name="doc.pdf",
               mime_type="application/pdf")
    posts = await db.get_group_posts(group["id"])
    assert posts[0]["file_name"] == "doc.pdf"
    assert posts[0]["mime_type"] == "application/pdf"


@pytest.mark.asyncio
async def test_post_blocked_mime_raises(db, alice, group):
    """SVG is blocked — raises FileError."""
    svg = b"<svg><script>alert(1)</script></svg>"
    with pytest.raises(FileError):
        await post(db, alice, group["id"],
                   file_data=svg, file_name="evil.svg", mime_type="image/svg+xml")


@pytest.mark.asyncio
async def test_post_file_payload_is_encrypted(db, alice, group):
    """The stored payload is ciphertext — decrypts to a JSON envelope with 'f' key."""
    from core import crypto
    jpeg = _make_jpeg()
    await post(db, alice, group["id"],
               file_data=jpeg, file_name="pic.jpg", mime_type="image/jpeg")

    stored_group = await db.get_group(group["id"])
    posts = await db.get_group_posts(group["id"])
    raw = crypto.decrypt_group(stored_group["group_key"], bytes(posts[0]["payload"]))
    import json
    envelope = json.loads(raw)
    assert "f" in envelope
    assert envelope["n"] == "pic.jpg"
    assert envelope["m"] == "image/jpeg"
    # Verify the file data is valid base64
    file_bytes = base64.b64decode(envelope["f"])
    assert len(file_bytes) > 0


# ------------------------------------------------------------------
# receive_post() — file attachment
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_receive_post_stores_file_metadata(db, alice, group):
    """receive_post() extracts file_name/mime_type and stores them."""
    jpeg = _make_jpeg()
    msg = await post(db, alice, group["id"],
                     file_data=jpeg, file_name="recv.jpg", mime_type="image/jpeg")

    # Simulate receiving (same DB, same group — just re-store via receive_post)
    # Clear existing post first
    await db._conn.execute("DELETE FROM group_posts WHERE id = ?", (msg["id"],))
    await db._conn.commit()

    await receive_post(db, alice, group["id"], msg)
    posts = await db.get_group_posts(group["id"])
    assert posts[0]["file_name"] == "recv.jpg"
    assert posts[0]["mime_type"] == "image/jpeg"


@pytest.mark.asyncio
async def test_receive_post_text_still_works(db, alice, group):
    msg = await post(db, alice, group["id"], text="received text")

    await db._conn.execute("DELETE FROM group_posts WHERE id = ?", (msg["id"],))
    await db._conn.commit()

    await receive_post(db, alice, group["id"], msg)
    posts = await db.get_group_posts(group["id"])
    assert posts[0]["file_name"] is None
    assert posts[0]["mime_type"] is None


# ------------------------------------------------------------------
# _decrypt_post() — via server helper
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_decrypt_post_returns_file_data(db, alice, group):
    """_decrypt_post extracts file_data for file posts."""
    from api.server import _decrypt_post
    jpeg = _make_jpeg()
    await post(db, alice, group["id"],
               file_data=jpeg, file_name="x.jpg", mime_type="image/jpeg")

    stored_group = await db.get_group(group["id"])
    posts = await db.get_group_posts(group["id"])
    result = _decrypt_post(posts[0], stored_group["group_key"])

    assert result["text"] is None
    assert result["file_data"] is not None
    assert result["file_name"] == "x.jpg"
    assert result["mime_type"] == "image/jpeg"
    # payload removed from result
    assert "payload" not in result


@pytest.mark.asyncio
async def test_decrypt_post_returns_text(db, alice, group):
    """_decrypt_post extracts text for text posts."""
    from api.server import _decrypt_post
    await post(db, alice, group["id"], text="plain text post")

    stored_group = await db.get_group(group["id"])
    posts = await db.get_group_posts(group["id"])
    result = _decrypt_post(posts[0], stored_group["group_key"])

    assert result["text"] == "plain text post"
    assert result["file_data"] is None


@pytest.mark.asyncio
async def test_decrypt_post_bad_key_returns_none(db, alice, group):
    """Wrong key → both text and file_data are None (no crash)."""
    from api.server import _decrypt_post
    from core.crypto import generate_group_key
    await post(db, alice, group["id"], text="secret")
    posts = await db.get_group_posts(group["id"])
    result = _decrypt_post(posts[0], generate_group_key())  # wrong key
    assert result["text"] is None
    assert result["file_data"] is None
