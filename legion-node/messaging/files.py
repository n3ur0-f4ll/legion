
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
Sanityzacja i walidacja plików przed wysyłką i po odbiorze.

Obrazy są re-enkodowane przez Pillow — usuwa WSZYSTKIE metadane:
EXIF, GPS, ICC profile, XMP, komentarze, miniatury, dane skanera.

Re-enkodowanie działa na OBU końcach: nadawca sanityzuje przed wysłaniem,
odbiorca sanityzuje ponownie po odebraniu i odszyfrowaniu.
Obrona warstwowa — nawet jeśli nadawca nie usunął metadanych, odbiorca to zrobi.
"""

from __future__ import annotations

import asyncio
import io
from typing import Final

from PIL import Image, UnidentifiedImageError

MAX_FILE_SIZE: Final = 5 * 1024 * 1024  # 5 MB

# Dozwolone typy MIME i ich sygnatury magic bytes
_IMAGE_SIGNATURES: Final[dict[str, bytes]] = {
    "image/jpeg": b"\xff\xd8\xff",
    "image/png":  b"\x89PNG\r\n\x1a\n",
    "image/webp": b"RIFF",
}

_PILLOW_FORMAT: Final[dict[str, str]] = {
    "image/jpeg": "JPEG",
    "image/png":  "PNG",
    "image/webp": "WEBP",
}

# SVG explicite zablokowane — może zawierać JS
_BLOCKED_MIME_TYPES: Final = frozenset({"image/svg+xml", "text/html", "application/xhtml+xml"})


class FileError(Exception):
    """Raised when a file fails validation or sanitization."""


def prepare_outgoing(data: bytes, file_name: str, mime_type: str) -> bytes:
    """Validate and sanitize a file before encryption and sending.

    Images: re-encoded through Pillow — all metadata stripped.
    Other files: size and name validation only.

    Returns sanitized bytes. Raises FileError on any problem.
    Must be called inside run_in_executor — PIL is CPU-bound.
    """
    _validate_size(data)
    _validate_file_name(file_name)

    if mime_type in _BLOCKED_MIME_TYPES:
        raise FileError(f"File type not allowed: {mime_type!r}")

    if mime_type in _IMAGE_SIGNATURES:
        return _sanitize_image(data, mime_type)

    # All other types: pass through (size + name already validated)
    return data


def sanitize_incoming(data: bytes, mime_type: str) -> bytes:
    """Sanitize a received file — defense-in-depth on the receiver side.

    Must be called inside run_in_executor — PIL is CPU-bound.
    """
    _validate_size(data)

    if mime_type in _IMAGE_SIGNATURES:
        return _sanitize_image(data, mime_type)

    return data


async def prepare_outgoing_async(data: bytes, file_name: str, mime_type: str) -> bytes:
    """Async wrapper — runs PIL in executor to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, prepare_outgoing, data, file_name, mime_type)


async def sanitize_incoming_async(data: bytes, mime_type: str) -> bytes:
    """Async wrapper — runs PIL in executor to avoid blocking the event loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, sanitize_incoming, data, mime_type)


def is_image(mime_type: str) -> bool:
    return mime_type in _IMAGE_SIGNATURES


# ------------------------------------------------------------------
# internal
# ------------------------------------------------------------------

def _sanitize_image(data: bytes, mime_type: str) -> bytes:
    """Re-encode image through Pillow — strips ALL metadata."""
    sig = _IMAGE_SIGNATURES[mime_type]
    # For WebP: magic is RIFF????WEBP — check first 4 bytes
    check = data[:4] if mime_type == "image/webp" else data[:len(sig)]
    if check != (sig[:4] if mime_type == "image/webp" else sig):
        raise FileError(
            f"File magic bytes don't match declared MIME type {mime_type!r}"
        )

    try:
        img = Image.open(io.BytesIO(data))
        img.load()  # full decode — validates integrity, catches truncated images

        # JPEG requires RGB or L mode
        if mime_type == "image/jpeg" and img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        out = io.BytesIO()
        fmt = _PILLOW_FORMAT[mime_type]
        kwargs: dict = {"format": fmt}
        if fmt == "JPEG":
            kwargs["quality"] = 92
            kwargs["optimize"] = True
        # No 'exif', no 'icc_profile', no extra info — clean encode
        img.save(out, **kwargs)
        return out.getvalue()

    except (UnidentifiedImageError, OSError) as exc:
        raise FileError(f"Invalid or corrupt image: {exc}") from exc


def _validate_size(data: bytes) -> None:
    if len(data) > MAX_FILE_SIZE:
        mb = len(data) / 1024 / 1024
        raise FileError(f"File too large: {mb:.1f} MB (max 5 MB)")


def _validate_file_name(name: str) -> None:
    forbidden = set('/\\:*?"<>|\x00')
    if not name or any(c in name for c in forbidden):
        raise FileError(f"Invalid file name: {name!r}")
    if name.startswith("."):
        raise FileError(f"Hidden file names not allowed: {name!r}")
