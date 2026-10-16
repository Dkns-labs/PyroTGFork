#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

"""mtproto.pack / unpack: byte-exact against the textbook formula, and the security checks hold."""

import os
import random
from hashlib import sha256
from io import BytesIO

import pytest

from pyrogram import raw
from pyrogram.crypto import aes, mtproto
from pyrogram.errors import SecurityCheckMismatch
from pyrogram.raw.core import Long, Message

RNG = random.Random(1234)
AUTH_KEY = RNG.randbytes(256)
AUTH_KEY_ID = RNG.randbytes(8)
SESSION_ID = RNG.randbytes(8)


def file_message(size: int, msg_id: int = 1234567890123456789) -> Message:
    body = raw.types.upload.File(type=raw.types.storage.FileUnknown(), mtime=0, bytes=RNG.randbytes(size))

    return Message(body, msg_id, 1, len(body.write()))


def server_pack(message: Message, padding: bytes = None, salt: int = 0) -> bytes:
    """What Telegram sends (key offsets for incoming traffic), written straight from the spec."""
    data = Long(salt) + SESSION_ID + message.write()
    padding = os.urandom(-(len(data) + 12) % 16 + 12) if padding is None else padding

    msg_key = sha256(AUTH_KEY[96:128] + data + padding).digest()[8:24]
    aes_key, aes_iv = mtproto._kdf_py(AUTH_KEY, msg_key, False)

    return AUTH_KEY_ID + msg_key + aes.ige256_encrypt(data + padding, aes_key, aes_iv)


@pytest.mark.parametrize("size", [0, 1, 100, 4096, 512 * 1024, 1024 * 1024])
def test_unpack_roundtrip(size):
    message = file_message(size)

    out = mtproto.unpack(BytesIO(server_pack(message)), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)

    assert out.body.bytes == message.body.bytes
    assert out.msg_id == message.msg_id


@pytest.mark.parametrize("size", [0, 100, 4096, 300 * 1024])
def test_pack_matches_the_textbook_formula(size, monkeypatch):
    message = file_message(size)
    fixed = bytes(range(256)) * 8

    monkeypatch.setattr(mtproto, "urandom", lambda n: fixed[:n])

    salt = 0x1122334455667788
    data = Long(salt) + SESSION_ID + message.write()
    padding = fixed[:-(len(data) + 12) % 16 + 12]

    msg_key = sha256(AUTH_KEY[88:120] + data + padding).digest()[8:24]
    aes_key, aes_iv = mtproto._kdf_py(AUTH_KEY, msg_key, True)
    expected = AUTH_KEY_ID + msg_key + aes.ige256_encrypt(data + padding, aes_key, aes_iv)

    assert mtproto.pack(message, salt, SESSION_ID, AUTH_KEY, AUTH_KEY_ID) == expected


def test_unpack_rejects_a_flipped_ciphertext_byte():
    packet = bytearray(server_pack(file_message(2048)))
    packet[-40] ^= 0x01

    with pytest.raises((SecurityCheckMismatch, ValueError, KeyError)):
        mtproto.unpack(BytesIO(bytes(packet)), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)


def test_unpack_rejects_a_forged_msg_key():
    packet = bytearray(server_pack(file_message(2048)))
    packet[8] ^= 0x01  # msg_key starts right after the 8-byte auth_key_id

    with pytest.raises((SecurityCheckMismatch, ValueError, KeyError)):
        mtproto.unpack(BytesIO(bytes(packet)), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)


def test_unpack_rejects_wrong_auth_key_id():
    with pytest.raises(SecurityCheckMismatch):
        mtproto.unpack(BytesIO(server_pack(file_message(64))), SESSION_ID, AUTH_KEY, b"\x00" * 8)


def test_unpack_rejects_wrong_session_id():
    with pytest.raises(SecurityCheckMismatch):
        mtproto.unpack(BytesIO(server_pack(file_message(64))), b"\x00" * 8, AUTH_KEY, AUTH_KEY_ID)


def test_unpack_rejects_even_msg_id():
    with pytest.raises(SecurityCheckMismatch):
        mtproto.unpack(BytesIO(server_pack(file_message(64, msg_id=1234567890123456788))), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)


def test_unpack_rejects_padding_shorter_than_12_bytes():
    # Smallest padding that still aligns the data to 16 bytes is 0..15; pick a message for which
    # it is below the required minimum of 12.
    for size in range(0, 64, 4):
        message = file_message(size)
        data_len = len(Long(0) + SESSION_ID + message.write())
        short = os.urandom(-data_len % 16)

        if len(short) < 12:
            break
    else:
        pytest.fail("no message size gives a padding below 12 bytes")

    with pytest.raises(SecurityCheckMismatch):
        mtproto.unpack(BytesIO(server_pack(message, padding=short)), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)


def test_unpack_rejects_padding_longer_than_1024_bytes():
    message = file_message(64)
    data_len = len(Long(0) + SESSION_ID + message.write())
    long_padding = os.urandom(-(data_len + 1100) % 16 + 1100)

    with pytest.raises(SecurityCheckMismatch):
        mtproto.unpack(BytesIO(server_pack(message, padding=long_padding)), SESSION_ID, AUTH_KEY, AUTH_KEY_ID)
