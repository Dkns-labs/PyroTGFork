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

"""The OpenSSL (`cryptography`) tier must be bit-exact with the pure-Python reference."""

import importlib.util
import os
import random

import pytest

import pyrogram.crypto.aes as _aes_module


def _load(backend: str):
    old = os.environ.get("PYROGRAM_CRYPTO")
    os.environ["PYROGRAM_CRYPTO"] = backend

    try:
        spec = importlib.util.spec_from_file_location(f"_aes_{backend}", _aes_module.__file__)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if old is None:
            os.environ.pop("PYROGRAM_CRYPTO", None)
        else:
            os.environ["PYROGRAM_CRYPTO"] = old


reference = _load("pyaes")
ossl = _load("cryptography")

pytestmark = pytest.mark.skipif(ossl._openssl is None, reason="cryptography is not installed")


def test_forced_backends_are_selected():
    assert not reference.NATIVE and reference._openssl is None
    assert not ossl.NATIVE and ossl._openssl is not None


@pytest.mark.parametrize("size", [16, 32, 48, 4096, 20 * 1024])
def test_ige_matches_reference(size):
    rng = random.Random(size)
    data, key, iv = (rng.randbytes(n) for n in (size, 32, 32))

    encrypted = ossl.ige256_encrypt(data, key, iv)
    assert encrypted == reference.ige256_encrypt(data, key, iv)
    assert ossl.ige256_decrypt(encrypted, key, iv) == data
    assert ossl.ige256_decrypt(data, key, iv) == reference.ige256_decrypt(data, key, iv)


def test_ige_accepts_bytearray_input():
    rng = random.Random(1)
    data, key, iv = rng.randbytes(64), rng.randbytes(32), rng.randbytes(32)

    assert ossl.ige256_encrypt(bytearray(data), key, bytearray(iv)) == reference.ige256_encrypt(data, key, iv)


def test_ige_rejects_unaligned_data():
    with pytest.raises(ValueError):
        ossl.ige256_encrypt(b"x" * 17, b"k" * 32, b"i" * 32)


@pytest.mark.parametrize("start_state", [0, 1, 7, 15])
def test_ctr_streaming_matches_reference_in_any_slicing(start_state):
    rng = random.Random(start_state)
    key = rng.randbytes(32)
    data = rng.randbytes(50_000)

    iv_a, iv_b = bytearray(rng.randbytes(16)), None
    iv_b = bytearray(iv_a)
    state_a, state_b = bytearray([start_state]), bytearray([start_state])

    out_a, out_b = bytearray(), bytearray()
    pos = 0

    while pos < len(data):
        n = rng.choice([1, 2, 3, 15, 16, 17, 31, 64, 1000, 4096])
        piece = data[pos:pos + n]
        pos += n

        out_a += ossl.ctr256_encrypt(piece, key, iv_a, state_a)
        out_b += reference.ctr256_encrypt(piece, key, iv_b, state_b)

        # the in-place counter / offset must evolve exactly like the reference's
        assert iv_a == iv_b and state_a == state_b

    assert out_a == out_b


def test_ctr_counter_wraps_like_the_reference():
    key = bytes(range(32))
    iv_a = bytearray(b"\xff" * 16)
    iv_b = bytearray(iv_a)
    state_a, state_b = bytearray(1), bytearray(1)
    data = bytes(100)

    assert ossl.ctr256_encrypt(data, key, iv_a, state_a) == reference.ctr256_encrypt(data, key, iv_b, state_b)
    assert iv_a == iv_b and state_a == state_b


def test_ctr_default_state_is_fresh():
    key, iv = bytes(range(32)), bytes(range(16))

    assert ossl.ctr256_decrypt(b"hello world", key, bytearray(iv)) == reference.ctr256_decrypt(
        b"hello world", key, bytearray(iv)
    )
