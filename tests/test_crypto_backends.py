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


# ---------------------------------------------------------------------------------------------
# libcrypto (OpenSSL AES_ige_encrypt through ctypes) IGE tier
# ---------------------------------------------------------------------------------------------

libcrypto = _load("libcrypto")

needs_libcrypto = pytest.mark.skipif(
    libcrypto._libcrypto_ige is None, reason="system libcrypto with legacy AES_* functions not available"
)


@needs_libcrypto
def test_libcrypto_backend_is_selected_when_forced():
    assert libcrypto.ige256_encrypt is libcrypto._libcrypto_ige[0]
    assert libcrypto.ige256_decrypt is libcrypto._libcrypto_ige[1]


def test_libcrypto_is_skipped_when_another_backend_is_forced():
    assert reference._libcrypto_ige is None
    assert ossl._libcrypto_ige is None


@needs_libcrypto
@pytest.mark.parametrize("size", [16, 32, 48, 4096, 20 * 1024, 1024 * 1024])
def test_libcrypto_ige_matches_reference(size):
    rng = random.Random(size)
    data, key, iv = (rng.randbytes(n) for n in (size, 32, 32))

    encrypted = libcrypto.ige256_encrypt(data, key, iv)
    assert encrypted == ossl.ige256_encrypt(data, key, iv)
    assert libcrypto.ige256_decrypt(encrypted, key, iv) == data
    assert libcrypto.ige256_decrypt(data, key, iv) == ossl.ige256_decrypt(data, key, iv)


@needs_libcrypto
def test_libcrypto_ige_matches_pure_python_reference():
    rng = random.Random(7)
    data, key, iv = rng.randbytes(256), rng.randbytes(32), rng.randbytes(32)

    assert libcrypto.ige256_encrypt(data, key, iv) == reference.ige256_encrypt(data, key, iv)
    assert libcrypto.ige256_decrypt(data, key, iv) == reference.ige256_decrypt(data, key, iv)


@needs_libcrypto
def test_libcrypto_ige_never_modifies_its_inputs():
    # OpenSSL updates the iv in place; the caller's bytes objects must come out untouched
    rng = random.Random(3)
    data, key, iv = rng.randbytes(1024), rng.randbytes(32), rng.randbytes(32)
    copies = (bytes(data), bytes(key), bytes(iv))

    first = libcrypto.ige256_encrypt(data, key, iv)
    libcrypto.ige256_decrypt(data, key, iv)

    assert (data, key, iv) == copies
    assert libcrypto.ige256_encrypt(data, key, iv) == first  # same call, same answer


@needs_libcrypto
def test_libcrypto_ige_accepts_bytearray_input():
    rng = random.Random(4)
    data, key, iv = rng.randbytes(64), rng.randbytes(32), rng.randbytes(32)

    assert libcrypto.ige256_encrypt(bytearray(data), bytearray(key), bytearray(iv)) == ossl.ige256_encrypt(data, key, iv)


@needs_libcrypto
def test_libcrypto_ige_rejects_bad_sizes():
    with pytest.raises(ValueError):
        libcrypto.ige256_encrypt(b"x" * 17, b"k" * 32, b"i" * 32)

    with pytest.raises(ValueError):
        libcrypto.ige256_encrypt(b"x" * 16, b"k" * 16, b"i" * 32)

    with pytest.raises(ValueError):
        libcrypto.ige256_decrypt(b"x" * 16, b"k" * 32, b"i" * 16)


@needs_libcrypto
def test_libcrypto_ige_is_thread_safe():
    from concurrent.futures import ThreadPoolExecutor

    rng = random.Random(5)
    jobs = [(rng.randbytes(64 * 1024), rng.randbytes(32), rng.randbytes(32)) for _ in range(32)]
    expected = [ossl.ige256_encrypt(*job) for job in jobs]

    with ThreadPoolExecutor(8) as pool:
        got = list(pool.map(lambda job: libcrypto.ige256_encrypt(*job), jobs * 4))

    assert got == expected * 4


def test_libcrypto_falls_back_when_self_test_fails(monkeypatch):
    # a backend that returns wrong bytes must never be used
    monkeypatch.setenv("PYROGRAM_CRYPTO", "libcrypto")
    spec = importlib.util.spec_from_file_location("_aes_badkat", _aes_module.__file__)
    source = open(_aes_module.__file__).read().replace(
        '"42e66e1a756cccf5b27acc47523ad074ee39bf54e3db37bbdf415df6b400fca9"',
        '"00e66e1a756cccf5b27acc47523ad074ee39bf54e3db37bbdf415df6b400fca9"',
    )
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, _aes_module.__file__, "exec"), module.__dict__)

    assert module._libcrypto_ige is None


@needs_libcrypto
def test_libcrypto_inlines_small_ige_frames_but_not_ctr():
    assert libcrypto.is_inline_ige(64) and not libcrypto.is_inline_ige(libcrypto.INLINE_LIMIT + 1)
    assert not libcrypto.is_inline(64)  # CTR may be pure Python, keep it off the event loop
    assert not reference.is_inline_ige(64)


@needs_libcrypto
def test_upload_part_packet_is_identical_with_libcrypto_and_the_openssl_tier(monkeypatch):
    # An upload part (512 KB SaveBigFilePart) goes through mtproto.pack(); the encrypted packet must
    # not depend on which IGE tier produced it.
    from pyrogram import raw
    from pyrogram.crypto import mtproto
    from pyrogram.raw.core import Message

    rng = random.Random(11)
    auth_key, auth_key_id, session_id = rng.randbytes(256), rng.randbytes(8), rng.randbytes(8)
    body = raw.functions.upload.SaveBigFilePart(
        file_id=1, file_part=3, file_total_parts=100, bytes=rng.randbytes(512 * 1024)
    )
    message = Message(body, 0x5000000000000001, 1, len(body.write()))

    monkeypatch.setattr(mtproto, "urandom", lambda n: b"\x07" * n)  # padding is random otherwise

    monkeypatch.setattr(mtproto, "aes", libcrypto)
    fast = mtproto.pack(message, 1, session_id, auth_key, auth_key_id)

    monkeypatch.setattr(mtproto, "aes", ossl)
    slow = mtproto.pack(message, 1, session_id, auth_key, auth_key_id)

    assert fast == slow
