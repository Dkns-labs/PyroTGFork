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

import importlib
import logging
import os
import struct

log = logging.getLogger(__name__)

# Backend priority (first one that imports AND exposes the 4 required
# functions wins):  HyperCrypto -> WarpCrypto -> TgCrypto -> cryptography (OpenSSL) -> pure-Python pyaes
# (same order as the rest of the repo, see crypto/mtproto.py)
#
# Force a specific backend with the env var PYROGRAM_CRYPTO, e.g.
#   PYROGRAM_CRYPTO=tgcrypto   (hypercrypto | warpcrypto | tgcrypto | cryptography | pyaes)
_BACKENDS = (
    ("hypercrypto", "HyperCrypto"),
    ("warpcrypto", "WarpCrypto"),
    ("tgcrypto", "TgCrypto"),
)

_REQUIRED = ("ige256_encrypt", "ige256_decrypt", "ctr256_encrypt", "ctr256_decrypt")


def xor(a: bytes, b: bytes) -> bytes:
    return int.to_bytes(
        int.from_bytes(a, "big") ^ int.from_bytes(b, "big"),
        len(a),
        "big",
    )


def _load_native():
    forced = os.environ.get("PYROGRAM_CRYPTO", "").strip().lower()

    if forced == "pyaes":
        return None, None

    for module_name, label in _BACKENDS:
        if forced and forced != module_name:
            continue

        try:
            module = importlib.import_module(module_name)
        except Exception:  # ImportError or a broken native extension
            continue

        if all(callable(getattr(module, name, None)) for name in _REQUIRED):
            return module, label

        log.warning("%s is installed but does not expose the expected API, skipping", label)

    return None, None


_native, _label = _load_native()


def _load_openssl():
    # Middle tier, used only when none of the Telegram-specific native backends is installed: the
    # `cryptography` package (OpenSSL). It is on most machines already, needs no compiler, and is
    # 30x+ faster than pure-Python pyaes for IGE and thousands of times faster for CTR.
    # Skipped when a different backend (or pyaes) was forced via PYROGRAM_CRYPTO.
    forced = os.environ.get("PYROGRAM_CRYPTO", "").strip().lower()

    if forced and forced != "cryptography":
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:  # ImportError or a broken OpenSSL binding
        return None

    return Cipher, algorithms.AES, modes.ECB, modes.CTR


_openssl = _load_openssl() if _native is None else None

# True when a compiled backend (hypercrypto / warpcrypto / tgcrypto) is in use
NATIVE = _native is not None

# Frames up to this many bytes are encrypted/decrypted right on the event loop instead of being
# handed to crypto_executor. A native cipher needs a few microseconds for them, while the thread
# hand-off costs ~100 us plus GIL contention, so for acks, pings and ordinary RPCs the hop is the
# expensive part. Bulk data (file parts, 1 MB chunks) still goes to the executor. Never used with the
# pure-Python fallback, where even a small frame would stall the loop. 0 disables.
# PYROGRAM_CRYPTO_INLINE=<bytes>
INLINE_LIMIT = max(0, int(os.environ.get("PYROGRAM_CRYPTO_INLINE", 4096)))


def is_inline(size: int) -> bool:
    return NATIVE and INLINE_LIMIT > 0 and size <= INLINE_LIMIT

if _native is not None:
    log.info("Using %s", _label)

    # The native backends are strict about argument types:
    #   data, key  -> immutable `bytes` (a `bytearray` raises
    #                 "TypeError: argument 'data': 'bytearray' object cannot be
    #                 converted to 'PyBytes'")
    #   iv, state  -> mutable `bytearray` for CTR (updated in place)
    # Pyrogram passes a `bytearray` as `data` in places (e.g. the obfuscated
    # transport nonce), so normalise the inputs here.

    _n_ige_enc = _native.ige256_encrypt
    _n_ige_dec = _native.ige256_decrypt
    _n_ctr_enc = _native.ctr256_encrypt
    _n_ctr_dec = _native.ctr256_decrypt

    def _b(value) -> bytes:
        return value if isinstance(value, bytes) else bytes(value)

    def _ba(value) -> bytearray:
        return value if isinstance(value, bytearray) else bytearray(value)

    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _n_ige_enc(_b(data), _b(key), _b(iv))

    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _n_ige_dec(_b(data), _b(key), _b(iv))

    def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return _n_ctr_enc(
            _b(data), _b(key), _ba(iv),
            bytearray(1) if state is None else _ba(state),
        )

    def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return _n_ctr_dec(
            _b(data), _b(key), _ba(iv),
            bytearray(1) if state is None else _ba(state),
        )

elif _openssl is not None:
    log.info("Using cryptography (OpenSSL); install tgcrypto / hypercrypto for the best speed")

    _Cipher, _AES, _ECB, _CTR = _openssl
    _Q = struct.Struct(">QQ")
    _MASK64 = 0xFFFFFFFFFFFFFFFF
    _MASK128 = (1 << 128) - 1

    def _ige(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        size = len(data)

        if size % 16:
            raise ValueError("IGE data length must be a multiple of 16")

        cipher = _Cipher(_AES(bytes(key)), _ECB())
        update = (cipher.encryptor() if encrypt else cipher.decryptor()).update

        unpack_from = _Q.unpack_from
        pack_into = _Q.pack_into
        from_bytes = int.from_bytes
        to_bytes = int.to_bytes

        iv = bytes(iv)
        prev_out = from_bytes(iv[:16], "big")  # iv_1: previous ciphertext (encrypt) / plaintext (decrypt)
        prev_in = from_bytes(iv[16:32], "big")  # iv_2: previous plaintext (encrypt) / ciphertext (decrypt)

        data = bytes(data)
        out = bytearray(size)

        if encrypt:
            for offset in range(0, size, 16):
                hi, lo = unpack_from(data, offset)
                block = (hi << 64) | lo
                result = from_bytes(update(to_bytes(block ^ prev_out, 16, "big")), "big") ^ prev_in
                prev_out = result
                prev_in = block
                pack_into(out, offset, result >> 64, result & _MASK64)
        else:
            for offset in range(0, size, 16):
                hi, lo = unpack_from(data, offset)
                block = (hi << 64) | lo
                result = from_bytes(update(to_bytes(block ^ prev_in, 16, "big")), "big") ^ prev_out
                prev_out = block
                prev_in = result
                pack_into(out, offset, result >> 64, result & _MASK64)

        return bytes(out)

    def _ctr(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
        # Same contract as the native backends: `iv` is the counter block and `state[0]` the number
        # of keystream bytes already used from it; both are advanced in place so a stream can be
        # processed in arbitrary slices.
        used = state[0]
        stream = _Cipher(_AES(bytes(key)), _CTR(bytes(iv))).encryptor()

        if used:
            stream.update(bytes(used))  # skip the part of the keystream block already consumed

        out = stream.update(bytes(data))

        total = used + len(data)
        counter = (int.from_bytes(iv, "big") + total // 16) & _MASK128
        iv[:] = counter.to_bytes(16, "big")
        state[0] = total % 16

        return out

    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _ige(data, key, iv, True)

    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return _ige(data, key, iv, False)

    def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return _ctr(data, key, iv, bytearray(1) if state is None else state)

    def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return _ctr(data, key, iv, bytearray(1) if state is None else state)

else:
    import pyaes

    log.warning(
        "No fast crypto backend found (hypercrypto / warpcrypto / tgcrypto)! "
        "Pyrogram will work the same, but at a much slower speed. "
        "More info: https://telegramplayground.github.io/pyrogram/topics/speedups"
    )

    def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return ige(data, key, iv, True)

    def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return ige(data, key, iv, False)

    def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return ctr(data, key, iv, bytearray(1) if state is None else state)

    def ctr256_decrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray = None) -> bytes:
        return ctr(data, key, iv, bytearray(1) if state is None else state)

    def ige(data: bytes, key: bytes, iv: bytes, encrypt: bool) -> bytes:
        cipher = pyaes.AES(key)

        iv_1 = iv[:16]
        iv_2 = iv[16:]

        data = [data[i: i + 16] for i in range(0, len(data), 16)]

        if encrypt:
            for i, chunk in enumerate(data):
                iv_1 = data[i] = xor(cipher.encrypt(xor(chunk, iv_1)), iv_2)
                iv_2 = chunk
        else:
            for i, chunk in enumerate(data):
                iv_2 = data[i] = xor(cipher.decrypt(xor(chunk, iv_2)), iv_1)
                iv_1 = chunk

        return b"".join(data)

    def ctr(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
        cipher = pyaes.AES(key)

        out = bytearray(data)
        chunk = cipher.encrypt(iv)

        for i in range(0, len(data), 16):
            for j in range(0, min(len(data) - i, 16)):
                out[i + j] ^= chunk[state[0]]

                state[0] += 1

                if state[0] >= 16:
                    state[0] = 0

                if state[0] == 0:
                    for k in range(15, -1, -1):
                        try:
                            iv[k] += 1
                            break
                        except ValueError:
                            iv[k] = 0

                    chunk = cipher.encrypt(iv)

        return bytes(out)
