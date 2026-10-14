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

log = logging.getLogger(__name__)

# Backend priority (first one that imports AND exposes the 4 required
# functions wins):  HyperCrypto -> WarpCrypto -> TgCrypto -> pure-Python pyaes
# (same order as the rest of the repo, see crypto/mtproto.py)
#
# Force a specific backend with the env var PYROGRAM_CRYPTO, e.g.
#   PYROGRAM_CRYPTO=tgcrypto   (hypercrypto | warpcrypto | tgcrypto | pyaes)
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
