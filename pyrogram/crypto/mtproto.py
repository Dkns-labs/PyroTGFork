import logging
from hashlib import sha256
from io import BytesIO
from os import urandom

from pyrogram.errors import SecurityCheckMismatch
from pyrogram.raw.core import Message, Long
from . import aes

log = logging.getLogger(__name__)


def _kdf_py(auth_key: bytes, msg_key: bytes, outgoing: bool) -> tuple:
    # https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
    x = 0 if outgoing else 8

    sha256_a = sha256(msg_key + auth_key[x: x + 36]).digest()
    sha256_b = sha256(auth_key[x + 40:x + 76] + msg_key).digest()  # 76 = 40 + 36

    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]

    return aes_key, aes_iv


def _pick_kdf_backend():
    # Priority: HyperCrypto > WarpCrypto > pure-Python (hashlib)
    # Backend ka output pehle pure-Python wale se match karke dekhte hain,
    # mismatch ho to us backend ko skip kar dete hain (safety check).
    test_auth_key = bytes(range(256))
    test_msg_key = bytes(range(16))

    for name in ("hypercrypto", "warpcrypto"):
        try:
            backend = __import__(name)
        except ImportError:
            continue

        try:
            for outgoing in (True, False):
                got = backend.kdf(test_auth_key, test_msg_key, outgoing)
                got = (bytes(got[0]), bytes(got[1]))

                if got != _kdf_py(test_auth_key, test_msg_key, outgoing):
                    raise ValueError("kdf output mismatch")
        except Exception as e:
            log.warning("%s kdf skipped: %s", name, e)
            continue

        log.info("Using %s for kdf", name)
        return backend.kdf

    return None


_kdf_backend = _pick_kdf_backend()


if _kdf_backend is not None:
    def kdf(auth_key: bytes, msg_key: bytes, outgoing: bool) -> tuple:
        return _kdf_backend(auth_key, msg_key, outgoing)
else:
    kdf = _kdf_py


def pack(message: Message, salt: int, session_id: bytes, auth_key: bytes, auth_key_id: bytes) -> bytes:
    body = message.write()

    # The padding length only depends on the size, so it is known before the plaintext exists and
    # the plaintext is built with ONE copy of the (up to 1 MB) message instead of two.
    padding = urandom(-(len(body) + 16 + 12) % 16 + 12)
    data = b"".join((Long(salt), session_id, body, padding))

    # 88 = 88 + 0 (outgoing message)
    # Hashed incrementally so the (up to 1 MB) message is not copied into one more temporary buffer.
    digest = sha256(auth_key[88: 88 + 32])
    digest.update(data)
    msg_key = digest.digest()[8:24]
    aes_key, aes_iv = kdf(auth_key, msg_key, True)

    return b"".join((auth_key_id, msg_key, aes.ige256_encrypt(data, aes_key, aes_iv)))


def unpack(
    b: BytesIO,
    session_id: bytes,
    auth_key: bytes,
    auth_key_id: bytes
) -> Message:
    SecurityCheckMismatch.check(b.read(8) == auth_key_id, "b.read(8) == auth_key_id")

    msg_key = b.read(16)
    aes_key, aes_iv = kdf(auth_key, msg_key, False)
    plain = aes.ige256_decrypt(b.read(), aes_key, aes_iv)
    data = BytesIO(plain)
    data.read(8)  # Salt

    # https://core.telegram.org/mtproto/security_guidelines#checking-session-id
    SecurityCheckMismatch.check(data.read(8) == session_id, "data.read(8) == session_id")

    try:
        message = Message.read(data)
    except KeyError as e:
        if e.args[0] == 0:
            raise ConnectionError(f"Received empty data. Check your internet connection.")

        left = data.read().hex()

        left = [left[i:i + 64] for i in range(0, len(left), 64)]
        left = [[left[i:i + 8] for i in range(0, len(left), 8)] for left in left]
        left = "\n".join(" ".join(x for x in left) for left in left)

        raise ValueError(f"The server sent an unknown constructor: {hex(e.args[0])}\n{left}")

    # https://core.telegram.org/mtproto/security_guidelines#checking-sha256-hash-value-of-msg-key
    # 96 = 88 + 8 (incoming message)
    # Hashed incrementally: `auth_key[96:128] + plain` would copy the whole (up to 1 MB) message.
    digest = sha256(auth_key[96:96 + 32])
    digest.update(plain)

    SecurityCheckMismatch.check(
        msg_key == digest.digest()[8:24],
        "msg_key == sha256(auth_key[96:96 + 32] + data.getvalue()).digest()[8:24]"
    )

    # https://core.telegram.org/mtproto/security_guidelines#checking-message-length
    # Skip salt (8) + session_id (8) + msg_id (8) + seq_no (4) + length (4) to get to the payload.
    # A memoryview slices exactly like bytes does, without copying the payload.
    payload = memoryview(plain)[32:]
    padding = payload[message.length:]
    SecurityCheckMismatch.check(12 <= len(padding) <= 1024, "12 <= len(padding) <= 1024")
    SecurityCheckMismatch.check(len(payload) % 4 == 0, "len(payload) % 4 == 0")

    # https://core.telegram.org/mtproto/security_guidelines#checking-msg-id
    SecurityCheckMismatch.check(message.msg_id % 2 != 0, "message.msg_id % 2 != 0")

    return message
