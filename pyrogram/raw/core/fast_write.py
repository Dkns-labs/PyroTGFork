"""Serialization of the two upload requests that carry megabytes of payload.

The generated `write()` of every TL type builds a BytesIO, and for a 512 KiB file part that costs
the blob being copied into the `Bytes()` wrapper, into the BytesIO and out of it again. Here the
header is packed on its own and the blob is copied exactly once, by a single join. The output is
byte-for-byte what the generated code produces (tests/test_fast_write.py checks that), and every
other type keeps using its own `write()`.
"""

from struct import Struct

from .tl_object import TLObject

_BIG = Struct("<Iqii")  # constructor id (u32), file_id (i64), file_part (i32), file_total_parts (i32)
_SMALL = Struct("<Iqi")  # constructor id (u32), file_id (i64), file_part (i32)

_SAVE_BIG = None
_SAVE_SMALL = None


def _load():
    global _SAVE_BIG, _SAVE_SMALL

    from pyrogram.raw.functions.upload import SaveBigFilePart, SaveFilePart

    _SAVE_BIG, _SAVE_SMALL = SaveBigFilePart, SaveFilePart


def serialize(obj: TLObject) -> bytes:
    """Same bytes as `obj.write()`, with fewer copies for upload.SaveBigFilePart / SaveFilePart."""
    if _SAVE_BIG is None:
        _load()

    cls = type(obj)

    if cls is _SAVE_BIG:
        blob = obj.bytes

        if isinstance(blob, (bytes, bytearray, memoryview)) and len(blob) > 253:
            n = len(blob)

            return b"".join((
                _BIG.pack(cls.ID, obj.file_id, obj.file_part, obj.file_total_parts),
                b"\xfe", n.to_bytes(3, "little"), blob, bytes(-n % 4),
            ))
    elif cls is _SAVE_SMALL:
        blob = obj.bytes

        if isinstance(blob, (bytes, bytearray, memoryview)) and len(blob) > 253:
            n = len(blob)

            return b"".join((
                _SMALL.pack(cls.ID, obj.file_id, obj.file_part),
                b"\xfe", n.to_bytes(3, "little"), blob, bytes(-n % 4),
            ))

    return obj.write()
