from io import BytesIO
from typing import Any

from ..tl_object import TLObject


class Bytes(bytes, TLObject):
    @classmethod
    def read(cls, data: BytesIO, *args: Any) -> bytes:
        length = int.from_bytes(data.read(1), "little")

        if length <= 253:
            x = data.read(length)
            data.read(-(length + 1) % 4)
        else:
            length = int.from_bytes(data.read(3), "little")
            x = data.read(length)
            data.read(-length % 4)

        return x

    def __new__(cls, value: bytes) -> bytes:  # type: ignore
        length = len(value)

        # b"".join copies `value` once; chained "+" copied a 512 KiB file part twice
        if length <= 253:
            return b"".join((bytes((length,)), value, bytes(-(length + 1) % 4)))
        else:
            return b"".join((b"\xfe", length.to_bytes(3, "little"), value, bytes(-length % 4)))
