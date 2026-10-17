from io import BytesIO
from typing import Any

from .primitives.int import Int, Long
from .tl_object import TLObject


class Message(TLObject):
    ID = 0x5BB8E511  # hex(crc32(b"message msg_id:long seqno:int bytes:int body:Object = Message"))

    __slots__ = ["msg_id", "seq_no", "length", "body", "_raw_body"]

    QUALNAME = "Message"

    def __init__(self, body: TLObject, msg_id: int, seq_no: int, length: int, raw_body: bytes = None):
        self.msg_id = msg_id
        self.seq_no = seq_no
        self.length = length
        self.body = body
        # `body` already serialized. MsgFactory has to serialize it once to learn `length`; keeping
        # the bytes means a 512 KiB file part is not serialized (and copied) a second time in write()
        self._raw_body = raw_body

    @staticmethod
    def read(data: BytesIO, *args: Any) -> "Message":
        msg_id = Long.read(data)
        seq_no = Int.read(data)
        length = Int.read(data)
        body = data.read(length)

        return Message(TLObject.read(BytesIO(body)), msg_id, seq_no, length)

    def write(self, *args: Any) -> bytes:
        body = self._raw_body if self._raw_body is not None else self.body.write()

        # one join = one copy of the (up to 1 MiB) body, instead of BytesIO.write() + getvalue()
        return b"".join((Long(self.msg_id), Int(self.seq_no), Int(self.length), body))
