from pyrogram.raw.core import Message, MsgContainer, TLObject
from pyrogram.raw.functions import Ping
from pyrogram.raw.types import MsgsAck, HttpWait
from pyrogram.raw.core.fast_write import serialize
from .msg_id import MsgId
from .seq_no import SeqNo

not_content_related = (Ping, HttpWait, MsgsAck, MsgContainer)


class MsgFactory:
    def __init__(self):
        self.seq_no = SeqNo()

    def __call__(self, body: TLObject) -> Message:
        # `len(body)` used to serialize the whole body, and Message.write() then did it again
        raw_body = serialize(body)

        return Message(
            body,
            MsgId(),
            self.seq_no(not isinstance(body, not_content_related)),
            len(raw_body),
            raw_body
        )
