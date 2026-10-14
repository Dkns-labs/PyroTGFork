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

import time


class MsgId:
    """
    High-performance, lock-free monotonic MTProto msg_id generator.
    Replaces floating-point math and datetime overhead with nanosecond integer bit-shifting.
    """
    def __init__(self):
        self.last_id = 0

    def __call__(self) -> int:
        now_ns = time.time_ns()
        sec = now_ns // 1000000000
        
        # Convert nanoseconds fractional part to 30-bit sub-seconds strictly divisible by 4
        subsec = ((now_ns % 1000000000) * 1024 // 15625000) & ~3
        
        msg_id = (sec << 32) + subsec
        
        if msg_id <= self.last_id:
            msg_id = self.last_id + 4
            
        self.last_id = msg_id
        return msg_id
