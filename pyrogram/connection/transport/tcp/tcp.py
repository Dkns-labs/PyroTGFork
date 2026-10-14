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

import logging
from typing import Optional, Tuple

from .tcp import TCP

log = logging.getLogger(__name__)


class TCPAbridged(TCP):
    def __init__(self, ipv6: bool, proxy: dict):
        super().__init__(ipv6, proxy)
        self._is_first_packet = True

    async def connect(self, address: Tuple[str, int]):
        await super().connect(address)
        self._is_first_packet = True

    async def send(self, data: bytes, *args):
        length = len(data) >> 2

        if length < 127:
            header = bytes((length,))
        else:
            header = b"\x7f" + length.to_bytes(3, "little")

        if self._is_first_packet:
            self._is_first_packet = False
            await super().send(b"\xef" + header + data)
        else:
            await super().send(header + data)

    async def recv(self, length: int = 0) -> Optional[bytes]:
        length_byte = await super().recv(1)

        if length_byte is None:
            return None

        length_val = length_byte[0]

        if length_val == 127:
            ext_bytes = await super().recv(3)

            if ext_bytes is None:
                return None

            length_val = int.from_bytes(ext_bytes, "little")

        return await super().recv(length_val << 2)
