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

import asyncio
import logging
import time
from typing import Optional

from .transport import *
from .transport.tcp.tcp import TCP
from ..session.internals import DataCenter, DCRouter

log = logging.getLogger(__name__)


class Connection:
    MAX_RETRIES = 3
    FALLBACK_TIMEOUT = 5

    MODES = {
        0: TCPFull,
        1: TCPAbridged,
        2: TCPIntermediate,
        3: TCPAbridgedO,
        4: TCPIntermediateO
    }

    def __init__(self, dc_id: int, test_mode: bool, ipv6: bool, proxy: dict, media: bool = False, mode: int = 3):
        self.dc_id = dc_id
        self.test_mode = test_mode
        self.ipv6 = ipv6
        self.proxy = proxy
        self.media = media
        self.address = DataCenter(dc_id, test_mode, ipv6, media)
        self.mode = self.MODES.get(mode, TCPAbridged)

        self.protocol = None  # type: TCP

    async def connect(self):
        for i in range(Connection.MAX_RETRIES):
            # Healthy endpoints first; the router demotes ones that failed recently.
            for n, address in enumerate(
                DCRouter.candidates(self.dc_id, self.test_mode, self.ipv6, self.media)
            ):
                self.protocol = self.mode(self.ipv6, self.proxy)

                # The preferred route gets the full TCP timeout, fallbacks fail faster.
                timeout = TCP.TIMEOUT + 2 if n == 0 else Connection.FALLBACK_TIMEOUT
                started = time.monotonic()

                try:
                    log.info("Connecting...")
                    await asyncio.wait_for(self.protocol.connect(address), timeout)
                except (OSError, asyncio.TimeoutError) as e:
                    log.warning(f"Unable to connect to {address[0]}:{address[1]} due to network issues: {e!r}")
                    DCRouter.record_failure(address)
                    await self.protocol.close()
                    continue

                DCRouter.record_success(address, time.monotonic() - started)
                self.address = address

                log.info("Connected! {} DC{}{} - IPv{} - {} - {}:{}".format(
                    "Test" if self.test_mode else "Production",
                    self.dc_id,
                    " (media)" if self.media else "",
                    "6" if self.ipv6 else "4",
                    self.mode.__name__,
                    address[0],
                    address[1],
                ))
                return

            await asyncio.sleep(1)

        log.warning("Connection failed! Trying again...")
        raise TimeoutError

    async def close(self):
        if self.protocol is not None:
            await self.protocol.close()
        log.info("Disconnected")

    async def send(self, data: bytes):
        try:
            await self.protocol.send(data)
        except Exception as e:
            raise OSError(e)

    async def recv(self) -> Optional[bytes]:
        return await self.protocol.recv()
