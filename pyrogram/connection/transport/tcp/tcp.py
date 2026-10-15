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
import ipaddress
import logging
import os
import socket
from typing import Optional, Tuple

import socks

log = logging.getLogger(__name__)


class TCP:
    TIMEOUT = 10
    # User-space (asyncio) read/write buffer limits only; this does NOT touch the kernel TCP window.
    SOCKET_BUFFER_SIZE = 4 * 1024 * 1024

    # Kernel socket buffer (SO_RCVBUF/SO_SNDBUF). Default 0 = leave it alone so Linux keeps TCP
    # auto-tuning. Forcing a fixed size turns auto-tuning OFF and clamps the window to
    # net.core.rmem_max/wmem_max (often only ~208 KB), which caps each connection at roughly
    # window / RTT -- a few MB/s on a long route such as India <-> Telegram DCs.
    # Opt in only if you know your sysctl limits: PYROGRAM_SOCKET_BUFFER=<bytes>
    KERNEL_SOCKET_BUFFER = int(os.environ.get("PYROGRAM_SOCKET_BUFFER", 0))

    def __init__(self, ipv6: bool, proxy: dict):
        self.socket = None

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

        self.lock = asyncio.Lock()
        self.loop = asyncio.get_event_loop()

        self.ipv6 = ipv6
        self.proxy = proxy

    @staticmethod
    def _tune_socket(sock: socket.socket):
        """Apply low-latency and high-bandwidth socket flags."""
        try:
            # Disable Nagle's algorithm for instant RPC & chunk transmission
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except (OSError, AttributeError):
            pass

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except (OSError, AttributeError):
            pass

        if TCP.KERNEL_SOCKET_BUFFER > 0:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TCP.KERNEL_SOCKET_BUFFER)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TCP.KERNEL_SOCKET_BUFFER)
            except (OSError, AttributeError):
                pass

    async def _connect(self, address: Tuple[str, int]):
        if self.proxy:
            ip, port = address
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sock = socks.socksocket(family)

            sock.set_proxy(
                proxy_type=getattr(socks, self.proxy.get("scheme").upper()),
                addr=self.proxy.get("hostname"),
                port=self.proxy.get("port"),
                username=self.proxy.get("username"),
                password=self.proxy.get("password")
            )
            sock.settimeout(TCP.TIMEOUT)

            await self.loop.run_in_executor(
                None,
                sock.connect,
                address
            )

            sock.setblocking(False)
            self._tune_socket(sock)

            self.reader, self.writer = await asyncio.open_connection(
                sock=sock,
                limit=self.SOCKET_BUFFER_SIZE
            )
        else:
            self.reader, self.writer = await asyncio.open_connection(
                host=address[0],
                port=address[1],
                family=socket.AF_INET6 if self.ipv6 else socket.AF_INET,
                limit=self.SOCKET_BUFFER_SIZE
            )

            sock = self.writer.get_extra_info("socket")
            if sock is not None:
                self._tune_socket(sock)

                # Expand asyncio transport write buffer limits so 512 KB chunks don't pause the protocol
                transport = self.writer.transport
                if hasattr(transport, "set_write_buffer_limits"):
                    transport.set_write_buffer_limits(
                        high=self.SOCKET_BUFFER_SIZE,
                        low=self.SOCKET_BUFFER_SIZE // 4
                    )

    async def connect(self, address: Tuple[str, int]):
        try:
            await asyncio.wait_for(self._connect(address), timeout=TCP.TIMEOUT)
        except asyncio.TimeoutError:
            raise TimeoutError("Connection timed out")

    async def close(self):
        async with self.lock:
            if self.writer is not None:
                try:
                    self.writer.close()
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=1.5)
                except Exception as e:
                    log.debug("Socket close ignored exception: %s", e)
                finally:
                    self.writer = None
                    self.reader = None

    async def send(self, data: bytes):
        async with self.lock:
            if self.writer is None:
                raise ConnectionResetError("Connection is closed")

            try:
                # Write directly on the event loop without thread executor overhead
                self.writer.write(data)
                await self.writer.drain()
            except Exception as e:
                log.info("Send exception: %s %s", type(e).__name__, e)
                raise OSError(e)

    async def recv(self, length: int = 0) -> Optional[bytes]:
        data = bytearray()

        while len(data) < length:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(length - len(data)),
                    timeout=TCP.TIMEOUT
                )
            except (OSError, asyncio.TimeoutError):
                return None
            else:
                if chunk:
                    data.extend(chunk)
                else:
                    return None

        return bytes(data)
