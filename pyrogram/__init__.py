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

__fork_name__ = "pyrotgfork"
__version__ = "2.2.24.1"
__license__ = "GNU Lesser General Public License v3.0 (LGPL-3.0)"
__copyright__ = "Copyright (C) 2017-present Dan <https://github.com/delivrance>"

from concurrent.futures.thread import ThreadPoolExecutor


class StopTransmission(Exception):
    pass


class StopPropagation(StopAsyncIteration):
    pass


class ContinuePropagation(StopAsyncIteration):
    pass


from . import raw, types, filters, handlers, emoji, enums
from .client import Client
from .sync import idle, compose

def _crypto_threads() -> int:
    # MTProto crypto (IGE/CTR/SHA-256) is CPU bound and releases the GIL, but a single worker
    # serializes every connection's traffic and caps total throughput at one core. Several
    # workers are safe because per-connection cipher state is ordered by the transport itself
    # (see TCPAbridgedO). Override with PYROGRAM_CRYPTO_THREADS=<n> (1 restores the old behaviour).
    import os

    try:
        forced = int(os.environ.get("PYROGRAM_CRYPTO_THREADS", 0))
    except ValueError:
        forced = 0

    if forced > 0:
        return min(forced, 32)

    return max(1, min(4, os.cpu_count() or 1))


crypto_executor = ThreadPoolExecutor(_crypto_threads(), thread_name_prefix="CryptoWorker")
