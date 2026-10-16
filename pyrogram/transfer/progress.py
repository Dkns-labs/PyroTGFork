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


"""Progress reporting beside the transfer pipeline."""

import asyncio
import functools
import inspect
import logging

log = logging.getLogger(__name__)


class ProgressReporter:
    """Delivers progress callbacks beside the download pipeline instead of inside it.

    The pipeline used to `await` the user's callback after every chunk. A callback that edits a
    Telegram message (50 ms to several seconds, plus flood waits) then froze the whole pipeline:
    no new requests were sent while it ran, so the speed fell to one chunk per callback (3 MB/s)
    and jumped up again in bursts. Now:

    - the callback runs in its own task, never more than one call at a time;
    - it is fed the *current* byte count whenever it is ready, so a slow callback skips values
      instead of queueing them (the last value is always delivered);
    - an exception raised by the callback (e.g. stop_transmission()) is re-raised in the
      transfer by check(), so cancelling still works.
    """

    def __init__(self, client, progress, progress_args, file_size, sample):
        self.client = client
        self.progress = progress
        self.args = progress_args
        self.file_size = file_size
        self.sample = sample
        self.is_coro = inspect.iscoroutinefunction(progress)
        self.error = None
        self._closing = False
        self._wake = asyncio.Event()
        self._task = client.loop.create_task(self._run())

    def poke(self):
        self._wake.set()

    def check(self):
        if self.error is not None:
            raise self.error

    async def _call(self):
        value = self.sample()

        if self.file_size:
            value = min(value, self.file_size)

        func = functools.partial(self.progress, value, self.file_size, *self.args)

        if self.is_coro:
            await func()
        else:
            await self.client.loop.run_in_executor(self.client.executor, func)

    async def _run(self):
        try:
            while True:
                await self._wake.wait()
                self._wake.clear()
                await self._call()

                if self._closing and not self._wake.is_set():
                    return
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            self.error = e

    async def close(self):
        """Deliver the final value, then stop. Raises what the callback raised, if anything."""
        self._closing = True
        self._wake.set()
        await asyncio.shield(self._task)
        self.check()

    def abort(self):
        if not self._task.done():
            self._task.cancel()
            self._task.add_done_callback(lambda t: t.cancelled() or t.exception())
