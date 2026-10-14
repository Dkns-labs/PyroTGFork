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
import pyrogram
from pyrogram import raw


class Stop:
    async def stop(
        self: "pyrogram.Client",
        block: bool = True
    ):
        """Stop the Client.

        This method disconnects the client from Telegram and stops the underlying tasks.
        """
        async def do_it():
            if not self.is_initialized:
                raise ConnectionError("Client has not been initialized yet")

            if self.updates_watchdog_task is not None:
                self.updates_watchdog_event.set()
                await self.updates_watchdog_task

            self.executor.shutdown(wait=block)

            if not self.no_updates:
                await self.dispatcher.stop()

            await self.terminate()
            await self.disconnect()

            self.is_initialized = False

        if block:
            await do_it()
        else:
            self.loop.create_task(do_it())

        return self

    async def disconnect(
        self: "pyrogram.Client"
    ):
        """Disconnect the Client from Telegram and close all pooled media sessions concurrently."""
        if not self.is_connected:
            raise ConnectionError("Client is already disconnected")

        if self.takeout_id:
            await self.invoke(
                raw.functions.account.FinishTakeoutSession()
            )

        # Concurrently close all cached download sessions and pooled upload sessions
        close_tasks = [i.stop() for i in self.media_sessions.values()]
        if hasattr(self, "_upload_session_pool") and self._upload_session_pool:
            close_tasks.extend(s.stop() for s in self._upload_session_pool)

        if close_tasks:
            await asyncio.gather(*close_tasks, return_exceptions=True)

        self.media_sessions.clear()
        if hasattr(self, "_upload_session_pool"):
            self._upload_session_pool.clear()

        await self.session.stop()
        await self.storage.save()
        await self.storage.close()

        self.is_connected = False
