#  PyroTGFork - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#  Copyright (C) 2022-present TelegramPlayground <https://github.com/TelegramPlayground>
#
#  This file is part of PyroTGFork.
#
#  PyroTGFork is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

import base64
import logging
import sqlite3
import struct

from .sqlite_storage import SQLiteStorage

log = logging.getLogger(__name__)


class MemoryStorage(SQLiteStorage):
    def __init__(self, name: str, session_string: str = None):
        super().__init__(name)

        self.session_string = session_string

    async def open(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.create()

        if not self.session_string:
            return

        s = self.session_string
        data = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

        if len(s) in (self.SESSION_STRING_SIZE, self.SESSION_STRING_SIZE_64):
            # Old session string format (no api_id)
            fmt = (
                self.OLD_SESSION_STRING_FORMAT
                if len(s) == self.SESSION_STRING_SIZE
                else self.OLD_SESSION_STRING_FORMAT_64
            )
            dc_id, test_mode, auth_key, user_id, is_bot = struct.unpack(fmt, data)
            api_id = None
            log.warning(
                "You are using an old session string format. "
                "Use export_session_string() to get a new one."
            )
        else:
            dc_id, api_id, test_mode, auth_key, user_id, is_bot = struct.unpack(
                self.SESSION_STRING_FORMAT, data
            )

        await self.dc_id(dc_id)
        await self.api_id(api_id)
        await self.test_mode(test_mode)
        await self.auth_key(auth_key)
        await self.user_id(user_id)
        await self.is_bot(is_bot)
        await self.date(0)

    async def save(self):
        pass

    async def close(self):
        pass

    async def delete(self):
        pass
