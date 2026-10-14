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

import logging
import os
import sqlite3
from pathlib import Path

from .sqlite_storage import SQLiteStorage

log = logging.getLogger(__name__)


class FileStorage(SQLiteStorage):
    FILE_EXTENSION = ".session"

    def __init__(self, name: str, workdir: Path):
        super().__init__(name)

        self.database = workdir / (self.name + self.FILE_EXTENSION)

    def update(self):
        version = self.conn.execute("SELECT number FROM version").fetchone()[0]

        if version == 1:
            with self.conn:
                self.conn.execute("DELETE FROM peers")

            version += 1

        if version == 2:
            with self.conn:
                self.conn.execute("ALTER TABLE sessions ADD api_id INTEGER")

            version += 1

        if version == 3:
            with self.conn:
                self.conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS usernames
                    (
                        id       INTEGER,
                        username TEXT,
                        FOREIGN KEY (id) REFERENCES peers(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_usernames_username ON usernames (username);
                    """
                )

            version += 1

        if version in (4, 5):
            self._ensure_tables()
            version = self.VERSION

        with self.conn:
            self.conn.execute("UPDATE version SET number = ?", (version,))

    async def open(self):
        path = self.database
        file_exists = isinstance(path, Path) and path.is_file()

        self.conn = sqlite3.connect(
            str(path),
            timeout=1,
            check_same_thread=False,
        )

        if not file_exists:
            self.create()
        else:
            self._ensure_tables()
            self.update()

        with self.conn:
            self.conn.execute("VACUUM")

    async def save(self):
        await self.date(int(os.path.getmtime(self.database)) if self.database.is_file() else 0)
        self.conn.commit()

    async def close(self):
        self.conn.close()

    async def delete(self):
        os.remove(self.database)
