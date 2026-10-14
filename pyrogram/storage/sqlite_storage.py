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

import inspect
import logging
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, List, Tuple

from pyrogram import raw
from .storage import Storage
from .. import utils

log = logging.getLogger(__name__)

# language=SQLite
SCHEMA = """
CREATE TABLE sessions
(
    dc_id     INTEGER PRIMARY KEY,
    api_id    INTEGER,
    test_mode INTEGER,
    auth_key  BLOB,
    date      INTEGER NOT NULL,
    user_id   INTEGER,
    is_bot    INTEGER
);

CREATE TABLE peers
(
    id             INTEGER PRIMARY KEY,
    access_hash    INTEGER,
    type           INTEGER NOT NULL,
    phone_number   TEXT,
    last_update_on INTEGER NOT NULL DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))
);

CREATE TABLE usernames
(
    id       INTEGER,
    username TEXT,
    FOREIGN KEY (id) REFERENCES peers (id)
);

CREATE TABLE update_state
(
    id   INTEGER PRIMARY KEY,
    pts  INTEGER,
    qts  INTEGER,
    date INTEGER,
    seq  INTEGER
);

CREATE INDEX idx_peers_id ON peers (id);
CREATE INDEX idx_peers_phone_number ON peers (phone_number);
CREATE INDEX idx_usernames_username ON usernames (username);
CREATE INDEX idx_usernames_id ON usernames (id);

CREATE TRIGGER trg_peers_last_update_on
    AFTER UPDATE
    ON peers
    FOR EACH ROW
BEGIN
    UPDATE peers
    SET last_update_on = CAST(STRFTIME('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;
"""


def get_input_peer(peer_id: int, access_hash: int, peer_type: str):
    if peer_type in ["user", "bot"]:
        return raw.types.InputPeerUser(
            user_id=peer_id,
            access_hash=access_hash
        )

    if peer_type == "group":
        return raw.types.InputPeerChat(
            chat_id=-peer_id
        )

    if peer_type in ["channel", "supergroup"]:
        return raw.types.InputPeerChannel(
            channel_id=utils.get_channel_id(peer_id),
            access_hash=access_hash
        )

    raise ValueError(f"Invalid peer type: {peer_type}")


class SQLiteStorage(Storage):
    VERSION = 4
    USERNAME_TTL = 8 * 60 * 60
    FILE_EXTENSION = ".session"
    PEER_CACHE_CAPACITY = 20000

    def __init__(self, name: str, workdir: Path, session_string: str = None, in_memory: bool = False):
        super().__init__(name)

        self.database = workdir / (self.name + self.FILE_EXTENSION)
        self.session_string = session_string
        self.in_memory = in_memory

        self.conn: sqlite3.Connection = None

        # High-speed in-memory LRU caches to avoid hitting SQLite on every RPC call
        self._peer_id_cache: OrderedDict[int, Any] = OrderedDict()
        self._peer_username_cache: OrderedDict[str, Tuple[Any, int]] = OrderedDict()
        self._meta_cache = {}

    def _apply_pragmas(self):
        """Configure SQLite for high-concurrency, non-blocking WAL performance."""
        if not self.in_memory:
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute("PRAGMA cache_size=-64000")      # 64 MB page cache
        self.conn.execute("PRAGMA mmap_size=134217728")   # 128 MB memory-mapped I/O
        self.conn.execute("PRAGMA busy_timeout=5000")

    def _cache_peer_id(self, peer_id: int, input_peer: Any):
        if peer_id in self._peer_id_cache:
            self._peer_id_cache.move_to_end(peer_id)
        self._peer_id_cache[peer_id] = input_peer
        if len(self._peer_id_cache) > self.PEER_CACHE_CAPACITY:
            self._peer_id_cache.popitem(last=False)

    def _cache_peer_username(self, username: str, input_peer: Any, last_update_on: int):
        if username in self._peer_username_cache:
            self._peer_username_cache.move_to_end(username)
        self._peer_username_cache[username] = (input_peer, last_update_on)
        if len(self._peer_username_cache) > self.PEER_CACHE_CAPACITY:
            self._peer_username_cache.popitem(last=False)

    def create(self):
        with self.conn:
            self.conn.executescript(SCHEMA)

            self.conn.execute(
                "INSERT INTO version VALUES (?)",
                (self.VERSION,)
            )

            self.conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (2, None, None, None, 0, None, None)
            )

    def update(self, version: int):
        if version == 1:
            with self.conn:
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS update_state ("
                    "id INTEGER PRIMARY KEY, "
                    "pts INTEGER, "
                    "qts INTEGER, "
                    "date INTEGER, "
                    "seq INTEGER)"
                )
            version += 1

        if version == 2:
            with self.conn:
                self.conn.execute("ALTER TABLE sessions ADD api_id INTEGER")
            version += 1

        if version == 3:
            with self.conn:
                self.conn.executescript(
                    """
                    CREATE TABLE usernames
                    (
                        id       INTEGER,
                        username TEXT,
                        FOREIGN KEY (id) REFERENCES peers (id)
                    );

                    INSERT INTO usernames (id, username)
                    SELECT id, username FROM peers WHERE username IS NOT NULL;

                    CREATE INDEX idx_usernames_username ON usernames (username);
                    CREATE INDEX idx_usernames_id ON usernames (id);

                    CREATE TABLE peers_new
                    (
                        id             INTEGER PRIMARY KEY,
                        access_hash    INTEGER,
                        type           INTEGER NOT NULL,
                        phone_number   TEXT,
                        last_update_on INTEGER NOT NULL DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))
                    );

                    INSERT INTO peers_new (id, access_hash, type, phone_number, last_update_on)
                    SELECT id, access_hash, type, phone_number, last_update_on FROM peers;

                    DROP TABLE peers;

                    ALTER TABLE peers_new RENAME TO peers;

                    CREATE INDEX idx_peers_id ON peers (id);
                    CREATE INDEX idx_peers_phone_number ON peers (phone_number);

                    CREATE TRIGGER trg_peers_last_update_on
                        AFTER UPDATE
                        ON peers
                        FOR EACH ROW
                    BEGIN
                        UPDATE peers
                        SET last_update_on = CAST(STRFTIME('%s', 'now') AS INTEGER)
                        WHERE id = NEW.id;
                    END;
                    """
                )
            version += 1

        with self.conn:
            self.conn.execute("UPDATE version SET number = ?", (version,))

    async def open(self):
        path = self.database
        if self.in_memory:
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._apply_pragmas()
            self.create()

            if self.session_string:
                # Old format
                if len(self.session_string) in [self.SESSION_STRING_SIZE, self.SESSION_STRING_SIZE_64]:
                    dc_id, test_mode, auth_key, user_id, is_bot = self.unpack_old(self.session_string)
                    await self.dc_id(dc_id)
                    await self.test_mode(test_mode)
                    await self.auth_key(auth_key)
                    await self.user_id(user_id)
                    await self.is_bot(is_bot)
                    return

                dc_id, api_id, test_mode, auth_key, user_id, is_bot = self.unpack(self.session_string)

                await self.dc_id(dc_id)
                await self.api_id(api_id)
                await self.test_mode(test_mode)
                await self.auth_key(auth_key)
                await self.user_id(user_id)
                await self.is_bot(is_bot)

            return

        file_exists = isinstance(path, Path) and path.is_file()

        self.conn = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
        self._apply_pragmas()

        if not file_exists:
            self.create()
        else:
            with self.conn:
                version = self.conn.execute("SELECT number FROM version").fetchone()[0]

            if version < self.VERSION:
                self.update(version)

        with self.conn:
            self.conn.execute("VACUUM")

    async def save(self):
        await self.date(int(time.time()))
        self.conn.commit()

    async def close(self):
        self.conn.close()
        self._peer_id_cache.clear()
        self._peer_username_cache.clear()
        self._meta_cache.clear()

    async def delete(self):
        if not self.in_memory:
            Path(self.database).unlink(missing_ok=True)
            Path(str(self.database) + "-wal").unlink(missing_ok=True)
            Path(str(self.database) + "-shm").unlink(missing_ok=True)

    async def update_peers(self, peers: List[Tuple[int, int, str, List[str], str]]):
        if not peers:
            return

        now = int(time.time())
        peers_data = []
        delete_usernames_data = []
        insert_usernames_data = []

        for peer_id, access_hash, peer_type, usernames, phone_number in peers:
            peers_data.append((peer_id, access_hash, peer_type, phone_number))
            delete_usernames_data.append((peer_id,))

            try:
                input_peer = get_input_peer(peer_id, access_hash, peer_type)
                self._cache_peer_id(peer_id, input_peer)
            except ValueError:
                input_peer = None

            if usernames:
                for username in usernames:
                    insert_usernames_data.append((peer_id, username))
                    if input_peer is not None:
                        self._cache_peer_username(username, input_peer, now)

        self.conn.executemany(
            "REPLACE INTO peers (id, access_hash, type, phone_number) VALUES (?, ?, ?, ?)",
            peers_data
        )
        self.conn.executemany(
            "DELETE FROM usernames WHERE id = ?",
            delete_usernames_data
        )
        if insert_usernames_data:
            self.conn.executemany(
                "REPLACE INTO usernames VALUES (?, ?)",
                insert_usernames_data
            )
        self.conn.commit()

    async def update_state(self, value: Tuple[int, int, int, int, int] = object):
        if value == object:
            return self.conn.execute(
                "SELECT id, pts, qts, date, seq FROM update_state ORDER BY id ASC"
            ).fetchall()
        else:
            if isinstance(value, int):
                self.conn.execute(
                    "DELETE FROM update_state WHERE id = ?",
                    (value,)
                )
            else:
                self.conn.execute(
                    "REPLACE INTO update_state VALUES (?, ?, ?, ?, ?)",
                    value
                )
            self.conn.commit()

    async def get_peer_by_id(self, peer_id: int):
        cached = self._peer_id_cache.get(peer_id)
        if cached is not None:
            self._peer_id_cache.move_to_end(peer_id)
            return cached

        r = self.conn.execute(
            "SELECT id, access_hash, type FROM peers WHERE id = ?",
            (peer_id,)
        ).fetchone()

        if r is None:
            raise KeyError(f"ID not found: {peer_id}")

        input_peer = get_input_peer(*r)
        self._cache_peer_id(peer_id, input_peer)
        return input_peer

    async def get_peer_by_username(self, username: str):
        username_key = username.lower()
        cached = self._peer_username_cache.get(username_key)
        if cached is not None:
            input_peer, last_update_on = cached
            if abs(time.time() - last_update_on) <= self.USERNAME_TTL:
                self._peer_username_cache.move_to_end(username_key)
                return input_peer
            else:
                del self._peer_username_cache[username_key]

        r = self.conn.execute(
            "SELECT p.id, p.access_hash, p.type, p.last_update_on FROM peers p "
            "JOIN usernames u ON p.id = u.id "
            "WHERE u.username = ? "
            "ORDER BY p.last_update_on DESC",
            (username_key,)
        ).fetchone()

        if r is None:
            raise KeyError(f"Username not found: {username}")

        if abs(time.time() - r[3]) > self.USERNAME_TTL:
            raise KeyError(f"Username expired: {username}")

        input_peer = get_input_peer(*r[:3])
        self._cache_peer_username(username_key, input_peer, r[3])
        return input_peer

    async def get_peer_by_phone_number(self, phone_number: str):
        r = self.conn.execute(
            "SELECT id, access_hash, type FROM peers WHERE phone_number = ?",
            (phone_number,)
        ).fetchone()

        if r is None:
            raise KeyError(f"Phone number not found: {phone_number}")

        input_peer = get_input_peer(*r)
        self._cache_peer_id(r[0], input_peer)
        return input_peer

    def _get(self):
        attr = inspect.stack()[2].function
        if attr in self._meta_cache:
            return self._meta_cache[attr]

        val = self.conn.execute(f"SELECT {attr} FROM sessions").fetchone()[0]
        self._meta_cache[attr] = val
        return val

    def _set(self, value: Any):
        attr = inspect.stack()[2].function
        self._meta_cache[attr] = value

        with self.conn:
            self.conn.execute(f"UPDATE sessions SET {attr} = ?", (value,))

    def _accessor(self, value: Any = object):
        return self._get() if value == object else self._set(value)

    async def dc_id(self, value: int = object):
        return self._accessor(value)

    async def api_id(self, value: int = object):
        return self._accessor(value)

    async def test_mode(self, value: bool = object):
        return self._accessor(value)

    async def auth_key(self, value: bytes = object):
        return self._accessor(value)

    async def date(self, value: int = object):
        return self._accessor(value)

    async def user_id(self, value: int = object):
        return self._accessor(value)

    async def is_bot(self, value: bool = object):
        return self._accessor(value)

    async def version(self, value: int = object):
        if value == object:
            return self.conn.execute("SELECT number FROM version").fetchone()[0]
        else:
            with self.conn:
                self.conn.execute("UPDATE version SET number = ?", (value,))
