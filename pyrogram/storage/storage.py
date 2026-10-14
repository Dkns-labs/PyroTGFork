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
import struct
from abc import ABC, abstractmethod
from typing import List, Tuple


class Storage(ABC):
    OLD_SESSION_STRING_FORMAT = ">B?256sI?"
    OLD_SESSION_STRING_FORMAT_64 = ">B?256sQ?"
    SESSION_STRING_SIZE = 351
    SESSION_STRING_SIZE_64 = 356

    SESSION_STRING_FORMAT = ">BI?256sQ?"

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def open(self):
        raise NotImplementedError

    @abstractmethod
    async def save(self):
        raise NotImplementedError

    @abstractmethod
    async def close(self):
        raise NotImplementedError

    @abstractmethod
    async def delete(self):
        raise NotImplementedError

    @abstractmethod
    async def update_peers(self, peers: List[Tuple[int, int, str, str, str]]):
        raise NotImplementedError

    @abstractmethod
    async def update_usernames(self, usernames: List[Tuple[int, List[str]]]):
        raise NotImplementedError

    @abstractmethod
    async def update_state(self, update_state: Tuple[int, int, int, int, int] = object):
        raise NotImplementedError

    @abstractmethod
    async def get_peer_by_id(self, peer_id: int):
        raise NotImplementedError

    @abstractmethod
    async def get_peer_by_username(self, username: str):
        raise NotImplementedError

    @abstractmethod
    async def get_peer_by_phone_number(self, phone_number: str):
        raise NotImplementedError

    @abstractmethod
    async def dc_id(self, value: int = object):
        raise NotImplementedError

    @abstractmethod
    async def api_id(self, value: int = object):
        raise NotImplementedError

    @abstractmethod
    async def test_mode(self, value: bool = object):
        raise NotImplementedError

    @abstractmethod
    async def auth_key(self, value: bytes = object):
        raise NotImplementedError

    @abstractmethod
    async def date(self, value: int = object):
        raise NotImplementedError

    @abstractmethod
    async def user_id(self, value: int = object):
        raise NotImplementedError

    @abstractmethod
    async def is_bot(self, value: bool = object):
        raise NotImplementedError

    async def export_session_string(self):
        packed = struct.pack(
            self.SESSION_STRING_FORMAT,
            await self.dc_id(),
            await self.api_id(),
            await self.test_mode(),
            await self.auth_key(),
            await self.user_id(),
            await self.is_bot(),
        )

        return base64.urlsafe_b64encode(packed).decode().rstrip("=")
