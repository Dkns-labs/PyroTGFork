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

from .file_storage import FileStorage
from .memory_storage import MemoryStorage
from .sqlite_storage import SQLiteStorage
from .storage import Storage

__all__ = ["FileStorage", "MemoryStorage", "SQLiteStorage", "Storage"]
