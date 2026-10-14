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

from enum import auto
from .auto_name import AutoName


class MessageMediaType(AutoName):
    """Message media type enumeration used in :obj:`~pyrogram.types.Message` and :obj:`~pyrogram.types.Story`."""

    AUDIO = auto()
    DOCUMENT = auto()
    PHOTO = auto()
    STICKER = auto()
    VIDEO = auto()
    ANIMATION = auto()
    VOICE = auto()
    VIDEO_NOTE = auto()
    CONTACT = auto()
    LOCATION = auto()
    VENUE = auto()
    POLL = auto()
    WEB_PAGE = auto()
    WEB_PAGE_PREVIEW = auto()
    DICE = auto()
    GAME = auto()
    STORY = auto()
    GIVEAWAY = auto()
    GIVEAWAY_WINNERS = auto()
    PAID_MEDIA = auto()
    CHECKLIST = auto()
