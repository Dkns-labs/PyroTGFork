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

from typing import List, Union

import pyrogram
from pyrogram import raw
from pyrogram import types
from ..object import Object


class ReplyKeyboardMarkup(Object):
    """A custom keyboard with reply options.

    Parameters:
        keyboard (List of List of :obj:`~pyrogram.types.KeyboardButton` | ``str``):
            List of button rows.

        is_persistent (``bool``, *optional*):
            Requests clients to always show the keyboard when the regular keyboard is hidden.

        resize_keyboard (``bool``, *optional*):
            Requests clients to resize the keyboard vertically for optimal fit.

        one_time_keyboard (``bool``, *optional*):
            Requests clients to hide the keyboard as soon as it's been used.

        selective (``bool``, *optional*):
            Use this parameter if you want to show the keyboard to specific users only.

        placeholder (``str``, *optional*):
            The placeholder to be shown in the input field when the keyboard is active.
    """

    def __init__(
        self,
        keyboard: List[List[Union["types.KeyboardButton", str]]],
        is_persistent: bool = None,
        resize_keyboard: bool = None,
        one_time_keyboard: bool = None,
        selective: bool = None,
        placeholder: str = None
    ):
        super().__init__()

        self.keyboard = keyboard
        self.is_persistent = is_persistent
        self.resize_keyboard = resize_keyboard
        self.one_time_keyboard = one_time_keyboard
        self.selective = selective
        self.placeholder = placeholder

    @staticmethod
    def read(kb: "raw.base.ReplyMarkup") -> "ReplyKeyboardMarkup":
        keyboard = []

        for row in kb.rows:
            buttons = []
            for button in row.buttons:
                buttons.append(types.KeyboardButton.read(button))
            keyboard.append(buttons)

        return ReplyKeyboardMarkup(
            keyboard=keyboard,
            is_persistent=getattr(kb, "persistent", None),
            resize_keyboard=getattr(kb, "resize", None),
            one_time_keyboard=getattr(kb, "single_use", None),
            selective=getattr(kb, "selective", None),
            placeholder=getattr(kb, "placeholder", None)
        )

    async def write(self, _: "pyrogram.Client") -> "raw.types.ReplyKeyboardMarkup":
        rows = []

        for row in self.keyboard:
            buttons = []
            for button in row:
                if isinstance(button, str):
                    buttons.append(types.KeyboardButton(button).write())
                else:
                    buttons.append(button.write())
            rows.append(raw.types.KeyboardButtonRow(buttons=buttons))

        return raw.types.ReplyKeyboardMarkup(
            rows=rows,
            resize=self.resize_keyboard or None,
            single_use=self.one_time_keyboard or None,
            selective=self.selective or None,
            persistent=self.is_persistent or None,
            placeholder=self.placeholder or None
        )
