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

from typing import Union, Optional

import pyrogram
from pyrogram import raw
from pyrogram import types
from ..object import Object


class InlineKeyboardButton(Object):
    """One button of an inline keyboard.

    You must use exactly one of the optional fields.

    Parameters:
        text (``str``):
            Label text on the button.

        callback_data (``str`` | ``bytes``, *optional*):
            Data to be sent in a callback query to the bot when button is pressed, 1-64 bytes.

        url (``str``, *optional*):
            HTTP url to be opened when button is pressed.

        web_app (:obj:`~pyrogram.types.WebAppInfo`, *optional*):
            Description of the Web App that will be launched when the user presses the button.

        login_url (:obj:`~pyrogram.types.LoginUrl`, *optional*):
            An HTTP URL used to automatically authorize the user.

        user_id (``int``, *optional*):
            User id, for links to the user profile.

        switch_inline_query (``str``, *optional*):
            If set, pressing the button will prompt the user to select one of their chats...

        switch_inline_query_current_chat (``str``, *optional*):
            If set, pressing the button will insert the bot's username and the specified inline query
            in the current chat's input field.

        callback_game (:obj:`~pyrogram.types.CallbackGame`, *optional*):
            Description of the game that will be launched when the user presses the button.
            **NOTE**: This type of button **must** always be the first button in the first row.

        copy_text (``str``, *optional*):
            Text that will be copied to the clipboard when the button is pressed (Layer 230+).
    """

    def __init__(
        self,
        text: str,
        callback_data: Union[str, bytes] = None,
        url: str = None,
        web_app: "types.WebAppInfo" = None,
        login_url: "types.LoginUrl" = None,
        user_id: int = None,
        switch_inline_query: str = None,
        switch_inline_query_current_chat: str = None,
        callback_game: "types.CallbackGame" = None,
        copy_text: str = None,
    ):
        super().__init__()

        self.text = str(text)
        self.callback_data = callback_data
        self.url = url
        self.web_app = web_app
        self.login_url = login_url
        self.user_id = user_id
        self.switch_inline_query = switch_inline_query
        self.switch_inline_query_current_chat = switch_inline_query_current_chat
        self.callback_game = callback_game
        self.copy_text = copy_text

    @staticmethod
    def read(b: "raw.base.KeyboardInlineButton") -> "InlineKeyboardButton":
        button_text = b.text
        button_type = b.type

        if isinstance(button_type, raw.types.InlineButtonTypeCallback):
            try:
                data = button_type.data.decode()
            except (UnicodeDecodeError, AttributeError):
                data = button_type.data

            return InlineKeyboardButton(
                text=button_text,
                callback_data=data
            )

        if isinstance(button_type, raw.types.InlineButtonTypeUrl):
            return InlineKeyboardButton(
                text=button_text,
                url=button_type.url
            )

        if isinstance(button_type, raw.types.InlineButtonTypeWebView):
            return InlineKeyboardButton(
                text=button_text,
                web_app=types.WebAppInfo(url=button_type.url)
            )

        if isinstance(button_type, raw.types.InlineButtonTypeUserProfile):
            return InlineKeyboardButton(
                text=button_text,
                user_id=button_type.user_id
            )

        if isinstance(button_type, raw.types.InlineButtonTypeSwitchInline):
            if getattr(button_type, "same_peer", False):
                return InlineKeyboardButton(
                    text=button_text,
                    switch_inline_query_current_chat=button_type.query
                )
            return InlineKeyboardButton(
                text=button_text,
                switch_inline_query=button_type.query
            )

        if isinstance(button_type, raw.types.InlineButtonTypeGame):
            return InlineKeyboardButton(
                text=button_text,
                callback_game=types.CallbackGame()
            )

        if isinstance(button_type, raw.types.InlineButtonTypeCopy):
            return InlineKeyboardButton(
                text=button_text,
                copy_text=button_type.copy_text
            )

        if isinstance(button_type, raw.types.InlineButtonTypeUrlAuth):
            return InlineKeyboardButton(
                text=button_text,
                login_url=types.LoginUrl(
                    url=button_type.url,
                    forward_text=getattr(button_type, "fwd_text", None),
                    button_id=getattr(button_type, "button_id", None)
                )
            )

        # Fallback
        return InlineKeyboardButton(text=button_text)

    async def write(self, client: "pyrogram.Client") -> "raw.types.KeyboardInlineButton":
        button_type = None

        if self.callback_data is not None:
            data = (
                bytes(self.callback_data, "utf-8")
                if isinstance(self.callback_data, str)
                else self.callback_data
            )
            button_type = raw.types.InlineButtonTypeCallback(data=data)

        elif self.url is not None:
            button_type = raw.types.InlineButtonTypeUrl(url=self.url)

        elif self.web_app is not None:
            button_type = raw.types.InlineButtonTypeWebView(url=self.web_app.url)

        elif self.user_id is not None:
            button_type = raw.types.InlineButtonTypeUserProfile(user_id=self.user_id)

        elif self.switch_inline_query is not None:
            button_type = raw.types.InlineButtonTypeSwitchInline(
                query=self.switch_inline_query
            )

        elif self.switch_inline_query_current_chat is not None:
            button_type = raw.types.InlineButtonTypeSwitchInline(
                query=self.switch_inline_query_current_chat,
                same_peer=True
            )

        elif self.callback_game is not None:
            button_type = raw.types.InlineButtonTypeGame()

        elif self.copy_text is not None:
            button_type = raw.types.InlineButtonTypeCopy(copy_text=self.copy_text)

        elif self.login_url is not None:
            # For login_url we use Input version when writing
            bot = await client.resolve_peer(self.login_url.bot_username or "self")
            return raw.types.KeyboardInlineButton(
                text=self.text,
                type=raw.types.InputInlineButtonTypeUrlAuth(
                    url=self.login_url.url,
                    bot=bot,
                    fwd_text=self.login_url.forward_text,
                    request_write_access=bool(self.login_url.request_write_access)
                )
            )

        if button_type is None:
            button_type = raw.types.InlineButtonTypeCallback(data=b"")

        return raw.types.KeyboardInlineButton(
            text=self.text,
            type=button_type
        )
