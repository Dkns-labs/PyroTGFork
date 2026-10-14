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

from pyrogram import raw
from ..object import Object


class LoginUrl(Object):
    """Represents a parameter of the inline keyboard button used to automatically authorize a user.

    Parameters:
        url (``str``):
            An HTTP URL to be opened with user authorization data added to the query string when the button is pressed.

        forward_text (``str``, *optional*):
            New text of the button in forwarded messages.

        bot_username (``str``, *optional*):
            Username of a bot, which will be used for user authorization.

        request_write_access (``bool``, *optional*):
            Pass True to request the permission for your bot to send messages to the user.

        button_id (``int``, *optional*):
            Button identifier.
    """

    def __init__(
        self,
        *,
        url: str,
        forward_text: str = None,
        bot_username: str = None,
        request_write_access: bool = None,
        button_id: int = None
    ):
        super().__init__()

        self.url = url
        self.forward_text = forward_text
        self.bot_username = bot_username
        self.request_write_access = request_write_access
        self.button_id = button_id

    @staticmethod
    def read(b) -> "LoginUrl":
        # Layer 230: InlineButtonTypeUrlAuth
        if isinstance(b, raw.types.InlineButtonTypeUrlAuth):
            return LoginUrl(
                url=b.url,
                forward_text=getattr(b, "fwd_text", None),
                button_id=getattr(b, "button_id", None)
            )
        return LoginUrl(url=getattr(b, "url", ""))

    def write(self, text: str, bot: "raw.base.InputUser"):
        return raw.types.InputInlineButtonTypeUrlAuth(
            url=self.url,
            bot=bot,
            fwd_text=self.forward_text,
            request_write_access=bool(self.request_write_access)
        )
