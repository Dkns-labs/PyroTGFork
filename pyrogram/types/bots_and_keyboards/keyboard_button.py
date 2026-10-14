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

from pyrogram import raw, types
from ..object import Object


class KeyboardButton(Object):
    """One button of the reply keyboard.

    For simple text buttons String can be used instead of this object to specify text of the button.
    Optional fields are mutually exclusive.

    Parameters:
        text (``str``):
            Text of the button.

        request_contact (``bool``, *optional*):
            If True, the user's phone number will be sent as a contact when the button is pressed.

        request_location (``bool``, *optional*):
            If True, the user's current location will be sent when the button is pressed.

        web_app (:obj:`~pyrogram.types.WebAppInfo`, *optional*):
            If specified, the described Web App will be launched when the button is pressed.
    """

    def __init__(
        self,
        text: str,
        request_contact: bool = None,
        request_location: bool = None,
        web_app: "types.WebAppInfo" = None
    ):
        super().__init__()

        self.text = str(text)
        self.request_contact = request_contact
        self.request_location = request_location
        self.web_app = web_app

    @staticmethod
    def read(b: "raw.base.KeyboardButton"):
        # Layer 230 structure: KeyboardButton + type: ButtonType
        if not hasattr(b, "type"):
            # Very old fallback
            return b.text if hasattr(b, "text") else str(b)

        button_type = b.type
        text = b.text

        if isinstance(button_type, raw.types.ButtonTypeDefault):
            return text

        if isinstance(button_type, raw.types.ButtonTypeRequestPhone):
            return KeyboardButton(text=text, request_contact=True)

        if isinstance(button_type, raw.types.ButtonTypeRequestGeoLocation):
            return KeyboardButton(text=text, request_location=True)

        if isinstance(button_type, raw.types.ButtonTypeSimpleWebView):
            return KeyboardButton(
                text=text,
                web_app=types.WebAppInfo(url=button_type.url)
            )

        # Fallback
        return text

    def write(self) -> "raw.types.KeyboardButton":
        if self.request_contact:
            button_type = raw.types.ButtonTypeRequestPhone()
        elif self.request_location:
            button_type = raw.types.ButtonTypeRequestGeoLocation()
        elif self.web_app:
            button_type = raw.types.ButtonTypeSimpleWebView(url=self.web_app.url)
        else:
            button_type = raw.types.ButtonTypeDefault()

        return raw.types.KeyboardButton(
            text=self.text,
            type=button_type
        )
