#  PyroTGFork / Pyrogram - Telegram MTProto API Client Library for Python
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
import struct
from enum import IntEnum, auto
from typing import Optional, Tuple, Union

from pyrogram.raw.core import Bytes, Int, Long, TLObject

log = logging.getLogger(__name__)


def b64_encode(s: Union[bytes, bytearray]) -> str:
    """Encode bytes into a URL-safe base64 string without padding."""
    return base64.urlsafe_b64encode(s).decode().rstrip("=")


def b64_decode(s: str) -> bytes:
    """Decode a URL-safe base64 string while restoring stripped padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rle_encode(s: Union[bytes, bytearray]) -> bytes:
    """Zero-byte Run-Length Encoding (RLE) used by Telegram File IDs."""
    r = bytearray()
    n = 0

    for b in s:
        if not b:
            n += 1
        else:
            if n:
                r.extend((0, n))
                n = 0
            r.append(b)

    if n:
        r.extend((0, n))

    return bytes(r)


def rle_decode(s: Union[bytes, bytearray]) -> bytes:
    """Zero-byte Run-Length Decoding (RLE) used by Telegram File IDs."""
    r = bytearray()
    z = False

    for b in s:
        if not b:
            z = True
            continue

        if z:
            r.extend(b"\x00" * b)
            z = False
        else:
            r.append(b)

    return bytes(r)


class FileType(IntEnum):
    THUMBNAIL = 0
    CHAT_PHOTO = 1  # ProfilePhoto
    PHOTO = 2
    VOICE = 3  # VoiceNote
    VIDEO = 4
    DOCUMENT = 5
    ENCRYPTED = 6
    TEMP = 7
    STICKER = 8
    AUDIO = 9
    ANIMATION = 10
    ENCRYPTED_THUMBNAIL = 11
    WALLPAPER = 12
    VIDEO_NOTE = 13
    SECURE_RAW = 14
    SECURE = 15
    BACKGROUND = 16
    DOCUMENT_AS_FILE = 17
    RING_TONE = 18
    CALL_LOG = 19
    PHOTO_STORY = 20
    VIDEO_STORY = 21
    SELF_DESTRUCTING_PHOTO = 22
    SELF_DESTRUCTING_VIDEO = 23
    SELF_DESTRUCTING_VIDEO_NOTE = 24
    SELF_DESTRUCTING_VOICE_NOTE = 25
    CUSTOM_EMOJI = 26


class ThumbnailSource(IntEnum):
    LEGACY = 0
    THUMBNAIL = 1
    CHAT_PHOTO_SMALL = 2  # DialogPhotoSmall
    CHAT_PHOTO_BIG = 3    # DialogPhotoBig
    STICKER_SET_THUMBNAIL = 4
    FULL_LEGACY = 5       # FragmentSticker / FullLegacy


class FileUniqueType(IntEnum):
    WEB = 0
    PHOTO = 1
    DOCUMENT = 2
    SECURE = 3
    ENCRYPTED = 4
    TEMP = 5


PHOTO_TYPES = {
    FileType.THUMBNAIL,
    FileType.CHAT_PHOTO,
    FileType.PHOTO,
    FileType.WALLPAPER,
    FileType.ENCRYPTED_THUMBNAIL,
    FileType.PHOTO_STORY,
    FileType.SELF_DESTRUCTING_PHOTO,
}

DOCUMENT_TYPES = (
    set(FileType)
    - PHOTO_TYPES
    - {FileType.SECURE, FileType.SECURE_RAW, FileType.ENCRYPTED, FileType.TEMP}
)

WEB_LOCATION_FLAG = 1 << 24
FILE_REFERENCE_FLAG = 1 << 25


def _read_tl_string(stream: bytes) -> Tuple[bytes, bytes]:
    """Read a Telegram TL-serialized bytes/string and return (value, remaining_stream)."""
    first_byte = stream[0]
    if first_byte == 254:
        length = int.from_bytes(stream[1:4], "little")
        offset = 4
    else:
        length = first_byte
        offset = 1

    data = stream[offset : offset + length]
    padding = (- (offset + length)) % 4
    return data, stream[offset + length + padding :]


class FileId:
    MAJOR = 4
    MINOR = 50  # Compatible with TDLib modern Persistent ID version

    __slots__ = (
        "major",
        "minor",
        "file_type",
        "dc_id",
        "file_reference",
        "url",
        "media_id",
        "access_hash",
        "volume_id",
        "thumbnail_source",
        "thumbnail_file_type",
        "thumbnail_size",
        "secret",
        "local_id",
        "chat_id",
        "chat_access_hash",
        "sticker_set_id",
        "sticker_set_access_hash",
    )

    def __init__(
        self,
        *,
        major: int = MAJOR,
        minor: int = MINOR,
        file_type: FileType,
        dc_id: int,
        file_reference: bytes = b"",
        url: Optional[str] = None,
        media_id: Optional[int] = None,
        access_hash: Optional[int] = None,
        volume_id: Optional[int] = None,
        thumbnail_source: Optional[ThumbnailSource] = None,
        thumbnail_file_type: Optional[FileType] = None,
        thumbnail_size: str = "",
        secret: Optional[int] = None,
        local_id: Optional[int] = None,
        chat_id: Optional[int] = None,
        chat_access_hash: Optional[int] = None,
        sticker_set_id: Optional[int] = None,
        sticker_set_access_hash: Optional[int] = None,
    ):
        self.major = major
        self.minor = minor
        self.file_type = file_type
        self.dc_id = dc_id
        self.file_reference = file_reference
        self.url = url
        self.media_id = media_id
        self.access_hash = access_hash
        self.volume_id = volume_id
        self.thumbnail_source = thumbnail_source
        self.thumbnail_file_type = thumbnail_file_type
        self.thumbnail_size = thumbnail_size
        self.secret = secret
        self.local_id = local_id
        self.chat_id = chat_id
        self.chat_access_hash = chat_access_hash
        self.sticker_set_id = sticker_set_id
        self.sticker_set_access_hash = sticker_set_access_hash

    @staticmethod
    def decode(file_id: str) -> Optional["FileId"]:
        """Decode a base64-encoded Telegram file_id string into a FileId object."""
        decoded = rle_decode(b64_decode(file_id))

        major = decoded[-1]

        if major < 4:
            minor = 0
            buffer = decoded[:-1]
        else:
            minor = decoded[-2]
            buffer = decoded[:-2]

        file_type, dc_id = struct.unpack("<ii", buffer[:8])
        buffer = buffer[8:]

        has_web_location = bool(file_type & WEB_LOCATION_FLAG)
        has_file_reference = bool(file_type & FILE_REFERENCE_FLAG)

        file_type &= ~WEB_LOCATION_FLAG
        file_type &= ~FILE_REFERENCE_FLAG

        try:
            file_type = FileType(file_type)
        except ValueError:
            raise ValueError(f"Unknown file_type {file_type} of file_id {file_id}")

        if has_web_location:
            url_bytes, buffer = _read_tl_string(buffer)
            url = url_bytes.decode("utf-8", errors="replace")
            (access_hash,) = struct.unpack("<q", buffer[:8])
            buffer = buffer[8:]

            return FileId(
                major=major,
                minor=minor,
                file_type=file_type,
                dc_id=dc_id,
                url=url,
                access_hash=access_hash,
            )

        file_reference = b""
        if has_file_reference:
            file_reference, buffer = _read_tl_string(buffer)

        media_id, access_hash = struct.unpack("<qq", buffer[:16])
        buffer = buffer[16:]

        if file_type in PHOTO_TYPES:
            (volume_id,) = struct.unpack("<q", buffer[:8])
            buffer = buffer[8:]

            (thumbnail_source,) = (0,) if minor < 4 else struct.unpack("<i", buffer[:4])
            if minor >= 4:
                buffer = buffer[4:]

            try:
                thumbnail_source = ThumbnailSource(thumbnail_source)
            except ValueError:
                raise ValueError(
                    f"Unknown thumbnail_source {thumbnail_source} of file_id {file_id}"
                )

            if thumbnail_source == ThumbnailSource.LEGACY:
                secret, local_id = struct.unpack("<qi", buffer[:12])
                return FileId(
                    major=major,
                    minor=minor,
                    file_type=file_type,
                    dc_id=dc_id,
                    file_reference=file_reference,
                    media_id=media_id,
                    access_hash=access_hash,
                    volume_id=volume_id,
                    thumbnail_source=thumbnail_source,
                    secret=secret,
                    local_id=local_id,
                )

            if thumbnail_source == ThumbnailSource.THUMBNAIL:
                # TDLib sub_version >= 32 still writes thumbnail_file_type for THUMBNAIL;
                # however, if older/custom encodings omit or shift fields, handle both cleanly.
                thumbnail_file_type, thumbnail_size, local_id = struct.unpack(
                    "<iii", buffer[:12]
                )
                thumbnail_size = chr(thumbnail_size) if thumbnail_size else ""

                try:
                    thumbnail_file_type = FileType(thumbnail_file_type)
                except ValueError:
                    thumbnail_file_type = file_type

                return FileId(
                    major=major,
                    minor=minor,
                    file_type=file_type,
                    dc_id=dc_id,
                    file_reference=file_reference,
                    media_id=media_id,
                    access_hash=access_hash,
                    volume_id=volume_id,
                    thumbnail_source=thumbnail_source,
                    thumbnail_file_type=thumbnail_file_type,
                    thumbnail_size=thumbnail_size,
                    local_id=local_id,
                )

            if thumbnail_source in (
                ThumbnailSource.CHAT_PHOTO_SMALL,
                ThumbnailSource.CHAT_PHOTO_BIG,
            ):
                chat_id, chat_access_hash, local_id = struct.unpack("<qqi", buffer[:20])
                return FileId(
                    major=major,
                    minor=minor,
                    file_type=file_type,
                    dc_id=dc_id,
                    file_reference=file_reference,
                    media_id=media_id,
                    access_hash=access_hash,
                    volume_id=volume_id,
                    thumbnail_source=thumbnail_source,
                    chat_id=chat_id,
                    chat_access_hash=chat_access_hash,
                    local_id=local_id,
                )

            if thumbnail_source == ThumbnailSource.STICKER_SET_THUMBNAIL:
                if len(buffer) >= 20:
                    sticker_set_id, sticker_set_access_hash, local_id = struct.unpack(
                        "<qqi", buffer[:20]
                    )
                else:
                    sticker_set_id, sticker_set_access_hash = 0, 0
                    (local_id,) = struct.unpack("<i", buffer[:4]) if len(buffer) >= 4 else (0,)

                return FileId(
                    major=major,
                    minor=minor,
                    file_type=file_type,
                    dc_id=dc_id,
                    file_reference=file_reference,
                    media_id=media_id,
                    access_hash=access_hash,
                    volume_id=volume_id,
                    thumbnail_source=thumbnail_source,
                    sticker_set_id=sticker_set_id,
                    sticker_set_access_hash=sticker_set_access_hash,
                    local_id=local_id,
                )

            if thumbnail_source == ThumbnailSource.FULL_LEGACY:
                volume_id, local_id, secret = struct.unpack("<qii", buffer[:16])
                return FileId(
                    major=major,
                    minor=minor,
                    file_type=file_type,
                    dc_id=dc_id,
                    file_reference=file_reference,
                    media_id=media_id,
                    access_hash=access_hash,
                    volume_id=volume_id,
                    thumbnail_source=thumbnail_source,
                    secret=secret,
                    local_id=local_id,
                )

        if file_type in DOCUMENT_TYPES:
            return FileId(
                major=major,
                minor=minor,
                file_type=file_type,
                dc_id=dc_id,
                file_reference=file_reference,
                media_id=media_id,
                access_hash=access_hash,
            )

        raise ValueError(f"Unsupported file_type {file_type} in file_id {file_id}")

    def encode(self, *, major: Optional[int] = None, minor: Optional[int] = None) -> str:
        """Encode the FileId instance into a URL-safe base64 Telegram file_id string."""
        major = major if major is not None else self.major
        minor = minor if minor is not None else self.minor

        buffer = bytearray()

        file_type = int(self.file_type)

        if self.url:
            file_type |= WEB_LOCATION_FLAG

        if self.file_reference:
            file_type |= FILE_REFERENCE_FLAG

        buffer.extend(struct.pack("<ii", file_type, self.dc_id))

        if self.url:
            buffer.extend(Bytes(self.url.encode("utf-8")))
            buffer.extend(Long(self.access_hash or 0))
            buffer.extend(struct.pack("<bb", minor, major))
            return b64_encode(rle_encode(buffer))

        if self.file_reference:
            buffer.extend(Bytes(self.file_reference))

        buffer.extend(struct.pack("<qq", self.media_id or 0, self.access_hash or 0))

        if self.file_type in PHOTO_TYPES:
            buffer.extend(Long(self.volume_id or 0))

            if minor >= 4:
                buffer.extend(Int(int(self.thumbnail_source or 0)))

            if self.thumbnail_source == ThumbnailSource.LEGACY:
                buffer.extend(struct.pack("<qi", self.secret or 0, self.local_id or 0))
            elif self.thumbnail_source == ThumbnailSource.THUMBNAIL:
                thumb_ft = int(self.thumbnail_file_type or self.file_type)
                thumb_sz = ord(self.thumbnail_size[0]) if self.thumbnail_size else 0
                buffer.extend(
                    struct.pack("<iii", thumb_ft, thumb_sz, self.local_id or 0)
                )
            elif self.thumbnail_source in (
                ThumbnailSource.CHAT_PHOTO_SMALL,
                ThumbnailSource.CHAT_PHOTO_BIG,
            ):
                buffer.extend(
                    struct.pack(
                        "<qqi",
                        self.chat_id or 0,
                        self.chat_access_hash or 0,
                        self.local_id or 0,
                    )
                )
            elif self.thumbnail_source == ThumbnailSource.STICKER_SET_THUMBNAIL:
                buffer.extend(
                    struct.pack(
                        "<qqi",
                        self.sticker_set_id or 0,
                        self.sticker_set_access_hash or 0,
                        self.local_id or 0,
                    )
                )
            elif self.thumbnail_source == ThumbnailSource.FULL_LEGACY:
                buffer.extend(
                    struct.pack(
                        "<qii",
                        self.volume_id or 0,
                        self.local_id or 0,
                        self.secret or 0,
                    )
                )

        buffer.extend(struct.pack("<bb", minor, major))

        return b64_encode(rle_encode(buffer))

    def __str__(self) -> str:
        return str({k: getattr(self, k) for k in self.__slots__ if getattr(self, k) is not None})

    def __repr__(self) -> str:
        attrs = ", ".join(
            f"{k}={getattr(self, k)!r}"
            for k in self.__slots__
            if getattr(self, k) is not None and k not in ("major", "minor")
        )
        return f"pyrogram.file_id.FileId({attrs})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FileId):
            return NotImplemented
        return all(getattr(self, k) == getattr(other, k) for k in self.__slots__)


class FileUniqueId:
    __slots__ = ("file_unique_type", "url", "media_id", "volume_id", "local_id")

    def __init__(
        self,
        *,
        file_unique_type: FileUniqueType,
        url: Optional[str] = None,
        media_id: Optional[int] = None,
        volume_id: Optional[int] = None,
        local_id: Optional[int] = None,
    ):
        self.file_unique_type = file_unique_type
        self.url = url
        self.media_id = media_id
        self.volume_id = volume_id
        self.local_id = local_id

    @staticmethod
    def decode(file_unique_id: str) -> "FileUniqueId":
        """Decode a base64-encoded Telegram file_unique_id string."""
        buffer = rle_decode(b64_decode(file_unique_id))

        (file_unique_type,) = struct.unpack("<i", buffer[:4])
        buffer = buffer[4:]

        try:
            file_unique_type = FileUniqueType(file_unique_type)
        except ValueError:
            raise ValueError(
                f"Unknown file_unique_type {file_unique_type} of file_unique_id {file_unique_id}"
            )

        if file_unique_type == FileUniqueType.WEB:
            url_bytes, _ = _read_tl_string(buffer)
            url = url_bytes.decode("utf-8", errors="replace")
            return FileUniqueId(file_unique_type=file_unique_type, url=url)

        if file_unique_type == FileUniqueType.PHOTO:
            if len(buffer) == 12:
                volume_id, local_id = struct.unpack("<qi", buffer[:12])
                return FileUniqueId(
                    file_unique_type=file_unique_type,
                    volume_id=volume_id,
                    local_id=local_id,
                )
            (media_id,) = struct.unpack("<q", buffer[:8])
            return FileUniqueId(file_unique_type=file_unique_type, media_id=media_id)

        if file_unique_type in (
            FileUniqueType.DOCUMENT,
            FileUniqueType.SECURE,
            FileUniqueType.ENCRYPTED,
            FileUniqueType.TEMP,
        ):
            (media_id,) = struct.unpack("<q", buffer[:8])
            return FileUniqueId(file_unique_type=file_unique_type, media_id=media_id)

        raise ValueError(
            f"Unsupported file_unique_type {file_unique_type} of file_unique_id {file_unique_id}"
        )

    def encode(self) -> str:
        """Encode the FileUniqueId instance into a URL-safe base64 string."""
        buffer = bytearray()
        buffer.extend(Int(int(self.file_unique_type)))

        if self.file_unique_type == FileUniqueType.WEB:
            buffer.extend(Bytes((self.url or "").encode("utf-8")))
        elif self.file_unique_type == FileUniqueType.PHOTO:
            if self.volume_id is not None and self.local_id is not None:
                buffer.extend(struct.pack("<qi", self.volume_id, self.local_id))
            else:
                buffer.extend(Long(self.media_id or 0))
        elif self.file_unique_type in (
            FileUniqueType.DOCUMENT,
            FileUniqueType.SECURE,
            FileUniqueType.ENCRYPTED,
            FileUniqueType.TEMP,
        ):
            buffer.extend(Long(self.media_id or 0))

        return b64_encode(rle_encode(buffer))

    @staticmethod
    def from_file_id(file_id: Union[str, FileId]) -> "FileUniqueId":
        """Generate a FileUniqueId directly from a FileId or file_id string."""
        if isinstance(file_id, str):
            file_id = FileId.decode(file_id)

        if file_id.url:
            return FileUniqueId(file_unique_type=FileUniqueType.WEB, url=file_id.url)

        if file_id.file_type in PHOTO_TYPES:
            if file_id.volume_id and file_id.local_id:
                return FileUniqueId(
                    file_unique_type=FileUniqueType.PHOTO,
                    volume_id=file_id.volume_id,
                    local_id=file_id.local_id,
                )
            return FileUniqueId(
                file_unique_type=FileUniqueType.PHOTO,
                media_id=file_id.media_id,
            )

        if file_id.file_type in DOCUMENT_TYPES:
            return FileUniqueId(
                file_unique_type=FileUniqueType.DOCUMENT,
                media_id=file_id.media_id,
            )

        raise ValueError(f"Cannot build FileUniqueId from file_type {file_id.file_type}")

    def __str__(self) -> str:
        return str({k: getattr(self, k) for k in self.__slots__ if getattr(self, k) is not None})

    def __repr__(self) -> str:
        attrs = ", ".join(
            f"{k}={getattr(self, k)!r}"
            for k in self.__slots__
            if getattr(self, k) is not None
        )
        return f"pyrogram.file_id.FileUniqueId({attrs})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FileUniqueId):
            return NotImplemented
        return all(getattr(self, k) == getattr(other, k) for k in self.__slots__)
