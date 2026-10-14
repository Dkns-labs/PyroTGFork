#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  Optimized for ultra-fast + ultra-stable uploads (Layer 230)

import asyncio
import functools
import inspect
import io
import logging
import math
import os
from hashlib import md5
from pathlib import PurePath
from typing import Union, BinaryIO, Callable

import pyrogram
from pyrogram import StopTransmission
from pyrogram import raw
from pyrogram.session import Session

log = logging.getLogger(__name__)


class SaveFile:
    async def save_file(
        self: "pyrogram.Client",
        path: Union[str, BinaryIO],
        file_id: int = None,
        file_part: int = 0,
        progress: Callable = None,
        progress_args: tuple = ()
    ):
        async with self.save_file_semaphore:
            if path is None:
                return None

            is_big = False
            part_size = 512 * 1024          # 512 KiB - best balance of speed & stability
            file_size = 0

            if isinstance(path, (str, PurePath)):
                file_size = os.path.getsize(path)
            elif isinstance(path, (BinaryIO, io.BytesIO, io.BufferedReader)):
                file_size = path.seek(0, os.SEEK_END)
                path.seek(0)
            else:
                raise ValueError("Invalid file type")

            if file_size > 10 * 1024 * 1024:          # > 10 MB → big file
                is_big = True
                part_size = 512 * 1024
            if file_size > 100 * 1024 * 1024:         # > 100 MB
                part_size = 1024 * 1024              # 1 MB
            if file_size > 1024 * 1024 * 1024:        # > 1 GB
                part_size = 2 * 1024 * 1024          # 2 MB

            file_total_parts = math.ceil(file_size / part_size)
            file_id = file_id or self.rnd_id()
            bytes_read = 0
            md5_hash = md5() if not is_big else None
            session = Session(
                self, await self.storage.dc_id(),
                await self.storage.auth_key(),
                await self.storage.test_mode(), is_media=True
            )
            await session.start()

            try:
                with open(path, "rb") if isinstance(path, (str, PurePath)) else path as f:
                    f.seek(part_size * file_part)

                    while True:
                        chunk = f.read(part_size)
                        if not chunk:
                            break

                        if is_big:
                            r = await session.invoke(
                                raw.functions.upload.SaveBigFilePart(
                                    file_id=file_id,
                                    file_part=file_part,
                                    file_total_parts=file_total_parts,
                                    bytes=chunk
                                )
                            )
                        else:
                            r = await session.invoke(
                                raw.functions.upload.SaveFilePart(
                                    file_id=file_id,
                                    file_part=file_part,
                                    bytes=chunk
                                )
                            )
                            md5_hash.update(chunk)

                        if not r:
                            raise RuntimeError(f"Upload failed at part {file_part}")

                        bytes_read += len(chunk)
                        file_part += 1

                        if progress:
                            try:
                                if inspect.iscoroutinefunction(progress):
                                    await progress(bytes_read, file_size, *progress_args)
                                else:
                                    progress(bytes_read, file_size, *progress_args)
                            except Exception:
                                pass

                        if len(chunk) < part_size:
                            break

            except (OSError, asyncio.CancelledError, StopTransmission):
                raise
            finally:
                await session.stop()

            if is_big:
                return raw.types.InputFileBig(
                    id=file_id,
                    parts=file_total_parts,
                    name=getattr(path, "name", "file") if not isinstance(path, str) else os.path.basename(path)
                )
            else:
                return raw.types.InputFile(
                    id=file_id,
                    parts=file_total_parts,
                    name=getattr(path, "name", "file") if not isinstance(path, str) else os.path.basename(path),
                    md5_checksum=md5_hash.hexdigest()
                )
