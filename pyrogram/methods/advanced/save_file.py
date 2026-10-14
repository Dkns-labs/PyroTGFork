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

import asyncio
import functools
import inspect
import io
import logging
import math
import os
from hashlib import md5
from pathlib import Path, PurePath
from typing import Callable, Union

import pyrogram
from pyrogram import StopTransmission, raw
from pyrogram.session import Session

log = logging.getLogger(__name__)


class SaveFile:
    async def _get_upload_sessions(self, count: int) -> list[Session]:
        """ Maintain a persistent pool of warm media upload sessions to avoid repeated TCP/MTProto handshakes. """
        if not hasattr(self, "_upload_session_pool"):
            self._upload_session_pool = []
            self._upload_pool_lock = asyncio.Lock()

        async with self._upload_pool_lock:
            dc_id = await self.storage.dc_id()
            auth_key = await self.storage.auth_key()
            test_mode = await self.storage.test_mode()

            # Remove any dead/disconnected sessions from the pool
            valid_sessions = []
            for s in self._upload_session_pool:
                if getattr(s, "is_Started", None) or getattr(s, "is_connected", True):
                    valid_sessions.append(s)
                else:
                    try:
                        await s.stop()
                    except Exception:
                        pass
            self._upload_session_pool = valid_sessions

            # Spawn missing sessions in parallel if pool is smaller than needed
            missing = count - len(self._upload_session_pool)
            if missing > 0:
                new_sessions = [
                    Session(self, dc_id, auth_key, test_mode, is_media=True)
                    for _ in range(missing)
                ]
                await asyncio.gather(*(s.start() for s in new_sessions))
                self._upload_session_pool.extend(new_sessions)

            return self._upload_session_pool[:count]

    async def save_file(
        self,
        path: Union[str, BinaryIO],
        file_id: int = None,
        file_part: int = 0,
        progress: Callable = None,
        progress_args: tuple = ()
    ):
        """Upload a file onto Telegram servers, without actually sending the message to anyone.
        Useful whenever an InputFile type is required.

        Optimized for maximum throughput:
        - 512 KB maximum MTProto part size
        - Persistent warm upload session pooling
        - Bounded async producer-consumer pipeline for minimal RAM footprint
        """
        async with self.save_file_semaphore:
            if path is None:
                return None

            async def worker(session: Session):
                while True:
                    data = await queue.get()

                    if data is None:
                        queue.task_done()
                        return

                    try:
                        part_index, chunk = data
                        if is_big:
                            rpc = raw.functions.upload.SaveBigFilePart(
                                file_id=file_id,
                                file_part=part_index,
                                file_total_parts=file_total_parts,
                                bytes=chunk
                            )
                        else:
                            rpc = raw.functions.upload.SaveFilePart(
                                file_id=file_id,
                                file_part=part_index,
                                bytes=chunk
                            )

                        await session.invoke(rpc, sleep_threshold=self.sleep_threshold)
                    except Exception as e:
                        log.exception(e)
                    finally:
                        queue.task_done()

            # Telegram's maximum allowed part size is 512 KB (524,288 bytes)
            part_size = 512 * 1024

            if isinstance(path, (str, PurePath)):
                fp = open(path, "rb", buffering=1024 * 1024)
                file_name = Path(path).name
                file_size = os.path.getsize(path)
                close_fp = True
            elif isinstance(path, io.IOBase):
                fp = path
                file_name = getattr(path, "name", "file")
                close_fp = False

                if isinstance(fp, (io.BytesIO, io.StringIO)):
                    file_size = len(fp.getvalue())
                else:
                    current_pos = fp.tell()
                    fp.seek(0, os.SEEK_END)
                    file_size = fp.tell()
                    fp.seek(current_pos, os.SEEK_SET)
            else:
                raise ValueError(f"Invalid file path/object type: {type(path)}")

            if file_size == 0:
                if close_fp:
                    fp.close()
                raise ValueError("File size equals to 0 B")

            file_size_limit_mib = 4000 if getattr(self.me, "is_premium", False) else 2000

            if file_size > file_size_limit_mib * 1024 * 1024:
                if close_fp:
                    fp.close()
                raise ValueError(f"Can't upload files bigger than {file_size_limit_mib} MiB")

            file_total_parts = int(math.ceil(file_size / part_size))
            is_big = file_size > 10 * 1024 * 1024
            is_missing_part = file_id is not None

            if file_id is None:
                file_id = self.rnd_id()

            md5_sum = md5() if not is_big and not is_missing_part else None

            # Scale workers dynamically based on part count and client configuration
            max_workers = max(1, min(16, getattr(self, "max_concurrent_transmissions", 8)))
            workers_count = 1 if is_missing_part else min(max_workers, file_total_parts)

            sessions = await self._get_upload_sessions(workers_count)

            # Bounded queue prevents loading large files entirely into RAM
            queue = asyncio.Queue(maxsize=workers_count * 2)
            workers = [self.loop.create_task(worker(s)) for s in sessions]

            is_coro_progress = inspect.iscoroutinefunction(progress) if progress else False

            try:
                fp.seek(part_size * file_part)

                while True:
                    chunk = fp.read(part_size)

                    if not chunk:
                        if not is_big and not is_missing_part:
                            md5_sum = "".join([hex(i)[2:].zfill(2) for i in md5_sum.digest()])
                        break

                    await queue.put((file_part, chunk))

                    if md5_sum is not None:
                        md5_sum.update(chunk)

                    if is_missing_part:
                        break

                    file_part += 1

                    if progress:
                        func = functools.partial(
                            progress,
                            min(file_part * part_size, file_size),
                            file_size,
                            *progress_args
                        )

                        if is_coro_progress:
                            await func()
                        else:
                            await self.loop.run_in_executor(self.executor, func)
            except StopTransmission:
                raise
            finally:
                if close_fp:
                    fp.close()

                # Signal all workers to exit cleanly
                for _ in workers:
                    await queue.put(None)

                await asyncio.gather(*workers, return_exceptions=True)

            if is_missing_part:
                return

            if is_big:
                return raw.types.InputFileBig(
                    id=file_id,
                    parts=file_total_parts,
                    name=file_name
                )
            else:
                return raw.types.InputFile(
                    id=file_id,
                    parts=file_total_parts,
                    name=file_name,
                    md5_checksum=md5_sum
                )
