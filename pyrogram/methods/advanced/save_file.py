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
from typing import BinaryIO, Callable, Optional, Union

import pyrogram
from pyrogram import StopTransmission, raw
from pyrogram.session import Session

log = logging.getLogger(__name__)


class SaveFile:
    async def _get_upload_sessions(self, count: int) -> list[Session]:
        """Maintain a persistent pool of warm media upload sessions to avoid repeated TCP/MTProto handshakes."""
        if not hasattr(self, "_upload_session_pool"):
            self._upload_session_pool = []
            self._upload_pool_lock = asyncio.Lock()

        async with self._upload_pool_lock:
            dc_id = await self.storage.dc_id()
            auth_key = await self.storage.auth_key()
            test_mode = await self.storage.test_mode()

            # Only hand out sessions that are connected right now. (`is_connected` is an
            # asyncio.Event, so it must be checked with is_set(), never by truthiness.)
            # A reconnecting session heals itself and is reused once it is back.
            usable = [s for s in self._upload_session_pool if s.is_connected.is_set()]

            # Spawn missing sessions in parallel; one failing to start must not lose the rest
            missing = count - len(usable)
            if missing > 0:
                new_sessions = [
                    Session(self, dc_id, auth_key, test_mode, is_media=True)
                    for _ in range(missing)
                ]
                results = await asyncio.gather(
                    *(s.start() for s in new_sessions), return_exceptions=True
                )

                for s, res in zip(new_sessions, results):
                    if isinstance(res, BaseException):
                        log.warning("Upload session failed to start: %r", res)
                    else:
                        self._upload_session_pool.append(s)
                        usable.append(s)

            if not usable:
                raise ConnectionError("No upload session could be started")

            return usable[:count]

    async def save_file(
        self: "pyrogram.Client",
        path: Union[str, PurePath, BinaryIO],
        file_id: Optional[int] = None,
        file_part: int = 0,
        progress: Optional[Callable] = None,
        progress_args: tuple = (),
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
                                bytes=chunk,
                            )
                        else:
                            rpc = raw.functions.upload.SaveFilePart(
                                file_id=file_id,
                                file_part=part_index,
                                bytes=chunk,
                            )

                        await session.invoke(
                            rpc,
                            timeout=Session.MEDIA_WAIT_TIMEOUT,
                            sleep_threshold=self.sleep_threshold,
                        )
                    except Exception as e:
                        # Remember the failure: a lost part must fail the upload, not be skipped silently
                        log.error("Upload of part %s failed: %r", data[0], e)
                        errors.append(e)
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
            # Parallel upload connections; PYROGRAM_UL_WORKERS overrides (1-32), useful on high-latency links
            max_workers = int(os.environ.get("PYROGRAM_UL_WORKERS", 0)) or getattr(self, "max_concurrent_transmissions", 8)
            max_workers = max(1, min(32, max_workers))
            workers_count = 1 if is_missing_part else min(max_workers, file_total_parts)

            sessions = await self._get_upload_sessions(workers_count)

            # Bounded queue prevents loading large files entirely into RAM
            queue: asyncio.Queue = asyncio.Queue(maxsize=workers_count * 2)
            errors: list = []
            workers =[self.loop.create_task(worker(s)) for s in sessions]

            is_coro_progress = inspect.iscoroutinefunction(progress) if progress else False

            try:
                fp.seek(part_size * file_part)

                while True:
                    chunk = fp.read(part_size)

                    if not chunk:
                        if not is_big and not is_missing_part:
                            md5_sum = md5_sum.hexdigest()
                        break

                    await queue.put((file_part, chunk))

                    if errors:
                        break

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
                            *progress_args,
                        )

                        if is_coro_progress:
                            await func()
                        else:
                            await self.loop.run_in_executor(self.executor, func)
            except StopTransmission:
                # Drain pending queue items so sentinel puts never block on cancellation
                while not queue.empty():
                    try:
                        queue.get_nowait()
                        queue.task_done()
                    except asyncio.QueueEmpty:
                        break
                raise
            finally:
                if close_fp:
                    fp.close()

                # Signal all workers to exit cleanly
                for _ in workers:
                    await queue.put(None)

                await asyncio.gather(*workers, return_exceptions=True)

            if errors:
                raise errors[0]

            if is_missing_part:
                return None

            if is_big:
                return raw.types.InputFileBig(
                    id=file_id,
                    parts=file_total_parts,
                    name=file_name,
                )
            else:
                return raw.types.InputFile(
                    id=file_id,
                    parts=file_total_parts,
                    name=file_name,
                    md5_checksum=md5_sum,
                )
