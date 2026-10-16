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
import io
import logging
import math
import os
from hashlib import md5
from pathlib import Path, PurePath
from typing import BinaryIO, Callable, Optional, Union

import pyrogram
from pyrogram import StopTransmission, raw
from pyrogram.transfer import ProgressReporter

log = logging.getLogger(__name__)

# Upload workers per connection. Each worker owns one part in flight; the media pool then limits how
# many really go out on each connection at once (its adaptive depth) and gives every part to the
# connection that finishes it soonest, so extra workers only keep that queue full.
# One request per connection makes the speed connections / round-trip-time (8 connections at 150 ms
# RTT cannot exceed ~27 MB/s however fast the link is). PYROGRAM_UL_DEPTH=<n>
UPLOAD_DEPTH = max(1, int(os.environ.get("PYROGRAM_UL_DEPTH", 4)))

# Parts read from disk per call. Reads run on a worker thread so a slow disk, network mount or
# SD card cannot freeze the event loop (and with it every other transfer and handler).
READ_BLOCK_PARTS = 8


def _read_full(fp, size: int) -> bytes:
    """Read exactly `size` bytes, or fewer only at EOF. A short read in the middle of the file
    would shift every following part boundary and corrupt the upload."""
    data = fp.read(size)

    if len(data) == size or not data:
        return data

    chunks = [data]
    remaining = size - len(data)

    while remaining > 0:
        more = fp.read(remaining)

        if not more:
            break

        chunks.append(more)
        remaining -= len(more)

    return b"".join(chunks)


def _expected_size(path, part_size: int, file_part: int) -> int:
    """Best-effort size of what an upload is going to send, for the scheduler (0 = unknown)."""
    try:
        if isinstance(path, (str, PurePath)):
            total = os.path.getsize(path)
        elif isinstance(path, (io.BytesIO, io.StringIO)):
            total = len(path.getvalue())
        elif isinstance(path, io.IOBase) and path.seekable():
            here = path.tell()
            total = path.seek(0, os.SEEK_END)
            path.seek(here, os.SEEK_SET)
        else:
            return 0
    except (OSError, ValueError):
        return 0

    return max(0, total - part_size * file_part)


class SaveFile:
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
        if path is None:
            return None

        # What this upload is going to send, so the scheduler can let small ones pass big ones
        job = self.save_file_semaphore.job(
            _expected_size(path, 512 * 1024, file_part),
            name=f"ul:{getattr(path, 'name', path)}",
        )

        async with self.save_file_semaphore.admit(job):

            done_bytes = [0]  # bytes Telegram has acknowledged (progress follows this, not the read side)
            reporter = None

            pool = self.media_pool
            home_dc = None

            async def send_part(part_index: int, chunk: bytes):
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

                # The pool picks the connection, re-sends a stalled part elsewhere and retries
                # failures on other connections; a part is idempotent, so a duplicate is harmless.
                await pool.request(home_dc, rpc, idx=part_index, job=job)
                job.add(len(chunk))  # the more a transfer has moved, the lower its priority

            async def worker():
                while True:
                    data = await queue.get()

                    if data is None:
                        queue.task_done()
                        return

                    part_index, chunk = data

                    try:
                        # The upload is already lost (or was stopped from the progress callback):
                        # don't spend bandwidth on the remaining parts
                        if errors or (reporter is not None and reporter.error is not None):
                            continue

                        try:
                            await send_part(part_index, chunk)
                        except Exception as e:
                            # Remember the failure: a lost part must fail the upload, not be skipped silently
                            log.error("Upload of part %s failed: %r", part_index, e)
                            errors.append(e)
                        else:
                            done_bytes[0] += len(chunk)

                            if reporter is not None:
                                reporter.poke()
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

            # Uploads go to the home DC over the same pool downloads use (warm connections are shared);
            # it returns once the first connection is up and the rest join while parts are flowing.
            home_dc = await self.storage.dc_id()
            await pool.ensure(home_dc, workers_count)

            tasks_count = 1 if is_missing_part else min(workers_count * UPLOAD_DEPTH, file_total_parts)

            # Bounded queue prevents loading large files entirely into RAM
            queue: asyncio.Queue = asyncio.Queue(maxsize=tasks_count * 2)
            errors: list = []
            workers = [self.loop.create_task(worker()) for _ in range(tasks_count)]

            if progress and not is_missing_part:
                base = part_size * file_part
                reporter = ProgressReporter(
                    self, progress, progress_args, file_size, lambda: base + done_bytes[0]
                )

            ok = False

            # Real files are read a block at a time on a worker thread; in-memory buffers are
            # already in RAM, so a thread hop would only add latency.
            offload_reads = not isinstance(fp, (io.BytesIO, io.StringIO))
            block_size = part_size * (1 if is_missing_part else READ_BLOCK_PARTS)

            async def read_parts():
                while True:
                    if offload_reads:
                        block = await self.loop.run_in_executor(self.executor, _read_full, fp, block_size)
                    else:
                        block = _read_full(fp, block_size)

                    if not block:
                        return

                    for start in range(0, len(block), part_size):
                        yield block[start:start + part_size]

            parts = read_parts()

            try:
                fp.seek(part_size * file_part)

                async for chunk in parts:
                    await queue.put((file_part, chunk))

                    if errors:
                        break

                    if md5_sum is not None:
                        md5_sum.update(chunk)

                    if is_missing_part:
                        break

                    file_part += 1

                    if reporter is not None:
                        reporter.check()  # re-raises e.g. StopTransmission from the callback
                        reporter.poke()
                else:
                    # reached EOF (no break): the checksum is complete
                    if not is_big and not is_missing_part:
                        md5_sum = md5_sum.hexdigest()

                ok = True
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
                await parts.aclose()

                if close_fp:
                    fp.close()

                # Signal all workers to exit cleanly
                for _ in workers:
                    await queue.put(None)

                await asyncio.gather(*workers, return_exceptions=True)

                if reporter is not None and not ok:
                    reporter.abort()

            if errors:
                if reporter is not None:
                    reporter.abort()

                raise errors[0]

            if reporter is not None:
                await reporter.close()  # final value: every part acknowledged

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
