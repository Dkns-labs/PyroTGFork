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


"""Connections for file transfers, shared by downloads and uploads.

One `MediaPool` owns every media session of a client. Both directions go through `request()`,
which gives them the same behaviour:

- **Slots.** Every connection accepts a limited number of requests at a time (its *depth*).
  Further requests wait, in order, for the next free slot.
- **Work stealing.** A free slot goes to the connection that would finish the request soonest,
  and a request prefers to wait for a fast connection over being given to a much slower one. A
  connection twice as fast therefore carries about twice the data, and the slowest connection no
  longer sets the pace of the whole transfer.
- **Adaptive depth.** Each connection's depth follows what it can actually sustain: it grows
  while the connection is saturated and its latency stays flat, and shrinks when requests start
  queueing behind each other (the TCP Vegas idea, counting queued requests).
- **Hedging.** A request that takes much longer than recent ones is sent again over another
  connection and the first answer wins, so one silent connection cannot stall a transfer.
- **Failover.** A failed request is retried on a different connection, and dead sessions are
  replaced.
"""

import asyncio
import logging
import os
import weakref
from collections import deque

from pyrogram import raw
from pyrogram.errors import AuthBytesInvalid, InternalServerError, ServiceUnavailable
from pyrogram.session import Session
from pyrogram.session.auth import Auth

log = logging.getLogger(__name__)


class Conn:
    """Scheduling state of one session."""

    __slots__ = ("inflight", "seconds", "depth", "recent", "since_change")

    def __init__(self, depth: int):
        self.inflight = 0
        self.seconds = None  # smoothed seconds per request (latency on the wire)
        self.depth = depth
        self.recent = deque(maxlen=128)  # recent wire times; their minimum approximates the idle latency
        self.since_change = 0


class MediaPool:
    RETRIES = max(1, int(os.environ.get("PYROGRAM_CHUNK_RETRIES", 4)))

    # Adaptive depth stays within [min(2, start), max(DEPTH_MAX, start)].
    # PYROGRAM_DEPTH_MAX=<n>; PYROGRAM_ADAPTIVE_DEPTH=0 keeps the starting depth fixed.
    DEPTH_MAX = max(1, int(os.environ.get("PYROGRAM_DEPTH_MAX", 8)))
    ADAPTIVE = os.environ.get("PYROGRAM_ADAPTIVE_DEPTH", "1") != "0"

    # Queued requests per connection that adaptive depth aims for: below LOW the connection is
    # under-used (grow), above HIGH requests wait behind each other for nothing (shrink).
    QUEUE_LOW = 1.0
    QUEUE_HIGH = 3.0

    # RPC errors that will not get better by asking again.
    FATAL = ("VOLUME_LOC_NOT_FOUND",)
    RETRYABLE = (OSError, TimeoutError, asyncio.TimeoutError, InternalServerError, ServiceUnavailable)

    def __init__(self, client):
        self.client = client
        self.loop = None

        # The names the rest of the library already uses (stop(), terminate(), inline sessions)
        self.sessions = {}  # dc_id -> the regular cached session
        self.pools = {}  # dc_id -> [Session, ...] every parallel connection, the cached one first
        self.lock = asyncio.Lock()

        self._dc_locks = {}
        self._growth = {}
        self._tasks = set()
        self._conns = weakref.WeakKeyDictionary()
        self._slot_events = {}
        self._durations = {}

    # ------------------------------------------------------------------ helpers

    def _spawn(self, coro) -> asyncio.Task:
        """create_task() that keeps a strong reference until the task is done."""
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _dc_lock(self, dc_id: int) -> asyncio.Lock:
        lock = self._dc_locks.get(dc_id)

        if lock is None:
            lock = self._dc_locks[dc_id] = asyncio.Lock()

        return lock

    @staticmethod
    async def _quiet_stop(session):
        try:
            await session.stop()
        except Exception as e:
            log.debug("Ignored error while stopping a media session: %r", e)

    def conn(self, session) -> Conn:
        c = self._conns.get(session)

        if c is None:
            c = self._conns[session] = Conn(self.client.DOWNLOAD_PIPELINE_DEPTH)

        return c

    def healthy(self, dc_id: int) -> list:
        return [s for s in self.pools.get(dc_id, ()) if s.failure is None]

    def capacity(self, dc_id: int) -> int:
        """How many requests the live connections of a DC can have in flight together."""
        return max(1, sum(self.conn(s).depth for s in self.healthy(dc_id)))

    # ------------------------------------------------------------------ sessions

    def evict(self, dc_id: int, session):
        """Forget a dead session and close it in the background."""
        if self.sessions.get(dc_id) is session:
            del self.sessions[dc_id]

        pool = self.pools.get(dc_id)

        if pool and session in pool:
            pool.remove(session)

        log.warning("Dropping dead media session for DC%s: %r", dc_id, session.failure)
        self._spawn(self._quiet_stop(session))
        self._wake(dc_id)

    async def create_session(self, dc_id: int) -> Session:
        client = self.client
        storage_dc_id = await client.storage.dc_id()
        test_mode = await client.storage.test_mode()

        auth_key = (
            await Auth(client, dc_id, test_mode).create()
            if dc_id != storage_dc_id
            else await client.storage.auth_key()
        )

        session = Session(client, dc_id, auth_key, test_mode, is_media=True)
        await session.start()

        if dc_id != storage_dc_id:
            for _ in range(3):
                exported_auth = await client.invoke(raw.functions.auth.ExportAuthorization(dc_id=dc_id))

                try:
                    await session.invoke(
                        raw.functions.auth.ImportAuthorization(id=exported_auth.id, bytes=exported_auth.bytes)
                    )
                except AuthBytesInvalid:
                    continue
                else:
                    break
            else:
                await session.stop()
                raise AuthBytesInvalid

        return session

    async def primary(self, dc_id: int) -> Session:
        """The cached media session of a DC, with cross-DC auth export.

        A cached session whose background reconnect gave up is replaced instead of being handed
        out again. Creation is serialized per DC, so a slow first connection to one DC does not
        hold up transfers on another.
        """
        session = self.sessions.get(dc_id)

        if session is not None and session.failure is None:
            return session

        async with self._dc_lock(dc_id):
            session = self.sessions.get(dc_id)

            if session is not None and session.failure is None:
                return session

            if session is not None:
                self.evict(dc_id, session)

            session = await self.client._create_media_session(dc_id)

            async with self.lock:
                current = self.sessions.get(dc_id)

                if current is not None and current is not session and current.failure is None:
                    keep = current  # another code path (inline sessions) registered one meanwhile
                else:
                    self.sessions[dc_id] = session
                    keep = session

            if keep is not session:
                await self._quiet_stop(session)

            pool = self.pools.setdefault(dc_id, [])

            if keep not in pool:
                pool.insert(0, keep)

            self._wake(dc_id)

            return keep

    async def ensure(self, dc_id: int, count: int) -> list:
        """The warm sessions of a DC, growing the pool towards `count` in the background.

        Never delays the caller waiting for extra connections: they join as soon as they are up.
        Extra sessions reuse the same auth key, so no new authorization export is needed.
        """
        early = False

        if count > 1 and dc_id not in self.sessions and not self.pools.get(dc_id):
            # The home DC's auth key is already known, so the extra connections can handshake while
            # the first one does, instead of one handshake later.
            task = self._growth.get(dc_id)

            if (task is None or task.done()) and dc_id == await self.client.storage.dc_id():
                self._growth[dc_id] = self._spawn(self._grow(dc_id, count, early=True))
                early = True

        first = await self.primary(dc_id)
        pool = self.pools.setdefault(dc_id, [])

        for s in list(pool):
            if s.failure is not None:
                self.evict(dc_id, s)

        if first not in pool:
            pool.insert(0, first)

        if len(pool) < count and not early:
            task = self._growth.get(dc_id)

            if task is None or task.done():
                self._growth[dc_id] = self._spawn(self._grow(dc_id, count))

        return list(pool)

    async def _grow(self, dc_id: int, count: int, early: bool = False):
        batch = []

        try:
            for _ in range(2):  # one retry round if some extra connections fail to start
                first = self.sessions.get(dc_id)
                pool = self.pools.setdefault(dc_id, [])

                if first is None and not early:
                    return

                # while the first connection is still starting, it is one of the `count`
                missing = count - sum(1 for s in pool if s.failure is None) - (1 if first is None else 0)

                if missing <= 0:
                    return

                test_mode = await self.client.storage.test_mode()
                auth_key = first.auth_key if first is not None else await self.client.storage.auth_key()
                batch = [Session(self.client, dc_id, auth_key, test_mode, is_media=True) for _ in range(missing)]
                started = 0

                async def bring_up(s):
                    # each connection joins the moment it is up: one slow handshake must not hold
                    # back the others
                    nonlocal started

                    try:
                        await s.start()
                    except Exception as e:
                        log.warning("Extra media session for DC%s failed to start: %r", dc_id, e)
                        return

                    if self.pools.get(dc_id) is pool:
                        pool.append(s)
                        started += 1
                        self._wake(dc_id)
                    else:
                        await self._quiet_stop(s)  # the pool was closed meanwhile

                await asyncio.gather(*(bring_up(s) for s in batch))

                batch = []
                self._wake(dc_id)
                early = False

                if not started:
                    return
        except asyncio.CancelledError:
            await asyncio.gather(*(self._quiet_stop(s) for s in batch))
            raise
        except Exception as e:
            log.warning("Growing the media session pool for DC%s failed: %r", dc_id, e)

    async def cancel_background(self):
        """Stop pool growth before sessions are torn down (used by stop/terminate)."""
        tasks = [t for t in self._growth.values() if not t.done()]

        for t in tasks:
            t.cancel()

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self._growth.clear()

    async def close(self):
        """Close every media session."""
        await self.cancel_background()

        every = list(self.sessions.values())

        for pool in self.pools.values():
            every.extend(s for s in pool if s not in every)

        if every:
            await asyncio.gather(*(s.stop() for s in every), return_exceptions=True)

        self.sessions.clear()
        self.pools.clear()

    # ------------------------------------------------------------------ scheduling

    def _wake(self, dc_id: int):
        event = self._slot_events.get(dc_id)

        if event is not None:
            event.set()

    def best(self, dc_id: int, idx: int, avoid=(), ignore_slots: bool = False):
        """The connection that would finish a new request soonest, or None if none is worth using.

        Estimated finish = (requests in flight + 1) x its recent seconds per request.
        """
        pool = self.healthy(dc_id)

        if not pool:
            return None

        known = [c.seconds for s in pool if (c := self._conns.get(s)) and c.seconds]
        default = sum(known) / len(known) if known else 1.0

        connected = [s for s in pool if s.is_connected.is_set()] or pool
        candidates = [s for s in connected if s not in avoid] or connected
        n = len(candidates)
        best = best_score = overall = None

        for k in range(n):
            s = candidates[(idx + k) % n]  # equal scores rotate instead of piling onto one connection
            c = self.conn(s)
            score = (c.inflight + 1) * (c.seconds or default)

            if overall is None or score < overall:
                overall = score  # soonest finish anywhere, even where the slots are full

            if not ignore_slots and c.inflight >= c.depth and s.is_connected.is_set():
                continue

            if best is None or score < best_score:
                best, best_score = s, score

        # Giving a request to a slow connection only because a fast one is momentarily full would
        # make it the one the whole transfer waits for. Wait for the fast one instead.
        if best is not None and not ignore_slots and best_score > 2.0 * overall:
            return None

        return best

    async def acquire(self, dc_id: int, idx: int, avoid=(), force: bool = False) -> Session:
        """Reserve a request slot on the best connection, waiting while all of them are full.

        `force` skips the slot limit; used for the duplicate of a stalled request, which must not
        wait behind the very queue it is trying to bypass.
        """
        event = self._slot_events.get(dc_id)

        if event is None:
            event = self._slot_events[dc_id] = asyncio.Event()

        while True:
            for s in list(self.pools.get(dc_id, ())):
                if s.failure is not None:
                    self.evict(dc_id, s)

            session = self.best(dc_id, idx, avoid, ignore_slots=force)

            if session is None and not self.pools.get(dc_id):
                session = await self.primary(dc_id)

            if session is not None:
                self.conn(session).inflight += 1
                return session

            event.clear()  # nothing awaited since the check above, so a release cannot be missed
            await event.wait()

    def release(self, session, dc_id: int, took: float = None):
        c = self.conn(session)
        saturated = c.inflight >= c.depth
        c.inflight = max(0, c.inflight - 1)

        if took is not None:
            c.seconds = took if c.seconds is None else 0.7 * c.seconds + 0.3 * took
            c.recent.append(took)

            if self.ADAPTIVE:
                self._adapt(c, saturated)

        self._wake(dc_id)

    def _adapt(self, c: Conn, saturated: bool):
        """Vegas-style depth control: aim for QUEUE_LOW..QUEUE_HIGH queued requests per connection.

        queued = depth x (1 - idle latency / current latency). Flat latency means more requests
        in flight are free (grow); latency that rises with the depth means they only queue.
        """
        c.since_change += 1

        if c.since_change < c.depth or not saturated or not c.seconds:
            return  # let the last change show up in the latency first; idle connections stay put

        queued = c.depth * (1 - min(c.recent) / c.seconds)
        start = self.client.DOWNLOAD_PIPELINE_DEPTH
        low, high = min(2, start), max(self.DEPTH_MAX, start)

        if queued < self.QUEUE_LOW and c.depth < high:
            c.depth += 1
            c.since_change = 0
        elif queued > self.QUEUE_HIGH and c.depth > low:
            c.depth -= 1
            c.since_change = 0

    # ------------------------------------------------------------------ requests

    def _hedge_limit(self, dc_id: int, rpc) -> float:
        floor = (
            self.client.DOWNLOAD_HEDGE_AFTER
            if isinstance(rpc, raw.functions.upload.GetFile)
            else self.client.UPLOAD_HEDGE_AFTER
        )

        if not floor:
            return 0

        seen = self._durations.get((dc_id, type(rpc))) or ()

        if len(seen) < 8:
            # Pace still being learned. The first requests of a connection queue behind each other
            # (a 1 MiB answer can take a while on a slow link) and their answers come in one by one,
            # so be patient rather than trigger-happy.
            return max(floor * 3, 3.0, 3 * max(seen, default=0))

        # A stall is a request much slower than recent ones, not slower than the gaps between
        # answers (parallel connections make those tiny even on a slow link, which would hedge
        # everything). Slow but steady links raise the bar by themselves.
        return max(floor, 2.5 * sorted(seen)[len(seen) * 3 // 4])

    def _record(self, dc_id: int, rpc, took: float):
        seen = self._durations.get((dc_id, type(rpc)))

        if seen is None:
            seen = self._durations[(dc_id, type(rpc))] = deque(maxlen=64)

        seen.append(took)

    async def _race(self, dc_id: int, session, rpc, idx: int, avoid):
        """Run `rpc` on `session` (a slot is already held), racing a duplicate if it stalls."""
        loop = asyncio.get_running_loop()
        held = []  # [session, task, started, took]: every slot taken here, released in `finally`

        def start(s):
            task = loop.create_task(
                s.invoke(
                    rpc,
                    retries=2,
                    timeout=Session.MEDIA_WAIT_TIMEOUT,
                    sleep_threshold=self.client.sleep_threshold,
                )
            )
            held.append([s, task, loop.time(), None])

        try:
            start(session)
            limit = self._hedge_limit(dc_id, rpc)
            done, _ = await asyncio.wait({held[0][1]}, timeout=limit or None)

            if not done and limit:
                other = self.best(dc_id, idx + 1, (session, *avoid), ignore_slots=True)

                if other is not None and other is not session:
                    log.info("Request stalled for %.1fs on DC%s: racing it on another connection", limit, dc_id)
                    self.conn(other).inflight += 1  # no await since best(): nobody else took the slot
                    start(other)

            pending = {h[1] for h in held}
            error = None

            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                for t in done:
                    h = next(h for h in held if h[1] is t)

                    if t.cancelled():
                        continue

                    exc = t.exception()

                    if exc is None:
                        h[3] = loop.time() - h[2]
                        self._record(dc_id, rpc, h[3])

                        return t.result()

                    if not isinstance(exc, self.RETRYABLE) or getattr(exc, "ID", None) in self.FATAL:
                        raise exc

                    if h[0].failure is not None:
                        self.evict(dc_id, h[0])

                    error = exc

            raise error if error is not None else TimeoutError("request was cancelled")
        finally:
            for s, task, _, took in held:
                if not task.done():
                    task.cancel()
                    task.add_done_callback(lambda t: t.cancelled() or t.exception())

                self.release(s, dc_id, took)

    async def request(self, dc_id: int, rpc, *, idx: int = 0, avoid=(), force: bool = False):
        """Send `rpc` over the best connection of a DC, with hedging and failover to other ones.

        `idx` only spreads equal choices; `avoid` lists connections to stay away from; `force` skips
        the slot limit (used for the first burst, before the extra connections exist).
        """
        last_error = None
        tried = []

        for attempt in range(self.RETRIES):
            session = await self.acquire(dc_id, idx + attempt, (*avoid, *tried), force=force)

            try:
                return await self._race(dc_id, session, rpc, idx + attempt, (*avoid, *tried))
            except self.RETRYABLE as e:
                if getattr(e, "ID", None) in self.FATAL:
                    raise

                last_error = e
                tried.append(session)

                (log.warning if attempt else log.info)(
                    "%s failed on DC%s (attempt %s/%s): %r",
                    type(rpc).__name__, dc_id, attempt + 1, self.RETRIES, e,
                )

            await asyncio.sleep(min(0.25 * 2 ** attempt, 2.0))  # after the slot is given back

        raise last_error
