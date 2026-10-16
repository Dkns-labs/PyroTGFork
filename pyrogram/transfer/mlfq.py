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

"""Multi-Level Feedback Queue (MLFQ) scheduling for file transfers.

Before this module every queue in the transfer path was plain FIFO: a transfer waited for a
`Semaphore` slot in arrival order and, once admitted, its chunks waited for a connection slot in
arrival order too. Eight big files therefore kept a small file waiting until one of them was
completely done (the convoy effect).

The scheduler works at two points and uses the same rules at both:

- **Admission** (`TransferGate`): replaces the `get_file` / `save_file` semaphores. When a slot
  frees up it goes to the waiting transfer with the best priority, not the oldest one.
- **Chunks** (`MediaPool.acquire`): when connection slots are scarce, a chunk of a transfer that
  has moved little data goes before a chunk of one that has already moved a lot.

The rules:

1. There are `len(QUANTA) + 1` levels, 0 being the highest. A transfer starts at level 0.
2. A `Job` is demoted by the bytes it has moved: level 0 until `QUANTA[0]` bytes, level 1 until
   `QUANTA[1]`, and so on. A chunk (<= 1 MiB) is the natural time slice, so no preemption is
   needed: a demoted transfer simply loses the next slot it competes for.
3. Equal levels are served in arrival order (FIFO inside a level).
4. **Aging.** A waiter is promoted one level for every `AGING` seconds it has waited, so nothing starves.
5. **Boost.** Every `BOOST` seconds a job's counter is reset, which puts long-running transfers
   back on level 0 for a while (classic MLFQ rule 5).
6. **Size hint (admission only).** The size of a transfer is known up front, unlike in a CPU
   scheduler, so the gate orders waiters by the level their size falls into instead of making
   every transfer start at the top.

Environment variables (all optional):

- `PYROGRAM_SCHEDULER=fifo`      switch the whole thing off (old behaviour)
- `PYROGRAM_MLFQ_QUANTA=8,64`    level boundaries in MiB (comma separated, ascending)
- `PYROGRAM_MLFQ_AGING=5`        seconds of waiting per promotion
- `PYROGRAM_MLFQ_BOOST=30`       seconds between counter resets
"""

import asyncio
import itertools
import os
import time
from typing import Optional, Sequence

MiB = 1024 * 1024


def _quanta_from_env() -> tuple:
    raw = os.environ.get("PYROGRAM_MLFQ_QUANTA", "8,64")
    try:
        values = tuple(int(float(x) * MiB) for x in raw.split(",") if x.strip())
    except ValueError:
        values = (8 * MiB, 64 * MiB)

    return tuple(sorted(v for v in values if v > 0)) or (8 * MiB, 64 * MiB)


class Policy:
    """The tunables of the scheduler, read once from the environment."""

    ENABLED = os.environ.get("PYROGRAM_SCHEDULER", "mlfq").lower() != "fifo"
    QUANTA = _quanta_from_env()
    AGING = max(0.1, float(os.environ.get("PYROGRAM_MLFQ_AGING", 5)))
    BOOST = max(1.0, float(os.environ.get("PYROGRAM_MLFQ_BOOST", 30)))

    def __init__(self, enabled=None, quanta: Optional[Sequence[int]] = None, aging=None, boost=None):
        self.enabled = self.ENABLED if enabled is None else enabled
        self.quanta = tuple(quanta) if quanta is not None else self.QUANTA
        self.aging = self.AGING if aging is None else aging
        self.boost = self.BOOST if boost is None else boost

    @property
    def levels(self) -> int:
        return len(self.quanta) + 1 if self.enabled else 1

    def level_for(self, amount: int) -> int:
        """The level a transfer that has moved (or will move) `amount` bytes belongs to."""
        if not self.enabled:
            return 0

        for level, limit in enumerate(self.quanta):
            if amount <= limit:
                return level

        return len(self.quanta)


_sequence = itertools.count()


class Job:
    """One transfer (a download or an upload) as the scheduler sees it."""

    __slots__ = ("policy", "size", "served", "seq", "boosted_at", "name", "inflight", "on_finish")

    def __init__(self, policy: Policy, size: int = 0, name: str = ""):
        self.policy = policy
        self.size = max(0, int(size or 0))  # expected bytes, 0 when unknown
        self.served = 0  # bytes moved since the last boost
        self.seq = next(_sequence)
        self.boosted_at = time.monotonic()
        self.name = name
        self.inflight = 0  # requests of this transfer holding a connection slot
        self.on_finish = None  # called once when the transfer leaves the gate

    def finish(self):
        cb, self.on_finish = self.on_finish, None

        if cb is not None:
            cb(self)

    def add(self, nbytes: int):
        self.served += nbytes

    def level(self, now: Optional[float] = None) -> int:
        """Current level: demoted by the bytes moved, reset by the periodic boost."""
        if not self.policy.enabled:
            return 0

        now = time.monotonic() if now is None else now

        if now - self.boosted_at >= self.policy.boost:
            self.boosted_at = now
            self.served = 0

        return self.policy.level_for(self.served)

    def hint_level(self) -> int:
        """Level implied by the expected size; unknown sizes go to the middle level."""
        if not self.policy.enabled:
            return 0

        if not self.size:
            return min(1, self.policy.levels - 1)

        return self.policy.level_for(self.size)

    def __repr__(self):
        return f"<Job {self.name or self.seq} size={self.size} served={self.served} level={self.level()}>"


def effective_level(base: int, waited: float, policy: Policy) -> int:
    """`base` promoted by the time spent waiting (aging)."""
    if not policy.enabled:
        return 0

    return max(0, base - int(waited / policy.aging))


class _Waiter:
    __slots__ = ("job", "future", "since", "seq", "wake", "force")

    def __init__(self, job: Job, future: Optional[asyncio.Future] = None):
        self.job = job
        self.future = future
        self.wake = None  # per-waiter wake-up event (used by the media pool)
        self.force = False
        self.since = time.monotonic()
        self.seq = next(_sequence)


class TransferGate:
    """Admission control: at most `slots` transfers run at once, best priority first.

    Drop-in replacement for the `asyncio.Semaphore` the client used to hold: `async with gate:`
    still works (the transfer then has no size hint and counts as an unknown-size one), while
    `async with gate.admit(job):` lets the scheduler order the waiters.
    """

    def __init__(self, slots: int, policy: Optional[Policy] = None):
        self.slots = max(1, int(slots))
        self.policy = policy or Policy()
        self.active = 0
        self._waiters = []

    # -- helpers

    def job(self, size: int = 0, name: str = "") -> Job:
        return Job(self.policy, size, name)

    @property
    def waiting(self) -> int:
        return len(self._waiters)

    def _key(self, waiter: _Waiter, now: float):
        level = effective_level(waiter.job.hint_level(), now - waiter.since, self.policy)
        return level, waiter.seq

    def _grant(self):
        """Hand free slots to the best waiters."""
        while self.active < self.slots and self._waiters:
            now = time.monotonic()
            best = min(self._waiters, key=lambda w: self._key(w, now))
            self._waiters.remove(best)

            if best.future.done():  # cancelled between the wake-up and now
                continue

            self.active += 1
            best.future.set_result(None)

    # -- API

    async def acquire(self, job: Optional[Job] = None):
        job = job or self.job()

        if self.active < self.slots and not self._waiters:
            self.active += 1
            return

        waiter = _Waiter(job, asyncio.get_running_loop().create_future())
        self._waiters.append(waiter)

        try:
            await waiter.future
        except asyncio.CancelledError:
            if waiter in self._waiters:
                self._waiters.remove(waiter)
            elif waiter.future.done() and not waiter.future.cancelled():
                # the slot had already been handed to us: give it to the next one
                self.release()

            raise

    def release(self):
        self.active = max(0, self.active - 1)
        self._grant()

    def admit(self, job: Optional[Job] = None):
        return _Admission(self, job)

    async def __aenter__(self):
        await self.acquire()

    async def __aexit__(self, *exc):
        self.release()


class _Admission:
    __slots__ = ("gate", "job")

    def __init__(self, gate: TransferGate, job: Optional[Job]):
        self.gate = gate
        self.job = job

    async def __aenter__(self):
        await self.gate.acquire(self.job)
        return self.job

    async def __aexit__(self, *exc):
        try:
            if self.job is not None:
                self.job.finish()
        finally:
            self.gate.release()
