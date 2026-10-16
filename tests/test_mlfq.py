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

"""Offline tests for the MLFQ transfer scheduler (pyrogram/transfer/mlfq.py)."""

import asyncio
import os

from pyrogram.transfer import Job, Policy, TransferGate

from .test_transfer import FakeSession, MB, download, make_client, run, use_sessions

QUANTA = (1 * MB, 10 * MB)


def policy(**kw):
    kw.setdefault("quanta", QUANTA)
    kw.setdefault("aging", 1000)
    kw.setdefault("boost", 1000)
    return Policy(enabled=kw.pop("enabled", True), **kw)


# ---------------------------------------------------------------------------------------------
# Policy and Job
# ---------------------------------------------------------------------------------------------

def test_levels_follow_the_bytes_a_transfer_has_moved():
    p = policy()
    job = Job(p)

    assert p.levels == 3
    assert job.level() == 0

    job.add(1 * MB)
    assert job.level() == 0  # the boundary itself still belongs to the upper level

    job.add(1)
    assert job.level() == 1

    job.add(10 * MB)
    assert job.level() == 2


def test_disabled_policy_is_a_single_level():
    p = policy(enabled=False)
    job = Job(p, size=500 * MB)
    job.add(500 * MB)

    assert p.levels == 1
    assert job.level() == 0
    assert job.hint_level() == 0


def test_boost_puts_a_long_transfer_back_on_top():
    p = policy(boost=0.05)
    job = Job(p)
    job.add(50 * MB)
    assert job.level() == 2

    import time
    time.sleep(0.07)

    assert job.level() == 0
    assert job.served == 0


def test_unknown_size_hint_is_the_middle_level():
    p = policy()

    assert Job(p, size=0).hint_level() == 1
    assert Job(p, size=100 * 1024).hint_level() == 0
    assert Job(p, size=5 * MB).hint_level() == 1
    assert Job(p, size=500 * MB).hint_level() == 2


# ---------------------------------------------------------------------------------------------
# Admission gate
# ---------------------------------------------------------------------------------------------

async def _admit_in_order(gate, jobs, hold_for=0.02):
    """Fill the only slot, queue `jobs` in the given order, free the slot, return the admission order."""
    order = []

    async def transfer(name, job):
        async with gate.admit(job):
            order.append(name)
            await asyncio.sleep(0)

    holder = Job(gate.policy)
    await gate.acquire(holder)

    tasks = []

    for name, job in jobs:
        tasks.append(asyncio.ensure_future(transfer(name, job)))
        await asyncio.sleep(hold_for / 10)  # make the arrival order unambiguous

    assert gate.waiting == len(jobs)
    gate.release()
    await asyncio.gather(*tasks)

    return order


def test_gate_lets_a_small_transfer_pass_big_ones_that_arrived_first():
    async def main():
        p = policy()
        gate = TransferGate(1, p)

        return await _admit_in_order(gate, [
            ("big", Job(p, size=500 * MB)),
            ("medium", Job(p, size=5 * MB)),
            ("small", Job(p, size=100 * 1024)),
        ])

    assert run(main()) == ["small", "medium", "big"]


def test_gate_is_fifo_inside_a_level():
    async def main():
        p = policy()
        gate = TransferGate(1, p)

        return await _admit_in_order(gate, [
            ("first", Job(p, size=2 * MB)),
            ("second", Job(p, size=3 * MB)),
            ("third", Job(p, size=4 * MB)),
        ])

    assert run(main()) == ["first", "second", "third"]


def test_gate_in_fifo_mode_keeps_arrival_order():
    async def main():
        p = policy(enabled=False)
        gate = TransferGate(1, p)

        return await _admit_in_order(gate, [
            ("big", Job(p, size=500 * MB)),
            ("small", Job(p, size=100 * 1024)),
        ])

    assert run(main()) == ["big", "small"]


def test_waiting_promotes_a_big_transfer_so_it_cannot_starve():
    async def main():
        p = policy(aging=0.05)
        gate = TransferGate(1, p)
        order = []

        async def transfer(name, job):
            async with gate.admit(job):
                order.append(name)

        await gate.acquire(Job(p))

        big = asyncio.ensure_future(transfer("big", Job(p, size=500 * MB)))  # level 2
        await asyncio.sleep(0.12)  # two promotions: level 0 now
        small = asyncio.ensure_future(transfer("small", Job(p, size=100 * 1024)))
        await asyncio.sleep(0.01)

        gate.release()
        await asyncio.gather(big, small)

        return order

    assert run(main()) == ["big", "small"]


def test_gate_does_not_leak_a_slot_when_a_waiter_is_cancelled():
    async def main():
        p = policy()
        gate = TransferGate(1, p)

        await gate.acquire(Job(p))
        waiter = asyncio.ensure_future(gate.acquire(Job(p, size=MB)))
        await asyncio.sleep(0.01)

        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)
        assert gate.waiting == 0

        gate.release()
        assert gate.active == 0

        await asyncio.wait_for(gate.acquire(Job(p)), 1)  # the slot is free again
        assert gate.active == 1

    run(main())


def test_gate_gives_the_slot_on_when_the_winner_was_cancelled_after_the_grant():
    async def main():
        p = policy()
        gate = TransferGate(1, p)

        await gate.acquire(Job(p))
        first = asyncio.ensure_future(gate.acquire(Job(p, size=MB)))
        second = asyncio.ensure_future(gate.acquire(Job(p, size=MB)))
        await asyncio.sleep(0.01)

        gate.release()  # granted to `first`, which is cancelled before it runs
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        await asyncio.wait_for(second, 1)

        assert gate.active == 1

    run(main())


def test_gate_still_works_as_a_plain_semaphore_replacement():
    async def main():
        gate = TransferGate(2, policy())
        running = peak = 0

        async def work():
            nonlocal running, peak
            async with gate:
                running += 1
                peak = max(peak, running)
                await asyncio.sleep(0.01)
                running -= 1

        await asyncio.gather(*(work() for _ in range(6)))

        return peak, gate.active

    assert run(main()) == (2, 0)


# ---------------------------------------------------------------------------------------------
# Chunk slots in the media pool
# ---------------------------------------------------------------------------------------------

async def _grant_order(monkeypatch, jobs_in_arrival_order, enabled=True):
    client = make_client(monkeypatch)
    session = FakeSession(client)
    use_sessions(client, [session])

    pool = client.media_pool
    pool.policy.enabled = enabled
    pool.conn(session).depth = 1

    held = await pool.acquire(2, 0)  # the only slot is taken
    order = []

    async def want(name, job):
        s = await pool.acquire(2, 0, job=job)
        order.append(name)
        pool.release(s, 2)

    tasks = []

    for name, job in jobs_in_arrival_order:
        tasks.append(asyncio.ensure_future(want(name, job)))
        await asyncio.sleep(0.005)

    pool.release(held, 2)
    await asyncio.wait_for(asyncio.gather(*tasks), 2)

    return order


def test_pool_serves_the_transfer_that_has_moved_the_least_first(monkeypatch):
    async def main():
        p = policy()
        heavy, medium, light = Job(p), Job(p), Job(p)
        heavy.add(100 * MB)
        medium.add(5 * MB)

        return await _grant_order(
            monkeypatch, [("heavy", heavy), ("medium", medium), ("light", light)]
        )

    assert run(main()) == ["light", "medium", "heavy"]


def test_pool_keeps_arrival_order_inside_a_level(monkeypatch):
    async def main():
        p = policy()

        return await _grant_order(
            monkeypatch, [(f"job{i}", Job(p)) for i in range(4)]
        )

    assert run(main()) == ["job0", "job1", "job2", "job3"]


def test_pool_in_fifo_mode_ignores_priorities(monkeypatch):
    async def main():
        p = policy(enabled=False)
        heavy, light = Job(p), Job(p)
        heavy.add(100 * MB)

        return await _grant_order(monkeypatch, [("heavy", heavy), ("light", light)], enabled=False)

    assert run(main()) == ["heavy", "light"]


def test_pool_requests_without_a_job_keep_working_and_stay_fifo(monkeypatch):
    async def main():
        return await _grant_order(
            monkeypatch, [("a", None), ("b", None), ("c", None)]
        )

    assert run(main()) == ["a", "b", "c"]


def test_pool_cancelled_waiter_does_not_block_the_queue(monkeypatch):
    async def main():
        client = make_client(monkeypatch)
        session = FakeSession(client)
        use_sessions(client, [session])
        pool = client.media_pool
        pool.conn(session).depth = 1

        held = await pool.acquire(2, 0)
        head = asyncio.ensure_future(pool.acquire(2, 0, job=Job(pool.policy)))
        behind = asyncio.ensure_future(pool.acquire(2, 0, job=Job(pool.policy)))
        await asyncio.sleep(0.01)

        head.cancel()
        await asyncio.gather(head, return_exceptions=True)
        pool.release(held, 2)

        s = await asyncio.wait_for(behind, 1)
        pool.release(s, 2)

        assert len(pool._queues[2]) == 0

    run(main())


# ---------------------------------------------------------------------------------------------
# End to end: real get_file calls through the gate and the pool
# ---------------------------------------------------------------------------------------------

def _contention(monkeypatch, enabled):
    async def main():
        client = make_client(monkeypatch)
        client.media_pool.policy.enabled = enabled
        client.media_pool.policy.quanta = QUANTA
        client.media_pool.policy.aging = 1000
        client.get_file_semaphore.slots = 1

        big_blob = os.urandom(24 * MB)
        small_blob = big_blob[:256 * 1024]  # the fake session serves big_blob; both files are prefixes of it

        session = FakeSession(client)
        session.blobs = {2: big_blob}
        session.delay = 0.002
        use_sessions(client, [session])

        order = []

        async def fetch(name, blob):
            got = bytearray()

            async for chunk in client.get_file(_fid(), len(blob)):
                got += chunk

            assert bytes(got[:len(blob)]) == blob

            order.append(name)
            return bytes(got)

        big_task = asyncio.ensure_future(fetch("big1", big_blob))
        await asyncio.sleep(0.02)  # big1 is admitted and running
        big2 = asyncio.ensure_future(fetch("big2", big_blob))
        await asyncio.sleep(0.005)
        small = asyncio.ensure_future(fetch("small", small_blob))

        await asyncio.wait_for(asyncio.gather(big_task, big2, small), 30)
        await client._cancel_background_work()

        return order

    return run(main())


def _fid():
    from .test_transfer import file_id

    return file_id()


def test_end_to_end_small_download_overtakes_a_queued_big_one(monkeypatch):
    order = _contention(monkeypatch, enabled=True)

    assert order.index("small") < order.index("big2")


def test_end_to_end_fifo_mode_makes_the_small_one_wait(monkeypatch):
    order = _contention(monkeypatch, enabled=False)

    assert order.index("big2") < order.index("small")
