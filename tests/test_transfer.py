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

"""Offline tests for DC routing, connection failover and the upload/download pipelines.

No network and no Telegram account are needed: sessions are replaced by in-memory fakes that can
inject failures, and the transport tests talk to a loopback server.
"""

import asyncio
import hashlib
import io
import os
import random
import socket
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest

import pyrogram
import pyrogram.transfer.pool
from pyrogram import raw
from pyrogram.client import Client
from pyrogram.connection import Connection
from pyrogram.connection.transport import TCPAbridged, TCPAbridgedO
from pyrogram.crypto import aes, mtproto
from pyrogram.errors import BadRequest
from pyrogram.errors.exceptions.see_other_303 import FileMigrate
from pyrogram.file_id import FileId, FileType
from pyrogram.session.internals import DataCenter, DCRouter

MB = 1024 * 1024


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def clean_router():
    DCRouter.reset()
    yield
    DCRouter.reset()


# ---------------------------------------------------------------------------------------------
# DC router
# ---------------------------------------------------------------------------------------------

def test_router_media_dc_falls_back_to_regular_then_alternate_ports():
    media = DataCenter(2, False, False, True)
    regular = DataCenter(2, False, False, False)
    assert media != regular  # DC2 has a dedicated media address

    assert DCRouter.candidates(2, False, False, True) == [
        media, regular, (regular[0], 80), (regular[0], 5222)
    ]


def test_router_dc_without_media_address_has_no_duplicate():
    regular = DataCenter(1, False, False, False)

    assert DCRouter.candidates(1, False, False, True) == [
        regular, (regular[0], 80), (regular[0], 5222)
    ]


def test_router_test_mode_single_endpoint():
    assert DCRouter.candidates(2, True, False, False) == [DataCenter(2, True, False, False)]


def test_router_demotes_failed_endpoint_and_recovers():
    first, second, *_ = DCRouter.candidates(2, False, False, True)

    DCRouter.record_failure(first)
    ordered = DCRouter.candidates(2, False, False, True)
    assert ordered[0] == second and ordered[-1] == first

    DCRouter.record_success(first, 0.05)
    assert DCRouter.candidates(2, False, False, True)[0] == first
    assert DCRouter.stats()[first]["rtt"] == pytest.approx(0.05)


# ---------------------------------------------------------------------------------------------
# Connection failover (loopback)
# ---------------------------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_connection_fails_over_to_next_endpoint(monkeypatch):
    dead, live = ("127.0.0.1", free_port()), None

    async def main():
        nonlocal live

        async def handler(reader, writer):
            await reader.read(1)
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        live = ("127.0.0.1", server.sockets[0].getsockname()[1])

        monkeypatch.setattr(DCRouter, "candidates", classmethod(lambda cls, *a, **k: [dead, live]))

        connection = Connection(2, False, False, None, mode=1)
        await connection.connect()

        assert connection.address == live
        assert isinstance(connection.protocol, TCPAbridged)
        assert DCRouter.stats()[dead]["fails"] == 1
        assert DCRouter.stats()[live]["fails"] == 0

        await connection.close()
        server.close()
        await server.wait_closed()

    run(main())


def test_connection_gives_up_after_all_endpoints_fail(monkeypatch):
    dead = [("127.0.0.1", free_port()), ("127.0.0.1", free_port())]
    monkeypatch.setattr(DCRouter, "candidates", classmethod(lambda cls, *a, **k: dead))
    monkeypatch.setattr(Connection, "MAX_RETRIES", 1)

    async def main():
        with pytest.raises(TimeoutError):
            await Connection(2, False, False, None, mode=1).connect()

    run(main())
    assert all(DCRouter.stats()[e]["fails"] == 1 for e in dead)


# ---------------------------------------------------------------------------------------------
# Obfuscated transport: several crypto workers must not reorder the CTR stream
# ---------------------------------------------------------------------------------------------

def test_obfuscated_sends_stay_ordered_with_many_crypto_workers(monkeypatch):
    frames = {i: bytes([i % 251]) * (4 * (1 + i % 40)) for i in range(300)}
    run_obfuscated_send(monkeypatch, frames)


def test_obfuscated_sends_stay_ordered_when_small_frames_are_encrypted_inline(monkeypatch):
    # With a native backend small frames skip the executor while big ones still use it; the
    # keystream must stay in order across both paths. (NATIVE is switched on for the test; the
    # cipher itself is whatever backend the test machine has.)
    monkeypatch.setattr(aes, "NATIVE", True)
    monkeypatch.setattr(aes, "INLINE_LIMIT", 4096)

    frames = {
        i: bytes([i % 251]) * (4 * (1 + i % 40) if i % 5 else 4 * 3000)  # every 5th frame is 12 KB
        for i in range(300)
    }
    run_obfuscated_send(monkeypatch, frames)


def run_obfuscated_send(monkeypatch, frames):
    monkeypatch.setattr(pyrogram, "crypto_executor", ThreadPoolExecutor(8))

    received = []

    async def main():
        done = asyncio.Event()

        async def handler(reader, writer):
            nonce = await reader.readexactly(64)
            # Same keystream the client derived; the client already consumed 64 bytes of it
            state = (bytearray(nonce[8:40]), bytearray(nonce[40:56]), bytearray(1))
            aes.ctr256_decrypt(nonce, *state)

            buf = b""
            while len(received) < len(frames):
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buf += aes.ctr256_decrypt(chunk, *state)

                while buf:
                    n = buf[0]
                    head = 1
                    if n == 0x7f:
                        if len(buf) < 4:
                            break
                        n, head = int.from_bytes(buf[1:4], "little"), 4
                    size = n * 4
                    if len(buf) < head + size:
                        break
                    received.append(buf[head:head + size])
                    buf = buf[head + size:]

            done.set()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        transport = TCPAbridgedO(False, None)
        await transport.connect(("127.0.0.1", port))

        await asyncio.gather(*(transport.send(f) for f in frames.values()))
        await asyncio.wait_for(done.wait(), 10)

        await transport.close()
        server.close()

    run(main())

    # The server's own CTR decode only works if the stream stayed in order, so every frame
    # must arrive intact (order between concurrent senders is irrelevant).
    assert sorted(received) == sorted(frames.values())


# ---------------------------------------------------------------------------------------------
# MTProto 2.0 conformance (independent re-derivation from core.telegram.org/mtproto/description)
# ---------------------------------------------------------------------------------------------

def test_pack_follows_mtproto_2_spec():
    auth_key = os.urandom(256)
    auth_key_id = sha256(auth_key).digest()[:8]
    session_id = os.urandom(8)
    salt = 0x1122334455667788

    message = raw.core.Message(raw.functions.Ping(ping_id=7), msg_id=(1 << 33) + 1, seq_no=1, length=12)
    packet = mtproto.pack(message, salt, session_id, auth_key, auth_key_id)

    assert packet[:8] == auth_key_id
    msg_key = packet[8:24]

    # Client -> server: x = 0
    sha_a = sha256(msg_key + auth_key[0:36]).digest()
    sha_b = sha256(auth_key[40:76] + msg_key).digest()
    key = sha_a[:8] + sha_b[8:24] + sha_a[24:32]
    iv = sha_b[:8] + sha_a[8:24] + sha_b[24:32]

    plain = aes.ige256_decrypt(packet[24:], key, iv)

    assert len(plain) % 16 == 0
    assert plain[:8] == salt.to_bytes(8, "little")
    assert plain[8:16] == session_id
    # msg_key = middle 128 bits of SHA-256(auth_key[88:120] + plaintext incl. padding)
    assert msg_key == sha256(auth_key[88:120] + plain).digest()[8:24]

    body = message.write()
    padding = plain[16 + len(body):]
    assert 12 <= len(padding) <= 1024


# ---------------------------------------------------------------------------------------------
# Fakes for the transfer pipelines
# ---------------------------------------------------------------------------------------------

class FakeStorage:
    async def dc_id(self):
        return 2

    async def test_mode(self):
        return False

    async def auth_key(self):
        return b"k" * 256


class FakeSession:
    MEDIA_WAIT_TIMEOUT = 5
    registry = []

    def __init__(self, client=None, dc_id=2, auth_key=b"k" * 256, test_mode=False, is_media=True, is_cdn=False):
        self.dc_id = dc_id
        self.auth_key = auth_key
        self.failure = None
        self.is_connected = asyncio.Event()
        self.is_connected.set()
        self.calls = 0
        self.stopped = False
        self.blobs = {}
        self.flaky = 0.0
        self.migrate_to = None
        self.error = None
        self.die_after = None
        self.stall = 0.0
        self.delay = 0.0  # simulated round-trip time, applied to every request
        self.serial = False  # True: one request at a time, like a connection with limited bandwidth
        self._lock = None
        self.uploaded = {}
        FakeSession.registry.append(self)

    async def start(self):
        await asyncio.sleep(0)

    async def stop(self):
        self.stopped = True
        self.is_connected.clear()

    async def invoke(self, query, retries=5, timeout=15, sleep_threshold=10):
        self.calls += 1

        if self.die_after is not None and self.calls > self.die_after:
            self.failure = ConnectionError("gone")
            raise OSError("socket closed")

        if self.error is not None:
            raise self.error

        # Like the real Session.invoke: transient errors are retried `retries` times in place
        # before the error reaches the caller.
        for attempt in range(retries + 1):
            if self.flaky and random.random() < self.flaky:
                if attempt == retries:
                    raise OSError("flaky")
                continue
            break

        if self.serial:
            if self._lock is None:
                self._lock = asyncio.Lock()

            async with self._lock:
                await asyncio.sleep(self.delay)
        else:
            await asyncio.sleep(self.delay)

        if isinstance(query, raw.functions.upload.GetFile):
            if self.stall:
                await asyncio.sleep(self.stall)  # a connection that is alive but has gone silent

            if self.migrate_to is not None:
                raise FileMigrate(value=self.migrate_to)

            blob = self.blobs[self.dc_id]
            return raw.types.upload.File(
                type=raw.types.storage.FileUnknown(), mtime=0,
                bytes=blob[query.offset:query.offset + query.limit],
            )

        self.uploaded[query.file_part] = query.bytes
        return True


def make_client(monkeypatch):
    """Must be called inside the running loop: Client binds to asyncio.get_event_loop()."""
    FakeSession.registry = []
    monkeypatch.setattr(pyrogram.client, "Session", FakeSession)
    monkeypatch.setattr(pyrogram.transfer.pool, "Session", FakeSession)

    client = Client("t", api_id=1, api_hash="x", in_memory=True)
    client.storage = FakeStorage()
    return client


def use_sessions(client, sessions, dc_id=2):
    """Hand ready-made sessions to the media pool (the home DC is 2) and stop it from opening more."""
    pool = client.media_pool
    pool.sessions[dc_id] = sessions[0]
    pool.pools[dc_id] = list(sessions)

    async def ensure(dc, count):
        return list(pool.pools[dc])

    pool.ensure = ensure


def file_id(dc_id=2):
    return FileId(file_type=FileType.DOCUMENT, dc_id=dc_id, media_id=1, access_hash=2, file_reference=b"x")


async def download(client, blob, dc_id=2, size=None):
    out = bytearray()
    async for chunk in client.get_file(file_id(dc_id), len(blob) if size is None else size):
        out += chunk
    return bytes(out)


def run_download(monkeypatch, blob, configure=None, dc_id=2):
    """Download `blob` through get_file, every session being a FakeSession serving it."""

    async def main():
        client = make_client(monkeypatch)

        async def create(dc_id_):
            s = FakeSession(client, dc_id_)
            s.blobs = {2: blob, 4: blob}
            if configure:
                configure(s)
            return s

        original_init = FakeSession.__init__

        def init(self, *a, **k):
            original_init(self, *a, **k)
            self.blobs = {2: blob, 4: blob}
            if configure:
                configure(self)

        monkeypatch.setattr(FakeSession, "__init__", init)
        client._create_media_session = create

        try:
            return client, await download(client, blob, dc_id=dc_id)
        finally:
            await client._cancel_background_work()

    return run(main())


# ---------------------------------------------------------------------------------------------
# Download pipeline
# ---------------------------------------------------------------------------------------------

def test_download_is_complete_and_ordered(monkeypatch):
    blob = os.urandom(10 * MB + 12345)
    client, got = run_download(monkeypatch, blob)

    assert got == blob
    assert len(FakeSession.registry) <= client.DOWNLOAD_CONNECTIONS


def test_small_file_does_not_open_extra_connections(monkeypatch):
    blob = os.urandom(300 * 1024)
    _, got = run_download(monkeypatch, blob)

    assert got == blob
    assert len(FakeSession.registry) == 1


def test_download_survives_flaky_connections(monkeypatch):
    random.seed(7)
    blob = os.urandom(24 * MB + 1)

    def flaky(session):
        session.flaky = 0.25

    _, got = run_download(monkeypatch, blob, configure=flaky)
    assert got == blob


def test_download_survives_connection_dying_midway(monkeypatch):
    blob = os.urandom(24 * MB + 1)
    made = []

    def dies(session):
        made.append(session)
        # the 2nd connection breaks for good after a few requests
        if len(made) == 2:
            session.die_after = 3

    _, got = run_download(monkeypatch, blob, configure=dies)

    assert got == blob
    assert made[1].failure is not None  # it was noticed and dropped from the pool


def test_file_migrate_reroutes_to_the_right_dc(monkeypatch):
    blob = os.urandom(3 * MB)

    def wrong_dc(session):
        session.migrate_to = 4 if session.dc_id == 2 else None

    _, got = run_download(monkeypatch, blob, configure=wrong_dc)

    assert got == blob
    assert {s.dc_id for s in FakeSession.registry} == {2, 4}


def test_non_retryable_error_is_not_retried(monkeypatch):
    blob = os.urandom(2 * MB)

    def expired(session):
        session.error = BadRequest(value="[400 FILE_REFERENCE_EXPIRED]")

    _, got = run_download(monkeypatch, blob, configure=expired)

    assert got == b""  # get_file reports the failure by ending early
    # Only the first burst of requests went out; none of them was retried
    assert sum(s.calls for s in FakeSession.registry) <= 2 * Client.DOWNLOAD_PIPELINE_DEPTH


def test_dead_cached_session_is_replaced(monkeypatch):
    async def main():
        client = make_client(monkeypatch)

        async def create(dc_id):
            return FakeSession(client, dc_id)

        client._create_media_session = create

        first = await client.media_pool.primary(2)
        first.failure = ConnectionError("reconnect gave up")

        second = await client.media_pool.primary(2)
        await asyncio.sleep(0.01)  # let the eviction task close the old one
        return first, second

    first, second = run(main())

    assert second is not first and second.failure is None
    assert first.stopped


# ---------------------------------------------------------------------------------------------
# Upload pipeline
# ---------------------------------------------------------------------------------------------

def run_upload(monkeypatch, path, sessions):
    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)
        return await client.save_file(str(path))

    return run(main())


def test_upload_sends_every_part_once_even_with_flaky_connections(monkeypatch, tmp_path):
    random.seed(3)
    data = os.urandom(20 * MB + 777)
    path = tmp_path / "big.bin"
    path.write_bytes(data)

    sessions = [FakeSession() for _ in range(6)]
    for s in sessions[:3]:
        s.flaky = 0.3

    result = run_upload(monkeypatch, path, sessions)

    uploaded = {}
    for s in sessions:
        uploaded.update(s.uploaded)

    part = 512 * 1024
    expected = {i: data[i * part:(i + 1) * part] for i in range(-(-len(data) // part))}

    assert uploaded == expected
    assert isinstance(result, raw.types.InputFileBig) and result.parts == len(expected)


def test_upload_fails_loudly_on_fatal_error_and_stops_early(monkeypatch, tmp_path):
    path = tmp_path / "doomed.bin"
    path.write_bytes(os.urandom(30 * MB))

    sessions = [FakeSession() for _ in range(4)]
    for s in sessions:
        s.error = BadRequest(value="[400 FILE_PART_INVALID]")

    with pytest.raises(BadRequest):
        run_upload(monkeypatch, path, sessions)

    # 30 MB = 60 parts: after the first fatal error the rest must not be hammered
    assert sum(s.calls for s in sessions) < 20


def test_background_restart_marks_session_dead(monkeypatch):
    from pyrogram.session import Session

    async def main():
        session = Session(object(), 2, b"k" * 256, False, is_media=True)

        async def boom():
            raise RuntimeError("auth key duplicated")

        session.restart = boom
        await session._background_restart()
        return session

    session = run(main())
    assert isinstance(session.failure, RuntimeError)


# ---------------------------------------------------------------------------------------------
# Offset / limit units, stall hedging, resume, session fixes, socket options
# ---------------------------------------------------------------------------------------------

def test_offset_and_limit_count_mib_even_for_small_files(monkeypatch):
    """stream_media() documents 1 MiB units; files <= 25 MB use 512 KB requests on the wire."""
    blob = os.urandom(10 * MB + 321)

    async def main():
        client = make_client(monkeypatch)
        original_init = FakeSession.__init__

        def init(self, *a, **k):
            original_init(self, *a, **k)
            self.blobs = {2: blob}

        monkeypatch.setattr(FakeSession, "__init__", init)

        async def create(dc_id_):
            return FakeSession(client, dc_id_)

        client._create_media_session = create

        async def collect(**kw):
            out = bytearray()
            async for chunk in client.get_file(file_id(), len(blob), **kw):
                out += chunk
            return bytes(out)

        try:
            return (
                await collect(limit=3, offset=2),
                await collect(offset=8),
                await collect(limit=1),
            )
        finally:
            await client._cancel_background_work()

    middle, tail, first = run(main())

    assert middle == blob[2 * MB:5 * MB]
    assert tail == blob[8 * MB:]
    assert first == blob[:MB]


def test_stalled_connection_does_not_stall_the_download(monkeypatch):
    import time

    monkeypatch.setattr(Client, "DOWNLOAD_HEDGE_AFTER", 0.2)
    blob = os.urandom(24 * MB + 5)
    made = []

    def silent(session):
        if session not in made:  # run_download() configures the first session twice
            made.append(session)
        if len(made) == 2:
            session.stall = 30  # alive, never answers within the test

    started = time.monotonic()
    _, got = run_download(monkeypatch, blob, configure=silent)

    assert got == blob
    assert time.monotonic() - started < 10
    assert made[1].calls >= 1  # the silent connection really was handed work


def test_hedging_can_be_disabled(monkeypatch):
    monkeypatch.setattr(Client, "DOWNLOAD_HEDGE_AFTER", 0)
    blob = os.urandom(6 * MB + 1)
    _, got = run_download(monkeypatch, blob)

    assert got == blob


def test_hedge_does_not_swallow_errors_when_both_requests_fail(monkeypatch):
    monkeypatch.setattr(Client, "DOWNLOAD_HEDGE_AFTER", 0.05)
    blob = os.urandom(2 * MB)

    def broken(session):
        session.stall = 0.2
        session.error = BadRequest(value="[400 FILE_REFERENCE_EXPIRED]")

    _, got = run_download(monkeypatch, blob, configure=broken)

    assert got == b""  # reported the usual way: get_file ends early, handle_download notices


def test_incomplete_download_resumes_from_last_whole_mib(monkeypatch):
    blob = os.urandom(8 * MB + 777)
    calls = []

    async def main():
        client = make_client(monkeypatch)
        client.DOWNLOAD_RESUME_DELAY = 0

        async def fake_get_file(fid, size, limit, offset, progress=None, progress_args=()):
            calls.append(offset)
            pos = offset * MB

            if len(calls) == 1:  # dies half way through the 4th MiB
                yield blob[pos:pos + 3 * MB + 100]
                return

            while pos < len(blob):
                yield blob[pos:pos + MB]
                pos += MB

        client.get_file = fake_get_file
        return await client.handle_download((file_id(), "unused", "f.bin", True, len(blob), None, ()))

    result = run(main())

    assert result.getvalue() == blob
    assert calls == [0, 3]  # restarted at MiB 3, the torn 100 bytes were discarded


def test_incomplete_download_resumes_on_disk_too(monkeypatch, tmp_path):
    blob = os.urandom(5 * MB + 9)
    calls = []

    async def main():
        client = make_client(monkeypatch)
        client.DOWNLOAD_RESUME_DELAY = 0

        async def fake_get_file(fid, size, limit, offset, progress=None, progress_args=()):
            calls.append(offset)
            pos = offset * MB

            if len(calls) <= 2:  # two failures in a row, each after some progress
                yield blob[pos:pos + MB + 50]
                return

            while pos < len(blob):
                yield blob[pos:pos + MB]
                pos += MB

        client.get_file = fake_get_file
        return await client.handle_download((file_id(), str(tmp_path), "f.bin", False, len(blob), None, ()))

    path = run(main())

    with open(path, "rb") as f:
        assert f.read() == blob
    assert calls == [0, 1, 2]
    assert not os.path.exists(path + ".temp")


def test_download_gives_up_quickly_when_nothing_ever_arrives(monkeypatch, tmp_path):
    calls = []

    async def main():
        client = make_client(monkeypatch)
        client.DOWNLOAD_RESUME_DELAY = 0

        async def fake_get_file(fid, size, limit, offset, progress=None, progress_args=()):
            calls.append(offset)
            return
            yield  # pragma: no cover  (makes this an async generator)

        client.get_file = fake_get_file
        return await client.handle_download((file_id(), str(tmp_path), "f.bin", False, 4 * MB, None, ()))

    assert run(main()) is None
    assert len(calls) == 2  # one retry, then a permanent error is assumed
    assert not any(n.endswith(".temp") for n in os.listdir(tmp_path))


def test_download_gives_up_after_max_resumes(monkeypatch):
    blob = os.urandom(10 * MB)
    calls = []

    async def main():
        client = make_client(monkeypatch)
        client.DOWNLOAD_RESUME_DELAY = 0

        async def fake_get_file(fid, size, limit, offset, progress=None, progress_args=()):
            calls.append(offset)
            pos = offset * MB
            yield blob[pos:pos + MB]  # always makes progress, never finishes

        client.get_file = fake_get_file
        return await client.handle_download((file_id(), "unused", "f.bin", True, len(blob), None, ()))

    assert run(main()) is None
    assert len(calls) == Client.DOWNLOAD_RESUMES + 1


def test_invoke_retry_keeps_the_callers_sleep_threshold(monkeypatch):
    from types import SimpleNamespace
    from pyrogram.errors import FloodWait
    from pyrogram.session import Session

    slept = []
    real_sleep = asyncio.sleep

    async def fast_sleep(delay, *a, **k):
        slept.append(delay)
        await real_sleep(0)

    async def main():
        client = SimpleNamespace(sleep_threshold=0, name="t")
        session = Session(client, 2, b"k" * 256, False, is_media=True)
        session.is_connected.set()
        outcomes = [TimeoutError(), FloodWait(value=30), "ok"]

        async def send(query, wait_response=True, timeout=15):
            outcome = outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        session.send = send
        monkeypatch.setattr(asyncio, "sleep", fast_sleep)
        return await session.invoke(raw.functions.Ping(ping_id=1), retries=2, sleep_threshold=60)

    # Before the fix the retry fell back to the default threshold and re-raised the 30 s wait
    assert run(main()) == "ok"
    assert 30 in slept


def test_session_keeps_strong_references_to_packet_tasks():
    from types import SimpleNamespace
    from pyrogram.session import Session

    async def main():
        client = SimpleNamespace(loop=asyncio.get_running_loop())
        session = Session(client, 2, b"k" * 256, False, is_media=True)
        gate = asyncio.Event()

        async def work():
            await gate.wait()

        task = session._spawn(work())
        await asyncio.sleep(0)
        held = task in session._tasks
        gate.set()
        await task
        await asyncio.sleep(0)
        return held, task in session._tasks

    held, still_held = run(main())
    assert held and not still_held


def test_failed_start_backs_off_instead_of_spinning(monkeypatch):
    from types import SimpleNamespace
    from pyrogram.session import Session
    import pyrogram.session.session as session_module

    attempts = []
    slept = []
    real_sleep = asyncio.sleep

    async def fast_sleep(delay, *a, **k):
        slept.append(delay)
        await real_sleep(0)

    class Failing:
        def __init__(self, *a, **k): pass

        async def connect(self):
            attempts.append(1)
            if len(attempts) < 5:
                raise TimeoutError

        async def send(self, data): pass

        async def recv(self):
            await real_sleep(3600)

        async def close(self): pass

    async def main():
        client = SimpleNamespace(
            loop=asyncio.get_running_loop(), ipv6=False, proxy=None, name="t",
            device_model="d", app_version="a", system_version="s", lang_code="en",
        )
        session = Session(client, 2, b"k" * 256, False, is_media=True, is_cdn=True)

        async def send(*a, **k):
            return None

        session.send = send
        monkeypatch.setattr(session_module, "Connection", Failing)
        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        async def stop():
            session.is_connected.clear()

        session.stop = stop
        await session.start()
        session.network_task.cancel()
        session.ping_task.cancel()

    run(main())

    assert len(attempts) == 5
    assert [d for d in slept if d >= 0.25][:4] == [0.25, 0.5, 1.0, 2.0]


def test_socket_options_make_dead_peers_visible():
    from pyrogram.connection.transport.tcp.tcp import TCP

    a = socket.socket()
    try:
        TCP._tune_socket(a)

        assert a.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
        assert a.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)

        if hasattr(socket, "TCP_KEEPIDLE"):
            assert a.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 15
            assert a.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == 3

        if hasattr(socket, "TCP_USER_TIMEOUT"):
            assert a.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT) == TCP.USER_TIMEOUT_MS
    finally:
        a.close()


def server_packet(body, auth_key, session_id, msg_id):
    """What the server would send: the incoming direction of MTProto 2.0 (x = 8)."""
    message = raw.core.Message(body, msg_id, 0, len(body.write()))
    data = bytes(8) + session_id + message.write()
    padding = os.urandom(-(len(data) + 12) % 16 + 12)
    msg_key = sha256(auth_key[96:128] + data + padding).digest()[8:24]
    aes_key, aes_iv = mtproto.kdf(auth_key, msg_key, False)
    auth_key_id = hashlib.sha1(auth_key).digest()[-8:]

    return auth_key_id + msg_key + aes.ige256_encrypt(data + padding, aes_key, aes_iv)


def feed_packets(monkeypatch, native, offsets):
    """Deliver server packets with msg_id = now + offset through Session.handle_packet."""
    from types import SimpleNamespace
    from pyrogram.session import Session
    from pyrogram.session.internals import MsgId

    monkeypatch.setattr(aes, "NATIVE", native)

    async def main():
        client = SimpleNamespace(loop=asyncio.get_running_loop(), name="t")
        auth_key = os.urandom(256)
        session = Session(client, 2, auth_key, False, is_media=True)
        base = MsgId() + 1  # server ids are odd

        for offset in offsets:
            await session.handle_packet(
                server_packet(raw.types.Pong(msg_id=1, ping_id=0), auth_key, session.session_id, base + offset)
            )

        return session.stored_msg_ids, base

    return run(main())


def test_duplicate_msg_ids_are_dropped_and_ids_stay_sorted(monkeypatch):
    for native in (False, True):  # executor path and inline path behave the same
        stored, base = feed_packets(monkeypatch, native, [0, 0, 8, 4, 8, 4, 12])

        assert stored == [base, base + 4, base + 8, base + 12], native


def test_msg_id_older_than_everything_seen_is_rejected(monkeypatch):
    stored, base = feed_packets(monkeypatch, True, [100, 4, 100])

    assert stored == [base + 100]


def test_only_file_parts_are_treated_as_big_payloads():
    from pyrogram.session import Session

    part = bytes(512 * 1024)
    ping = raw.functions.Ping(ping_id=1)
    save = raw.functions.upload.SaveBigFilePart(file_id=1, file_part=0, file_total_parts=1, bytes=part)

    assert Session._payload_size(ping) == 0
    assert Session._payload_size(save) == len(part)
    assert Session._payload_size(raw.functions.InvokeWithoutUpdates(query=save)) == len(part)
    assert not aes.is_inline(len(part)) and aes.is_inline(0) == aes.NATIVE


def test_inline_crypto_is_never_used_without_a_native_backend(monkeypatch):
    monkeypatch.setattr(aes, "NATIVE", False)
    assert not aes.is_inline(16)

    monkeypatch.setattr(aes, "NATIVE", True)
    assert aes.is_inline(16) and not aes.is_inline(aes.INLINE_LIMIT + 1)

    monkeypatch.setattr(aes, "INLINE_LIMIT", 0)  # PYROGRAM_CRYPTO_INLINE=0 switches it off
    assert not aes.is_inline(0) and not aes.is_inline(16)


def test_first_round_trip_carries_the_whole_burst(monkeypatch):
    """A small file must not need a second round trip after the first answer."""
    blob = os.urandom(2 * MB + 5)

    def slow(session):
        session.delay = 0.3

    t = __import__("time").monotonic()
    _, got = run_download(monkeypatch, blob, configure=slow)
    elapsed = __import__("time").monotonic() - t

    assert got == blob
    assert elapsed < 0.55  # one 0.3 s round trip, not two


def test_speculative_requests_are_dropped_on_file_migrate(monkeypatch):
    blob = os.urandom(3 * MB)

    def wrong_dc(session):
        session.migrate_to = 4 if session.dc_id == 2 else None

    _, got = run_download(monkeypatch, blob, configure=wrong_dc)

    assert got == blob
    assert {s.dc_id for s in FakeSession.registry} == {2, 4}


def test_upload_parts_survive_short_reads_and_keep_their_boundaries(monkeypatch, tmp_path):
    """A raw stream may return fewer bytes than asked; part boundaries must not shift."""
    data = os.urandom(5 * 512 * 1024 + 1234)
    path = tmp_path / "f.bin"
    path.write_bytes(data)

    class Trickle(io.RawIOBase):
        """Raw stream that never returns more than 100 kB per read, like a socket or a pipe."""
        name = "f.bin"

        def __init__(self, payload):
            self._b, self._pos = payload, 0

        def readable(self):
            return True

        def seekable(self):
            return True

        def tell(self):
            return self._pos

        def seek(self, offset, whence=0):
            self._pos = offset if whence == 0 else len(self._b) + offset if whence == 2 else self._pos + offset
            return self._pos

        def read(self, n=-1):
            n = 100_000 if n is None or n < 0 else min(n, 100_000)
            out = self._b[self._pos:self._pos + n]
            self._pos += len(out)
            return out

    sessions = [FakeSession() for _ in range(3)]

    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)

        return await client.save_file(Trickle(data))

    result = run(main())

    uploaded = {}
    for s in sessions:
        uploaded.update(s.uploaded)

    part = 512 * 1024
    assert b"".join(uploaded[i] for i in sorted(uploaded)) == data
    assert all(len(uploaded[i]) == part for i in sorted(uploaded)[:-1])
    assert result.parts == 6


def test_small_upload_md5_matches_and_uses_every_part(monkeypatch, tmp_path):
    data = os.urandom(3 * 512 * 1024 + 7)  # under 10 MB: a regular InputFile with md5
    path = tmp_path / "small.bin"
    path.write_bytes(data)

    sessions = [FakeSession() for _ in range(4)]
    result = run_upload(monkeypatch, path, sessions)

    assert isinstance(result, raw.types.InputFile)
    assert result.md5_checksum == hashlib.md5(data).hexdigest()
    assert result.parts == 4


def test_upload_keeps_several_requests_in_flight_per_connection(monkeypatch, tmp_path):
    path = tmp_path / "f.bin"
    path.write_bytes(os.urandom(20 * MB))

    peak = {"now": 0, "max": 0}
    session = FakeSession()
    session.delay = 0.02
    original = session.invoke

    async def counting(query, *a, **k):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        try:
            return await original(query, *a, **k)
        finally:
            peak["now"] -= 1

    session.invoke = counting
    run_upload(monkeypatch, path, [session])

    assert peak["max"] >= 2  # UPLOAD_DEPTH requests overlapped on the single connection


# ---------------------------------------------------------------------------------------------
# Stable speed: progress callbacks, disk writes and ramp-up must not throttle the pipeline
# ---------------------------------------------------------------------------------------------

def _fast_client(monkeypatch, blob, delay=0.01):
    original_init = FakeSession.__init__

    def init(self, *a, **k):
        original_init(self, *a, **k)
        self.blobs = {2: blob}
        self.delay = delay

    monkeypatch.setattr(FakeSession, "__init__", init)
    client = make_client(monkeypatch)

    async def create(dc_id_):
        return FakeSession(client, dc_id_)

    client._create_media_session = create
    return client


def test_slow_progress_callback_does_not_throttle_the_download(monkeypatch):
    import time

    blob = os.urandom(30 * MB)
    calls = []

    async def main():
        client = _fast_client(monkeypatch, blob)

        async def progress(current, total):
            calls.append(current)
            await asyncio.sleep(0.3)  # e.g. editing a status message

        t = time.monotonic()
        n = 0
        async for c in client.get_file(file_id(), len(blob), 0, 0, progress):
            n += len(c)
        elapsed = time.monotonic() - t
        await client._cancel_background_work()
        return n, elapsed

    n, elapsed = run(main())

    assert n == len(blob)
    # 30 chunks x 0.3 s = 9 s if the callback sat inside the pipeline (the old behaviour)
    assert elapsed < 3
    assert calls[-1] == len(blob)            # the final value is always delivered
    assert calls == sorted(calls)            # never goes backwards
    assert len(calls) < 30                   # slow callbacks skip values instead of queueing them


def test_progress_callbacks_never_overlap_and_end_at_the_full_size(monkeypatch):
    blob = os.urandom(12 * MB + 1)
    running = {"now": 0, "max": 0}
    seen = []

    async def main():
        client = _fast_client(monkeypatch, blob)

        async def progress(current, total):
            running["now"] += 1
            running["max"] = max(running["max"], running["now"])
            await asyncio.sleep(0.02)
            seen.append((current, total))
            running["now"] -= 1

        async for _ in client.get_file(file_id(), len(blob), 0, 0, progress):
            pass

        await client._cancel_background_work()

    run(main())

    assert running["max"] == 1
    assert seen[-1] == (len(blob), len(blob))


def test_sync_progress_callbacks_still_work(monkeypatch):
    blob = os.urandom(5 * MB)
    seen = []

    async def main():
        client = _fast_client(monkeypatch, blob)
        client.executor = ThreadPoolExecutor(2)

        def progress(current, total, tag):
            seen.append((current, total, tag))

        async for _ in client.get_file(file_id(), len(blob), 0, 0, progress, ("x",)):
            pass

        await client._cancel_background_work()

    run(main())

    assert seen and seen[-1] == (len(blob), len(blob), "x")


def test_stop_transmission_from_a_progress_callback_still_stops_the_download(monkeypatch):
    blob = os.urandom(40 * MB)
    got = []

    async def main():
        client = _fast_client(monkeypatch, blob, delay=0.02)

        async def progress(current, total):
            if current >= 3 * MB:
                raise pyrogram.StopTransmission

        try:
            async for c in client.get_file(file_id(), len(blob), 0, 0, progress):
                got.append(len(c))
        finally:
            await client._cancel_background_work()

    with pytest.raises(pyrogram.StopTransmission):
        run(main())

    # Progress counts bytes that have arrived (ahead of what was handed over), so the stop lands
    # a little before 3 MB delivered; the point is that it stops long before the end.
    assert 0 < sum(got) < len(blob) // 4


def test_extra_connections_start_with_the_first_request_not_after_it(monkeypatch):
    blob = os.urandom(30 * MB)
    events = []

    async def main():
        client = _fast_client(monkeypatch, blob, delay=0.2)
        grow = client.media_pool.ensure

        async def spy_grow(dc_id, count):
            events.append("pool")
            return await grow(dc_id, count)

        client.media_pool.ensure = spy_grow
        original = FakeSession.invoke

        async def spy_invoke(self, query, *a, **k):
            result = await original(self, query, *a, **k)
            events.append("answer")
            return result

        monkeypatch.setattr(FakeSession, "invoke", spy_invoke)

        async for _ in client.get_file(file_id(), len(blob)):
            pass

        await client._cancel_background_work()

    run(main())

    assert events[0] == "pool"  # asked for before any GetFile answered


def test_disk_download_is_written_off_the_event_loop_and_intact(monkeypatch, tmp_path):
    blob = os.urandom(9 * MB + 31)
    threads = set()

    async def main():
        client = _fast_client(monkeypatch, blob)
        loop_thread = __import__("threading").get_ident()

        class Spy(io.FileIO):
            def write(self, b):
                threads.add(__import__("threading").get_ident() != loop_thread)
                return super().write(b)

        real_open = open

        def spy_open(path, mode="r", buffering=-1, *a, **k):
            return Spy(path, "wb") if str(path).endswith(".temp") else real_open(path, mode, buffering, *a, **k)

        monkeypatch.setattr(__import__("builtins"), "open", spy_open)

        try:
            return await client.handle_download((file_id(), str(tmp_path), "f.bin", False, len(blob), None, ()))
        finally:
            monkeypatch.setattr(__import__("builtins"), "open", real_open)
            await client._cancel_background_work()

    path = run(main())

    with open(path, "rb") as f:
        assert f.read() == blob
    assert threads == {True}  # every write happened on a worker thread


# ---------------------------------------------------------------------------------------------
# Stable upload speed
# ---------------------------------------------------------------------------------------------

def _upload_file(tmp_path, mb):
    path = tmp_path / "up.bin"
    path.write_bytes(os.urandom(int(mb * MB)))
    return path


def test_slow_progress_callback_does_not_throttle_the_upload(monkeypatch, tmp_path):
    import time

    path = _upload_file(tmp_path, 20)  # 40 parts
    sessions = [FakeSession() for _ in range(4)]
    for s in sessions:
        s.delay = 0.02
    calls = []

    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)

        async def progress(current, total):
            calls.append(current)
            await asyncio.sleep(0.3)

        t = time.monotonic()
        await client.save_file(str(path), progress=progress)
        return time.monotonic() - t

    elapsed = run(main())

    # 40 parts x 0.3 s = 12 s if the callback sat in the producer loop (the old behaviour)
    assert elapsed < 4
    assert calls[-1] == 20 * MB and calls == sorted(calls)


def test_upload_progress_follows_acknowledged_bytes(monkeypatch, tmp_path):
    path = _upload_file(tmp_path, 12)
    sessions = [FakeSession() for _ in range(3)]
    for s in sessions:
        s.delay = 0.05
    seen = []

    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)

        async def progress(current, total):
            acked = sum(len(b) for s in sessions for b in s.uploaded.values())
            seen.append((current, acked, total))

        await client.save_file(str(path), progress=progress)

    run(main())

    assert all(cur <= acked + 1 for cur, acked, _ in seen), "progress ran ahead of what Telegram accepted"
    cur, acked, total = seen[-1]
    assert cur == total == acked  # the last value comes after every part was acknowledged


def test_stop_transmission_from_an_upload_progress_callback_stops_the_upload(monkeypatch, tmp_path):
    path = _upload_file(tmp_path, 40)  # 80 parts
    sessions = [FakeSession() for _ in range(2)]
    for s in sessions:
        s.delay = 0.02

    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)

        async def progress(current, total):
            if current >= 2 * MB:
                raise pyrogram.StopTransmission

        await client.save_file(str(path), progress=progress)

    with pytest.raises(pyrogram.StopTransmission):
        run(main())

    assert sum(len(s.uploaded) for s in sessions) < 40  # nowhere near all 80 parts went out


def test_part_stuck_on_a_silent_connection_is_raced_on_another(monkeypatch, tmp_path):
    import time
    monkeypatch.setattr(Client, "UPLOAD_HEDGE_AFTER", 0.1)
    path = _upload_file(tmp_path, 8)  # 16 parts
    data = path.read_bytes()
    sessions = [FakeSession() for _ in range(3)]

    original = sessions[1].invoke

    async def silent(query, *a, **k):
        await asyncio.sleep(30)  # alive but never answers (the real timeout is 60 s)
        return await original(query, *a, **k)

    sessions[1].invoke = silent

    async def main():
        client = make_client(monkeypatch)

        use_sessions(client, sessions)
        t = time.monotonic()
        result = await client.save_file(str(path))
        return result, time.monotonic() - t

    result, elapsed = run(main())

    uploaded = {}
    for s in sessions:
        uploaded.update(s.uploaded)

    part = 512 * 1024
    assert b"".join(uploaded[i] for i in sorted(uploaded)) == data
    assert result.parts == 16
    assert elapsed < 5


def test_upload_starts_on_the_first_connection_that_is_up(monkeypatch, tmp_path):
    path = _upload_file(tmp_path, 6)
    data = path.read_bytes()
    events = []

    async def run_it():
        client = make_client(monkeypatch)
        counter = [0]
        original_init = FakeSession.__init__

        def init(self, *a, **k):
            original_init(self, *a, **k)
            counter[0] += 1
            self.n = counter[0]

        async def start(self):
            await asyncio.sleep(0.05 if self.n == 1 else 1.5)  # the others are slow to connect
            events.append(("up", self.n))

        original_invoke = FakeSession.invoke

        async def invoke(self, query, *a, **k):
            events.append(("part", self.n))
            return await original_invoke(self, query, *a, **k)

        monkeypatch.setattr(FakeSession, "__init__", init)
        monkeypatch.setattr(FakeSession, "start", start)
        monkeypatch.setattr(FakeSession, "invoke", invoke)

        await client.save_file(str(path))
        return client

    client = run(run_it())

    first_part = next(i for i, e in enumerate(events) if e[0] == "part")
    # The slow connections need 1.5 s; the upload may well be finished before they are up at all
    slow_up = next((i for i, e in enumerate(events) if e == ("up", 2)), len(events))
    assert events[0] == ("up", 1) and first_part < slow_up  # parts flowed before the slow ones were up

    uploaded = {}
    for s in FakeSession.registry:
        uploaded.update(s.uploaded)
    assert b"".join(uploaded[i] for i in sorted(uploaded)) == data


def test_upload_fails_cleanly_when_no_session_can_start(monkeypatch, tmp_path):
    path = _upload_file(tmp_path, 2)

    async def main():
        client = make_client(monkeypatch)

        async def broken_start(self):
            raise OSError("no route")

        monkeypatch.setattr(FakeSession, "start", broken_start)
        await client.save_file(str(path))

    with pytest.raises(OSError):  # the connection error itself, not a swallowed one
        run(main())


# ---------------------------------------------------------------------------------------------
# Uneven connections: the pipeline must not run at the pace of the slowest one
# ---------------------------------------------------------------------------------------------

def _download_with_speeds(monkeypatch, blob, delays):
    """get_file over connections whose per-request latency is delays[i] (in creation order)."""
    made = []

    async def main():
        client = make_client(monkeypatch)
        original_init = FakeSession.__init__

        def init(self, *a, **k):
            original_init(self, *a, **k)
            self.blobs = {2: blob}
            self.delay = delays[len(made) % len(delays)]
            self.serial = True  # each connection serves its requests one after another
            made.append(self)

        monkeypatch.setattr(FakeSession, "__init__", init)

        async def create(dc_id_):
            return FakeSession(client, dc_id_)

        client._create_media_session = create

        out = bytearray()
        t = __import__("time").monotonic()
        async for chunk in client.get_file(file_id(), len(blob)):
            out += chunk
        elapsed = __import__("time").monotonic() - t
        await client._cancel_background_work()
        return bytes(out), elapsed

    got, elapsed = run(main())
    return got, elapsed, made


def test_fast_connections_carry_more_chunks_than_slow_ones(monkeypatch):
    blob = os.urandom(60 * MB)
    got, _, made = _download_with_speeds(monkeypatch, blob, [0.02, 0.02, 0.4])

    assert got == blob
    calls = sorted(s.calls for s in made)
    # round-robin would give every connection a third (20 chunks); the slow one must get far less
    assert calls[0] < calls[-1] / 3


def test_one_slow_connection_does_not_set_the_pace_of_the_download(monkeypatch):
    blob = os.urandom(36 * MB)
    got, elapsed, _ = _download_with_speeds(monkeypatch, blob, [0.02, 0.6])  # 3 fast, 3 slow of 6

    assert got == blob
    # Handing out chunks in turn puts 6 on each slow connection: 6 x 0.6 s = 3.6 s at the very least
    assert elapsed < 2.2


def test_slow_but_steady_link_is_not_hedged_into_double_traffic(monkeypatch):
    monkeypatch.setattr(Client, "DOWNLOAD_HEDGE_AFTER", 0.1)
    blob = os.urandom(30 * MB)
    got, _, made = _download_with_speeds(monkeypatch, blob, [0.4])

    assert got == blob
    # one GetFile per chunk, nothing sent twice although every request takes 4x the hedge floor
    assert sum(s.calls for s in made) == 30


def test_best_session_prefers_the_soonest_finisher_and_waits_instead_of_picking_a_slow_one(monkeypatch):
    async def main():
        client = make_client(monkeypatch)
        pool = client.media_pool
        fast, slow = FakeSession(), FakeSession()
        pool.pools[2] = [fast, slow]
        pool.conn(fast).seconds = 0.1
        pool.conn(slow).seconds = 1.0

        picks = [pool.best(2, i) for i in range(4)]

        # fast is full; the slow one is free but 10x slower: better to wait for the fast one
        pool.conn(fast).inflight = pool.conn(fast).depth
        waits = pool.best(2, 0)

        # ... unless the fast one's queue is long enough that the slow one finishes first
        pool.conn(slow).seconds = 0.25
        takes_slow = pool.best(2, 0)

        return fast, slow, picks, waits, takes_slow

    fast, slow, picks, waits, takes_slow = run(main())

    assert picks == [fast] * 4
    assert waits is None
    assert takes_slow is slow


def test_slots_are_given_back_when_a_request_fails_or_is_cancelled(monkeypatch):
    async def main():
        client = make_client(monkeypatch)
        pool = client.media_pool
        a, b = FakeSession(), FakeSession()
        pool.pools[2] = [a, b]
        rpc = raw.functions.upload.GetFile(location=None, offset=0, limit=MB)

        a.error = BadRequest(value="[400 FILE_REFERENCE_EXPIRED]")
        b.error = BadRequest(value="[400 FILE_REFERENCE_EXPIRED]")

        for _ in range(3):
            try:
                await pool.request(2, rpc)
            except BadRequest:
                pass

        a.error = b.error = None
        a.delay = b.delay = 5
        task = asyncio.ensure_future(pool.request(2, rpc))
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

        return [pool.conn(s).inflight for s in (a, b)]

    assert run(main()) == [0, 0]


def test_depth_grows_on_a_connection_that_can_take_more_and_shrinks_when_requests_queue(monkeypatch):
    async def main():
        client = make_client(monkeypatch)
        pool = client.media_pool
        s = FakeSession()
        c = pool.conn(s)
        start = c.depth

        # latency stays at its idle value however many are in flight: room for more
        for _ in range(40):
            c.inflight = c.depth
            pool.release(s, 2, 0.1)
            c.inflight = c.depth

        grown = c.depth

        # latency now rises with every request in flight: they only wait behind each other
        for _ in range(60):
            c.inflight = c.depth
            pool.release(s, 2, 0.1 * c.depth)
            c.inflight = c.depth

        return start, grown, c.depth

    start, grown, shrunk = run(main())

    assert grown > start
    assert shrunk < grown


def test_streaming_a_few_chunks_does_not_open_connections_for_the_whole_file(monkeypatch):
    blob = os.urandom(40 * MB)

    async def main():
        client = _fast_client(monkeypatch, blob, delay=0.01)
        got = bytearray()

        async for chunk in client.get_file(file_id(), len(blob), 3, 5):  # 3 MiB starting at 5 MiB
            got += chunk

        await client._cancel_background_work()
        return bytes(got)

    got = run(main())

    assert got == blob[5 * MB:8 * MB]
    assert len(FakeSession.registry) == 1
