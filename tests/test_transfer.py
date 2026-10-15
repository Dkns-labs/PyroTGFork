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
import os
import random
import socket
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256

import pytest

import pyrogram
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
    monkeypatch.setattr(pyrogram, "crypto_executor", ThreadPoolExecutor(8))

    frames = {i: bytes([i % 251]) * (4 * (1 + i % 40)) for i in range(300)}
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

        await asyncio.sleep(0)

        if isinstance(query, raw.functions.upload.GetFile):
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

    client = Client("t", api_id=1, api_hash="x", in_memory=True)
    client.storage = FakeStorage()
    return client


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
    assert sum(s.calls for s in FakeSession.registry) == 1


def test_dead_cached_session_is_replaced(monkeypatch):
    async def main():
        client = make_client(monkeypatch)

        async def create(dc_id):
            return FakeSession(client, dc_id)

        client._create_media_session = create

        first = await client._get_media_session(2)
        first.failure = ConnectionError("reconnect gave up")

        second = await client._get_media_session(2)
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

        async def get_sessions(count):
            return sessions[:count]

        client._get_upload_sessions = get_sessions
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
