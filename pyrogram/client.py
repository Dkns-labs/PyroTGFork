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
from collections import OrderedDict, deque
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timedelta
import functools
from hashlib import sha256
from importlib import import_module
import inspect
from io import BytesIO, StringIO
import logging
from mimetypes import MimeTypes
import os
from pathlib import Path
import platform
import re
import shutil
import sys
from typing import AsyncGenerator, Callable, Optional, Tuple, Union

import pyrogram
from pyrogram import __license__, __version__
from pyrogram import enums
from pyrogram import raw
from pyrogram import utils
from pyrogram.crypto import aes
from pyrogram.errors import (
    AuthBytesInvalid,
    BadRequest,
    CDNFileHashMismatch,
    ChannelInvalid,
    ChannelPrivate,
    FloodPremiumWait,
    FloodWait,
    PersistentTimestampInvalid,
    PersistentTimestampOutdated,
    SessionPasswordNeeded,
    VolumeLocNotFound,
)
from pyrogram.handlers.handler import Handler
from pyrogram.methods import Methods
from pyrogram.session import Auth, Session
# --- EDIT A: import FileStorage / MemoryStorage instead of SQLiteStorage ---
from pyrogram.storage import FileStorage, MemoryStorage, Storage
from pyrogram.types import TermsOfService, User
from pyrogram.utils import MIN_MONOFORUM_CHANNEL_ID, ainput
from .connection import Connection
from .connection.transport import TCP, TCPAbridged, TCPFull
from .dispatcher import Dispatcher
from .file_id import FileId, FileType, ThumbnailSource
from .mime_types import mime_types
from .parser import Parser
from .session.internals import MsgId

log = logging.getLogger(__name__)


class Client(Methods):
    """Pyrogram Client, the main means for interacting with Telegram."""

    APP_VERSION = f"Pyrogram {__version__}"
    DEVICE_MODEL = (
        f"{platform.python_implementation()} {platform.python_version()}"
    )
    SYSTEM_VERSION = f"{platform.system()} {platform.release()}"

    LANG_PACK = ""
    LANG_CODE = "en"
    SYSTEM_LANG_CODE = "en"

    PARENT_DIR = Path(sys.argv[0]).parent

    INVITE_LINK_RE = re.compile(
        r"^(?:https?://)?(?:www\.)?(?:t(?:elegram)?\.(?:org|me|dog)/(?:joinchat/|\+))([\w-]+)$"
    )
    TME_PUBLIC_LINK_RE = re.compile(
        r"^(?:https?://)?(?:www|([\w-]+)\.)?(?:t(?:elegram)?\.(?:org|me|dog))/?([\w-]+)?$"
    )
    INVOICE_LINK_RE = re.compile(
        r"^(?:https?://)?(?:www\.)?(?:t(?:elegram)?\.(?:org|me|dog)/\$)([\w-]+)$"
    )
    WORKERS = min(64, (os.cpu_count() or 1) * 4 + 8)
    WORKDIR = PARENT_DIR

    # Interval of seconds in which the updates watchdog will kick in
    UPDATES_WATCHDOG_INTERVAL = 15 * 60

    # Optimized default concurrent transmissions for faster parallel uploads & downloads
    MAX_CONCURRENT_TRANSMISSIONS = 8
    MAX_CACHE_SIZE = 10000
    DISK_BUFFER_SIZE = 1024 * 1024  # 1 MB disk write buffer

    # Parallel download tuning: connections per DC, and in-flight GetFile requests per connection
    # (override without code changes: PYROGRAM_DL_CONNECTIONS / PYROGRAM_DL_DEPTH env vars)
    DOWNLOAD_CONNECTIONS = max(1, int(os.environ.get("PYROGRAM_DL_CONNECTIONS", 6)))
    DOWNLOAD_PIPELINE_DEPTH = max(1, int(os.environ.get("PYROGRAM_DL_DEPTH", 3)))

    mimetypes = MimeTypes()
    mimetypes.readfp(StringIO(mime_types))

    def __init__(
        self,
        name: str,
        api_id: Union[int, str] = None,
        api_hash: str = None,
        app_version: str = APP_VERSION,
        device_model: str = DEVICE_MODEL,
        system_version: str = SYSTEM_VERSION,
        lang_pack: str = LANG_PACK,
        lang_code: str = LANG_CODE,
        system_lang_code: str = SYSTEM_LANG_CODE,
        ipv6: bool = False,
        proxy: dict = None,
        test_mode: bool = False,
        bot_token: str = None,
        session_string: str = None,
        in_memory: bool = None,
        phone_number: str = None,
        phone_code: str = None,
        password: str = None,
        workers: int = WORKERS,
        workdir: str = WORKDIR,
        plugins: dict = None,
        parse_mode: "enums.ParseMode" = enums.ParseMode.DEFAULT,
        no_updates: bool = None,
        skip_updates: bool = True,
        takeout: bool = None,
        sleep_threshold: int = 30,
        hide_password: bool = False,
        max_concurrent_transmissions: int = MAX_CONCURRENT_TRANSMISSIONS,
        max_message_cache_size: int = MAX_CACHE_SIZE,
        max_business_user_connection_cache_size: int = MAX_CACHE_SIZE,
        storage_engine: Storage = None,
        no_joined_notifications: bool = False,
        client_platform: enums.ClientPlatform = enums.ClientPlatform.OTHER,
        link_preview_options: "types.LinkPreviewOptions" = None,
        fetch_replies: int = 1,
        _un_docu_gnihts: list = [],
    ):
        super().__init__()

        self.name = name
        self.api_id = int(api_id) if api_id else None
        self.api_hash = api_hash
        self.app_version = app_version
        self.device_model = device_model
        self.system_version = system_version
        self.lang_pack = lang_pack.lower()
        self.lang_code = lang_code.lower()
        self.system_lang_code = system_lang_code.lower()
        self.ipv6 = ipv6
        self.proxy = proxy
        self.test_mode = test_mode
        self.bot_token = bot_token
        self.session_string = session_string
        self.in_memory = in_memory
        self.phone_number = phone_number
        self.phone_code = phone_code
        self.password = password
        self.workers = workers
        self.workdir = Path(workdir)
        self.plugins = plugins
        self.parse_mode = parse_mode
        self.no_updates = no_updates
        self.skip_updates = skip_updates
        self.takeout = takeout
        self.sleep_threshold = sleep_threshold
        self.hide_password = hide_password
        self.max_concurrent_transmissions = max_concurrent_transmissions
        self.max_message_cache_size = max_message_cache_size
        self.max_business_user_connection_cache_size = (
            max_business_user_connection_cache_size
        )
        self.no_joined_notifications = no_joined_notifications
        self.client_platform = client_platform
        self._un_docu_gnihts = _un_docu_gnihts
        self.link_preview_options = link_preview_options
        self.fetch_replies = fetch_replies

        self.executor = ThreadPoolExecutor(
            self.workers, thread_name_prefix="Handler"
        )

        if self.in_memory is None:
            self.in_memory = bool(self.session_string)

        # --- EDIT B: pick a concrete (non-abstract) storage class ---
        if isinstance(storage_engine, Storage):
            self.storage = storage_engine
        elif self.in_memory:
            self.storage = MemoryStorage(self.name, self.session_string)
        else:
            self.storage = FileStorage(self.name, self.workdir)

        self.dispatcher = Dispatcher(self)
        self.rnd_id = MsgId
        self.parser = Parser(self)
        self.session = None

        self.media_sessions = {}
        self.media_session_pool = {}  # dc_id -> [Session, ...] extra parallel download connections
        self.media_sessions_lock = asyncio.Lock()

        self.save_file_semaphore = asyncio.Semaphore(
            self.max_concurrent_transmissions
        )
        self.get_file_semaphore = asyncio.Semaphore(
            self.max_concurrent_transmissions
        )

        self.is_connected = None
        self.is_initialized = None

        self.takeout_id = None
        self.disconnect_handler = None
        self.me: Optional[User] = None

        self.message_cache = Cache(self.max_message_cache_size)
        self.business_user_connection_cache = Cache(
            self.max_business_user_connection_cache_size
        )

        self.updates_watchdog_task = None
        self.updates_watchdog_event = asyncio.Event()
        self.last_update_time = datetime.now()

        self.loop = utils.get_event_loop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        try:
            self.stop()
        except ConnectionError:
            pass

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *args):
        try:
            await self.stop()
        except ConnectionError:
            pass

    async def updates_watchdog(self):
        while True:
            try:
                await asyncio.wait_for(
                    self.updates_watchdog_event.wait(),
                    self.UPDATES_WATCHDOG_INTERVAL,
                )
            except asyncio.TimeoutError:
                pass
            else:
                break

            if datetime.now() - self.last_update_time > timedelta(
                seconds=self.UPDATES_WATCHDOG_INTERVAL
            ):
                await self.invoke(raw.functions.updates.GetState())

    async def authorize(self) -> User:
        if self.bot_token:
            return await self.sign_in_bot(self.bot_token)

        print(f"Welcome to Pyrogram (version {__version__})")
        print(
            f"Pyrogram is free software and comes with ABSOLUTELY NO WARRANTY. Licensed\n"
            f"under the terms of the {__license__}.\n"
        )

        while True:
            try:
                if not self.phone_number:
                    while True:
                        value = await ainput(
                            "Enter phone number or bot token: "
                        )

                        if not value:
                            continue

                        confirm = (
                            await ainput(f'Is "{value}" correct? (y/N): ')
                        ).lower()

                        if confirm == "y":
                            break

                    if ":" in value:
                        self.bot_token = value
                        return await self.sign_in_bot(value)
                    else:
                        self.phone_number = value

                sent_code = await self.send_code(self.phone_number)
            except BadRequest as e:
                print(e.MESSAGE)
                self.phone_number = None
                self.bot_token = None
            else:
                break

        if sent_code.type == enums.SentCodeType.SETUP_EMAIL_REQUIRED:
            print("Setup email required for authorization")

            while True:
                try:
                    while True:
                        email = await ainput(
                            "Enter setup email: ", loop=self.loop
                        )

                        if not email:
                            continue

                        confirm = await ainput(
                            f'Is "{email}" correct? (y/N): ', loop=self.loop
                        )

                        if confirm.lower() == "y":
                            break

                    await self.invoke(
                        raw.functions.account.SendVerifyEmailCode(
                            purpose=raw.types.EmailVerifyPurposeLoginSetup(
                                phone_number=self.phone_number,
                                phone_code_hash=sent_code.phone_code_hash,
                            ),
                            email=email,
                        )
                    )

                    email_code = await ainput(
                        "Enter confirmation code received in setup email: ",
                        loop=self.loop,
                    )

                    email_sent_code = await self.invoke(
                        raw.functions.account.VerifyEmail(
                            purpose=raw.types.EmailVerifyPurposeLoginSetup(
                                phone_number=self.phone_number,
                                phone_code_hash=sent_code.phone_code_hash,
                            ),
                            verification=raw.types.EmailVerificationCode(
                                code=email_code
                            ),
                        )
                    )

                    if isinstance(
                        email_sent_code, raw.types.account.EmailVerifiedLogin
                    ):
                        sent_code = pyrogram.types.SentCode._parse(
                            email_sent_code.sent_code
                        )
                except BadRequest as e:
                    print(e.MESSAGE)
                    self.phone_number = None
                    self.bot_token = None
                else:
                    break
        else:
            sent_code_descriptions = {
                enums.SentCodeType.APP: "Telegram app",
                enums.SentCodeType.CALL: "phone call",
                enums.SentCodeType.FLASH_CALL: "phone flash call",
                enums.SentCodeType.MISSED_CALL: "",
                enums.SentCodeType.SMS: "SMS",
                enums.SentCodeType.FRAGMENT_SMS: "Fragment SMS",
                enums.SentCodeType.FIREBASE_SMS: (
                    "SMS after Firebase attestation"
                ),
                enums.SentCodeType.EMAIL_CODE: "email",
                enums.SentCodeType.SETUP_EMAIL_REQUIRED: (
                    "add and verify email required"
                ),
            }

            print(
                f"The confirmation code has been sent via {sent_code_descriptions[sent_code.type]}"
            )

        while True:
            if not self.phone_code:
                self.phone_code = await ainput("Enter confirmation code: ")
            try:
                signed_in = await self.sign_in(
                    self.phone_number,
                    sent_code.phone_code_hash,
                    self.phone_code,
                )
            except BadRequest as e:
                print(e.MESSAGE)
                self.phone_code = None
            except SessionPasswordNeeded as e:
                print(e.MESSAGE)

                while True:
                    print(
                        "Password hint: {}".format(
                            await self.get_password_hint()
                        )
                    )

                    if not self.password:
                        self.password = await ainput(
                            "Enter password (empty to recover): ",
                            hide=self.hide_password,
                        )

                    try:
                        if not self.password:
                            confirm = await ainput(
                                "Confirm password recovery (y/n): "
                            )

                            if confirm == "y":
                                email_pattern = await self.send_recovery_code()
                                print(
                                    f"The recovery code has been sent to {email_pattern}"
                                )

                                while True:
                                    recovery_code = await ainput(
                                        "Enter recovery code: "
                                    )

                                    try:
                                        return await self.recover_password(
                                            recovery_code
                                        )
                                    except BadRequest as e:
                                        print(e.MESSAGE)
                                    except Exception as e:
                                        log.exception(e)
                                        raise
                            else:
                                self.password = None
                        else:
                            return await self.check_password(self.password)
                    except BadRequest as e:
                        print(e.MESSAGE)
                        self.password = None
            else:
                break

        if isinstance(signed_in, User):
            return signed_in

        while True:
            first_name = await ainput("Enter first name: ")
            last_name = await ainput("Enter last name (empty to skip): ")

            try:
                signed_up = await self.sign_up(
                    self.phone_number,
                    sent_code.phone_code_hash,
                    first_name,
                    last_name,
                )
            except BadRequest as e:
                print(e.MESSAGE)
            else:
                break

        if isinstance(signed_in, TermsOfService):
            print("\n" + signed_in.text + "\n")
            await self.accept_terms_of_service(signed_in.id)

        return signed_up

    def set_parse_mode(self, parse_mode: Optional["enums.ParseMode"]):
        self.parse_mode = parse_mode

    async def fetch_peers(
        self,
        peers: list[Union[raw.types.User, raw.types.Chat, raw.types.Channel]],
    ) -> bool:
        is_min = False
        parsed_peers = []

        for peer in peers:
            if getattr(peer, "min", False):
                is_min = True
                continue

            usernames = None
            phone_number = None

            if isinstance(peer, raw.types.User):
                peer_id = peer.id
                access_hash = peer.access_hash
                usernames = (
                    [peer.username.lower()]
                    if peer.username
                    else [
                        username.username.lower() for username in peer.usernames
                    ]
                    if peer.usernames
                    else None
                )
                phone_number = peer.phone
                peer_type = "bot" if peer.bot else "user"
            elif isinstance(peer, (raw.types.Chat, raw.types.ChatForbidden)):
                peer_id = -peer.id
                access_hash = 0
                peer_type = "group"
            elif isinstance(peer, raw.types.Channel):
                peer_id = utils.get_channel_id(peer.id)
                access_hash = peer.access_hash
                usernames = (
                    [peer.username.lower()]
                    if peer.username
                    else [
                        username.username.lower() for username in peer.usernames
                    ]
                    if peer.usernames
                    else None
                )
                peer_type = "channel" if peer.broadcast else "supergroup"
            elif isinstance(peer, raw.types.ChannelForbidden):
                peer_id = utils.get_channel_id(peer.id)
                access_hash = peer.access_hash
                peer_type = "channel" if peer.broadcast else "supergroup"
            else:
                continue

            parsed_peers.append(
                (peer_id, access_hash, peer_type, usernames, phone_number)
            )

        await self.storage.update_peers(parsed_peers)

        return is_min

    async def handle_updates(self, updates):
        self.last_update_time = datetime.now()

        if isinstance(
            updates, (raw.types.Updates, raw.types.UpdatesCombined)
        ):
            is_min = any(
                (
                    await self.fetch_peers(updates.users),
                    await self.fetch_peers(updates.chats),
                )
            )

            users = {u.id: u for u in updates.users}
            chats = {c.id: c for c in updates.chats}

            for update in updates.updates:
                channel_id = getattr(
                    getattr(getattr(update, "message", None), "peer_id", None),
                    "channel_id",
                    None,
                ) or getattr(update, "channel_id", None)

                pts = getattr(update, "pts", None)
                pts_count = getattr(update, "pts_count", None)

                if pts and not self.skip_updates:
                    await self.storage.update_state(
                        (
                            utils.get_channel_id(channel_id)
                            if channel_id
                            else 0,
                            pts,
                            None,
                            updates.date,
                            updates.seq,
                        )
                    )

                if isinstance(update, raw.types.UpdateChannelTooLong):
                    log.info(update)

                if (
                    isinstance(update, raw.types.UpdateNewChannelMessage)
                    and is_min
                ):
                    message = update.message

                    if not isinstance(message, raw.types.MessageEmpty):
                        try:
                            diff = await self.invoke(
                                raw.functions.updates.GetChannelDifference(
                                    channel=await self.resolve_peer(
                                        utils.get_channel_id(channel_id)
                                    ),
                                    filter=raw.types.ChannelMessagesFilter(
                                        ranges=[
                                            raw.types.MessageRange(
                                                min_id=update.message.id,
                                                max_id=update.message.id,
                                            )
                                        ]
                                    ),
                                    pts=pts - pts_count,
                                    limit=pts,
                                    force=False,
                                )
                            )
                        except (
                            ChannelPrivate,
                            PersistentTimestampOutdated,
                            PersistentTimestampInvalid,
                        ):
                            pass
                        else:
                            if not isinstance(
                                diff, raw.types.updates.ChannelDifferenceEmpty
                            ):
                                users.update({u.id: u for u in diff.users})
                                chats.update({c.id: c for c in diff.chats})

                self.dispatcher.updates_queue.put_nowait(
                    (update, users, chats)
                )
        elif isinstance(
            updates,
            (raw.types.UpdateShortMessage, raw.types.UpdateShortChatMessage),
        ):
            if not self.skip_updates:
                await self.storage.update_state(
                    (0, updates.pts, None, updates.date, None)
                )

            diff = await self.invoke(
                raw.functions.updates.GetDifference(
                    pts=updates.pts - updates.pts_count,
                    date=updates.date,
                    qts=-1,
                )
            )

            if diff.new_messages:
                self.dispatcher.updates_queue.put_nowait(
                    (
                        raw.types.UpdateNewMessage(
                            message=diff.new_messages[0],
                            pts=updates.pts,
                            pts_count=updates.pts_count,
                        ),
                        {u.id: u for u in diff.users},
                        {c.id: c for c in diff.chats},
                    )
                )
            else:
                if diff.other_updates:
                    self.dispatcher.updates_queue.put_nowait(
                        (diff.other_updates[0], {}, {})
                    )
        elif isinstance(updates, raw.types.UpdateShort):
            self.dispatcher.updates_queue.put_nowait((updates.update, {}, {}))
        elif isinstance(updates, raw.types.UpdatesTooLong):
            log.info(updates)

    async def recover_gaps(self) -> Tuple[int, int]:
        if self.skip_updates:
            log.info("Recover gaps disabled in client params. Skipping recovery")
            return (0, 0)

        states = await self.storage.update_state()

        if not states:
            log.info("No states found, skipping recovery")
            return (0, 0)

        message_updates_counter = 0
        other_updates_counter = 0

        log.info("Started gaps recovering...")

        for local_state in states:
            id, local_pts, local_qts, local_date, local_seq = local_state

            prev_pts = 0

            while True:
                try:
                    diff = await self.invoke(
                        raw.functions.updates.GetChannelDifference(
                            channel=await self.resolve_peer(id),
                            filter=raw.types.ChannelMessagesFilterEmpty(),
                            pts=local_pts,
                            limit=10000,
                            force=False,
                        )
                        if id < 0 or id > MIN_MONOFORUM_CHANNEL_ID
                        else raw.functions.updates.GetDifference(
                            pts=local_pts, date=local_date, qts=0
                        )
                    )
                except (
                    ChannelPrivate,
                    ChannelInvalid,
                    PersistentTimestampOutdated,
                    PersistentTimestampInvalid,
                ):
                    break

                if isinstance(diff, raw.types.updates.DifferenceEmpty):
                    await self.storage.update_state(
                        (id, local_pts, None, diff.date, diff.seq)
                    )
                    break
                elif isinstance(diff, raw.types.updates.DifferenceTooLong):
                    await self.storage.update_state(
                        (id, diff.pts, None, local_date, local_seq)
                    )
                    continue
                elif isinstance(diff, raw.types.updates.Difference):
                    local_pts = diff.state.pts
                    local_date = diff.state.date
                    local_seq = diff.state.seq
                elif isinstance(diff, raw.types.updates.DifferenceSlice):
                    local_pts = diff.intermediate_state.pts
                    local_date = diff.intermediate_state.date
                    local_seq = diff.intermediate_state.seq

                    if prev_pts == local_pts:
                        break

                    prev_pts = local_pts
                elif isinstance(diff, raw.types.updates.ChannelDifferenceEmpty):
                    await self.storage.update_state(
                        (id, diff.pts, None, local_date, local_seq)
                    )
                    break
                elif isinstance(
                    diff, raw.types.updates.ChannelDifferenceTooLong
                ):
                    await self.storage.update_state(
                        (id, diff.dialog.pts, None, local_date, local_seq)
                    )
                    continue
                elif isinstance(diff, raw.types.updates.ChannelDifference):
                    local_pts = diff.pts

                users = {i.id: i for i in diff.users}
                chats = {i.id: i for i in diff.chats}

                for message in diff.new_messages:
                    message_updates_counter += 1
                    self.dispatcher.updates_queue.put_nowait(
                        (
                            raw.types.UpdateNewMessage(
                                message=message, pts=local_pts, pts_count=-1
                            ),
                            users,
                            chats,
                        )
                    )

                for update in diff.other_updates:
                    other_updates_counter += 1
                    self.dispatcher.updates_queue.put_nowait(
                        (update, users, chats)
                    )

                if isinstance(
                    diff,
                    (
                        raw.types.updates.Difference,
                        raw.types.updates.ChannelDifference,
                    ),
                ):
                    break

            await self.storage.update_state(
                (id, local_pts, None, local_date, local_seq)
            )

        log.info(
            "Recovered %s messages and %s updates",
            message_updates_counter,
            other_updates_counter,
        )
        return (message_updates_counter, other_updates_counter)

    async def load_session(self):
        await self.storage.open()

        session_empty = any(
            [
                await self.storage.test_mode() is None,
                await self.storage.auth_key() is None,
                await self.storage.user_id() is None,
                await self.storage.is_bot() is None,
            ]
        )

        if session_empty:
            if not self.api_id or not self.api_hash:
                raise AttributeError(
                    "The API key is required for new authorizations. "
                    "More info: https://telegramplayground.github.io/pyrogram/start/auth"
                )

            await self.storage.api_id(self.api_id)

            await self.storage.dc_id(2)
            await self.storage.date(0)

            await self.storage.test_mode(self.test_mode)
            await self.storage.auth_key(
                await Auth(
                    self,
                    await self.storage.dc_id(),
                    await self.storage.test_mode(),
                ).create()
            )
            await self.storage.user_id(None)
            await self.storage.is_bot(None)
        else:
            if not await self.storage.api_id():
                if self.api_id:
                    await self.storage.api_id(self.api_id)
                else:
                    while True:
                        try:
                            value = int(
                                await ainput(
                                    "Enter the api_id part of the API key: "
                                )
                            )

                            if value <= 0:
                                print("Invalid value")
                                continue

                            confirm = (
                                await ainput(f'Is "{value}" correct? (y/N): ')
                            ).lower()

                            if confirm == "y":
                                await self.storage.api_id(value)
                                break
                        except Exception as e:
                            print(e)

    def load_plugins(self):
        if self.plugins:
            plugins = self.plugins.copy()

            for option in ["include", "exclude"]:
                if plugins.get(option, []):
                    plugins[option] = [
                        (i.split()[0], i.split()[1:] or None)
                        for i in self.plugins[option]
                    ]
        else:
            return

        if plugins.get("enabled", True):
            root = plugins["root"]
            include = plugins.get("include", [])
            exclude = plugins.get("exclude", [])

            count = 0

            if not include:
                for path in sorted(Path(root.replace(".", "/")).rglob("*.py")):
                    module_path = ".".join(path.parent.parts + (path.stem,))
                    module = import_module(module_path)

                    for name in vars(module).keys():
                        try:
                            for handler, group in getattr(
                                module, name
                            ).handlers:
                                if isinstance(handler, Handler) and isinstance(
                                    group, int
                                ):
                                    self.add_handler(handler, group)

                                    log.info(
                                        '[{}] [LOAD] {}("{}") in group {} from "{}"'.format(
                                            self.name,
                                            type(handler).__name__,
                                            name,
                                            group,
                                            module_path,
                                        )
                                    )

                                    count += 1
                        except Exception:
                            pass
            else:
                for path, handlers in include:
                    module_path = root + "." + path
                    warn_non_existent_functions = True

                    try:
                        module = import_module(module_path)
                    except ImportError:
                        log.warning(
                            '[%s] [LOAD] Ignoring non-existent module "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    if "__path__" in dir(module):
                        log.warning(
                            '[%s] [LOAD] Ignoring namespace "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    if handlers is None:
                        handlers = vars(module).keys()
                        warn_non_existent_functions = False

                    for name in handlers:
                        try:
                            for handler, group in getattr(
                                module, name
                            ).handlers:
                                if isinstance(handler, Handler) and isinstance(
                                    group, int
                                ):
                                    self.add_handler(handler, group)

                                    log.info(
                                        '[{}] [LOAD] {}("{}") in group {} from "{}"'.format(
                                            self.name,
                                            type(handler).__name__,
                                            name,
                                            group,
                                            module_path,
                                        )
                                    )

                                    count += 1
                        except Exception:
                            if warn_non_existent_functions:
                                log.warning(
                                    '[{}] [LOAD] Ignoring non-existent function "{}" from "{}"'.format(
                                        self.name, name, module_path
                                    )
                                )

            if exclude:
                for path, handlers in exclude:
                    module_path = root + "." + path
                    warn_non_existent_functions = True

                    try:
                        module = import_module(module_path)
                    except ImportError:
                        log.warning(
                            '[%s] [UNLOAD] Ignoring non-existent module "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    if "__path__" in dir(module):
                        log.warning(
                            '[%s] [UNLOAD] Ignoring namespace "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    if handlers is None:
                        handlers = vars(module).keys()
                        warn_non_existent_functions = False

                    for name in handlers:
                        try:
                            for handler, group in getattr(
                                module, name
                            ).handlers:
                                if isinstance(handler, Handler) and isinstance(
                                    group, int
                                ):
                                    self.remove_handler(handler, group)

                                    log.info(
                                        '[{}] [UNLOAD] {}("{}") from group {} in "{}"'.format(
                                            self.name,
                                            type(handler).__name__,
                                            name,
                                            group,
                                            module_path,
                                        )
                                    )

                                    count -= 1
                        except Exception:
                            if warn_non_existent_functions:
                                log.warning(
                                    '[{}] [UNLOAD] Ignoring non-existent function "{}" from "{}"'.format(
                                        self.name, name, module_path
                                    )
                                )

            if count > 0:
                log.info(
                    '[{}] Successfully loaded {} plugin{} from "{}"'.format(
                        self.name, count, "s" if count > 1 else "", root
                    )
                )
            else:
                log.warning(
                    '[%s] No plugin loaded from "%s"', self.name, root
                )

    async def handle_download(self, packet):
        (
            file_id,
            directory,
            file_name,
            in_memory,
            file_size,
            progress,
            progress_args,
        ) = packet

        if not in_memory:
            os.makedirs(directory, exist_ok=True)

        final_file_path = os.path.abspath(
            re.sub("\\\\", "/", os.path.join(directory, file_name))
        )
        temp_file_path = final_file_path + ".temp"

        # Use 1 MB write buffering for disk files to minimize OS I/O syscalls
        file = (
            BytesIO()
            if in_memory
            else open(temp_file_path, "wb", buffering=self.DISK_BUFFER_SIZE)
        )

        try:
            async for chunk in self.get_file(
                file_id, file_size, 0, 0, progress, progress_args
            ):
                file.write(chunk)
        except BaseException as e:
            if not in_memory:
                file.close()
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass

            if isinstance(e, asyncio.CancelledError):
                raise e

            return None
        else:
            if in_memory:
                file.name = file_name
                file.seek(0)
                return file
            else:
                file.flush()
                file.close()
                shutil.move(temp_file_path, final_file_path)
                return final_file_path

    async def _get_media_session(self, dc_id: int) -> Session:
        """Thread-safe media session pooler with automatic cross-DC auth export."""
        session = self.media_sessions.get(dc_id)
        if session:
            return session

        async with self.media_sessions_lock:
            session = self.media_sessions.get(dc_id)
            if session:
                return session

            storage_dc_id = await self.storage.dc_id()
            test_mode = await self.storage.test_mode()

            auth_key = (
                await Auth(self, dc_id, test_mode).create()
                if dc_id != storage_dc_id
                else await self.storage.auth_key()
            )

            session = Session(
                self, dc_id, auth_key, test_mode, is_media=True
            )
            await session.start()

            if dc_id != storage_dc_id:
                for _ in range(3):
                    exported_auth = await self.invoke(
                        raw.functions.auth.ExportAuthorization(dc_id=dc_id)
                    )
                    try:
                        await session.invoke(
                            raw.functions.auth.ImportAuthorization(
                                id=exported_auth.id,
                                bytes=exported_auth.bytes,
                            )
                        )
                    except AuthBytesInvalid:
                        continue
                    else:
                        break
                else:
                    await session.stop()
                    raise AuthBytesInvalid

            self.media_sessions[dc_id] = session
            return session

    async def _get_media_sessions(self, dc_id: int, count: int) -> list:
        """Return up to `count` warm media sessions for a DC (the first is the regular cached one).

        Extra sessions reuse the same auth key, so no new authorization export/import is needed.
        """
        first = await self._get_media_session(dc_id)

        async with self.media_sessions_lock:
            pool = self.media_session_pool.get(dc_id)

            if not pool or pool[0] is not first:
                pool = self.media_session_pool[dc_id] = [first]

            missing = count - len(pool)

            if missing > 0:
                test_mode = await self.storage.test_mode()
                new_sessions = [
                    Session(self, dc_id, first.auth_key, test_mode, is_media=True)
                    for _ in range(missing)
                ]
                results = await asyncio.gather(
                    *(s.start() for s in new_sessions), return_exceptions=True
                )

                for s, res in zip(new_sessions, results):
                    if isinstance(res, BaseException):
                        log.warning("Extra media session failed to start: %r", res)
                    else:
                        pool.append(s)

            return pool[:count]

    async def get_file(
        self,
        file_id: FileId,
        file_size: int = 0,
        limit: int = 0,
        offset: int = 0,
        progress: Callable = None,
        progress_args: tuple = (),
    ) -> Optional[AsyncGenerator[bytes, None]]:
        """
        High-performance pipelined MTProto file downloader:
        - Reuses persistent per-DC media sessions (zero repeated handshake overhead)
        - Pipelined prefetching: requests chunk N+1 while yielding/writing chunk N
        - MTProto-compliant adaptive chunk sizing (max 1 MB per Telegram API spec)
        """
        async with self.get_file_semaphore:
            file_type = file_id.file_type

            if file_type == FileType.CHAT_PHOTO:
                if file_id.chat_id > 0:
                    peer = raw.types.InputPeerUser(
                        user_id=file_id.chat_id,
                        access_hash=file_id.chat_access_hash,
                    )
                else:
                    if file_id.chat_access_hash == 0:
                        peer = raw.types.InputPeerChat(
                            chat_id=-file_id.chat_id
                        )
                    else:
                        peer = raw.types.InputPeerChannel(
                            channel_id=utils.get_channel_id(file_id.chat_id),
                            access_hash=file_id.chat_access_hash,
                        )

                location = raw.types.InputPeerPhotoFileLocation(
                    peer=peer,
                    photo_id=file_id.media_id,
                    big=file_id.thumbnail_source
                    == ThumbnailSource.CHAT_PHOTO_BIG,
                )
            elif file_type == FileType.PHOTO:
                location = raw.types.InputPhotoFileLocation(
                    id=file_id.media_id,
                    access_hash=file_id.access_hash,
                    file_reference=file_id.file_reference,
                    thumb_size=file_id.thumbnail_size,
                )
            else:
                location = raw.types.InputDocumentFileLocation(
                    id=file_id.media_id,
                    access_hash=file_id.access_hash,
                    file_reference=file_id.file_reference,
                    thumb_size=file_id.thumbnail_size,
                )

            # MTProto max limit is strictly 1048576 bytes (1 MB).
            # Use 1 MB chunks for files > 25 MB (or unknown size), 512 KB for smaller files.
            if file_size == 0 or file_size > 25 * 1024 * 1024:
                chunk_size = 1024 * 1024
            else:
                chunk_size = 512 * 1024

            current = 0
            total = abs(limit) or ((1 << 31) - 1)
            offset_bytes = abs(offset) * chunk_size
            dc_id = file_id.dc_id
            is_coro_progress = (
                inspect.iscoroutinefunction(progress) if progress else False
            )

            try:
                session = await self._get_media_session(dc_id)

                r = await session.invoke(
                    raw.functions.upload.GetFile(
                        location=location,
                        offset=offset_bytes,
                        limit=chunk_size,
                    ),
                    timeout=Session.MEDIA_WAIT_TIMEOUT,
                    sleep_threshold=self.sleep_threshold,
                )

                if isinstance(r, raw.types.upload.File):
                    # Parallel pipeline: keep a window of GetFile requests in flight,
                    # spread round-robin over several connections, yield strictly in order.
                    sessions = await self._get_media_sessions(
                        dc_id, self.DOWNLOAD_CONNECTIONS
                    )
                    window = len(sessions) * self.DOWNLOAD_PIPELINE_DEPTH
                    pending = deque()
                    next_offset = offset_bytes + chunk_size
                    scheduled = 1  # the first chunk was already fetched

                    def top_up():
                        nonlocal next_offset, scheduled

                        while (
                            len(pending) < window
                            and scheduled < total
                            and (file_size == 0 or next_offset < file_size)
                        ):
                            task = self.loop.create_task(
                                sessions[scheduled % len(sessions)].invoke(
                                    raw.functions.upload.GetFile(
                                        location=location,
                                        offset=next_offset,
                                        limit=chunk_size,
                                    ),
                                    timeout=Session.MEDIA_WAIT_TIMEOUT,
                                    sleep_threshold=self.sleep_threshold,
                                )
                            )
                            pending.append(task)
                            next_offset += chunk_size
                            scheduled += 1

                    try:
                        while True:
                            chunk = r.bytes
                            chunk_len = len(chunk)

                            current += 1
                            offset_bytes += chunk_len

                            is_last = (
                                chunk_len < chunk_size
                                or current >= total
                                or (file_size > 0 and offset_bytes >= file_size)
                            )

                            if not is_last:
                                top_up()

                            yield chunk

                            if progress:
                                func = functools.partial(
                                    progress,
                                    min(offset_bytes, file_size)
                                    if file_size != 0
                                    else offset_bytes,
                                    file_size,
                                    *progress_args,
                                )
                                if is_coro_progress:
                                    await func()
                                else:
                                    await self.loop.run_in_executor(
                                        self.executor, func
                                    )

                            if is_last:
                                break

                            r = await pending.popleft()
                    finally:
                        # Drop speculative requests (EOF, cancel, error) without leaking warnings
                        for task in pending:
                            task.cancel()
                            task.add_done_callback(
                                lambda t: t.cancelled() or t.exception()
                            )

                elif isinstance(r, raw.types.upload.FileCdnRedirect):
                    test_mode = await self.storage.test_mode()
                    cdn_session = Session(
                        self,
                        r.dc_id,
                        await Auth(self, r.dc_id, test_mode).create(),
                        test_mode,
                        is_media=True,
                        is_cdn=True,
                    )

                    try:
                        await cdn_session.start()

                        while True:
                            r2 = await cdn_session.invoke(
                                raw.functions.upload.GetCdnFile(
                                    file_token=r.file_token,
                                    offset=offset_bytes,
                                    limit=chunk_size,
                                )
                            )

                            if isinstance(
                                r2, raw.types.upload.CdnFileReuploadNeeded
                            ):
                                try:
                                    await session.invoke(
                                        raw.functions.upload.ReuploadCdnFile(
                                            file_token=r.file_token,
                                            request_token=r2.request_token,
                                        )
                                    )
                                except VolumeLocNotFound:
                                    break
                                else:
                                    continue

                            chunk = r2.bytes
                            chunk_len = len(chunk)

                            decrypted_chunk = aes.ctr256_decrypt(
                                chunk,
                                r.encryption_key,
                                bytearray(
                                    r.encryption_iv[:-4]
                                    + (offset_bytes // 16).to_bytes(4, "big")
                                ),
                            )

                            hashes = await session.invoke(
                                raw.functions.upload.GetCdnFileHashes(
                                    file_token=r.file_token,
                                    offset=offset_bytes,
                                )
                            )

                            for i, h in enumerate(hashes):
                                cdn_chunk = decrypted_chunk[
                                    h.limit * i : h.limit * (i + 1)
                                ]
                                CDNFileHashMismatch.check(
                                    h.hash == sha256(cdn_chunk).digest(),
                                    "h.hash == sha256(cdn_chunk).digest()",
                                )

                            yield decrypted_chunk

                            current += 1
                            offset_bytes += chunk_len

                            if progress:
                                func = functools.partial(
                                    progress,
                                    min(offset_bytes, file_size)
                                    if file_size != 0
                                    else offset_bytes,
                                    file_size,
                                    *progress_args,
                                )
                                if is_coro_progress:
                                    await func()
                                else:
                                    await self.loop.run_in_executor(
                                        self.executor, func
                                    )

                            if (
                                chunk_len < chunk_size
                                or current >= total
                                or (
                                    file_size > 0 and offset_bytes >= file_size
                                )
                            ):
                                break
                    finally:
                        await cdn_session.stop()
            except pyrogram.StopTransmission:
                raise
            except Exception as e:
                log.exception(e)

    def guess_mime_type(self, filename: str) -> Optional[str]:
        return self.mimetypes.guess_type(filename)[0]

    def guess_extension(self, mime_type: str) -> Optional[str]:
        return self.mimetypes.guess_extension(mime_type)


class Cache:
    """High-speed O(1) LRU Cache using OrderedDict."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self.store = OrderedDict()

    def __getitem__(self, key):
        value = self.store.get(key, None)
        if value is not None:
            self.store.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        if key in self.store:
            self.store.move_to_end(key)
        self.store[key] = value
        if len(self.store) > self.capacity:
            self.store.popitem(last=False)
