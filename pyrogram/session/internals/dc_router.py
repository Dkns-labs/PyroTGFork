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

import os
import time
from typing import Dict, List, Tuple

from .data_center import DataCenter

Endpoint = Tuple[str, int]


class _Health:
    __slots__ = ("fails", "last_fail", "last_ok", "rtt")

    def __init__(self):
        self.fails = 0
        self.last_fail = 0.0
        self.last_ok = 0.0
        self.rtt = None  # EWMA of TCP+handshake time in seconds


class DCRouter:
    """Ordered endpoint candidates for a data center, with a process-wide health table.

    Telegram data centers accept MTProto on several ports and, for DC2/DC4, expose a dedicated
    media address. A route that stops working (blocked port, overloaded media address) used to
    be retried forever. The router keeps the static preference order, but demotes an endpoint
    that failed recently so reconnects go straight to one that works.

    Order for production DCs:
        1. media address on the default port (only DCs that have one)
        2. regular address on the default port
        3. regular address on the alternate ports (80, 5222)

    Environment:
        PYROGRAM_DC_FALLBACK_PORTS=0   disable alternate ports (use only the default port)
        PYROGRAM_DC_COOLDOWN=<sec>     how long a failed endpoint stays demoted (default 30)
    """

    ALT_PORTS = (80, 5222)
    COOLDOWN = float(os.environ.get("PYROGRAM_DC_COOLDOWN", 30))
    USE_ALT_PORTS = os.environ.get("PYROGRAM_DC_FALLBACK_PORTS", "1") != "0"
    RTT_ALPHA = 0.3

    _health: Dict[Endpoint, _Health] = {}

    @classmethod
    def _entry(cls, endpoint: Endpoint) -> _Health:
        entry = cls._health.get(endpoint)

        if entry is None:
            entry = cls._health[endpoint] = _Health()

        return entry

    @classmethod
    def static_candidates(cls, dc_id: int, test_mode: bool, ipv6: bool, media: bool) -> List[Endpoint]:
        primary = DataCenter(dc_id, test_mode, ipv6, media)
        candidates = [primary]

        if test_mode:
            return candidates

        regular = DataCenter(dc_id, test_mode, ipv6, False)

        if regular != primary:
            candidates.append(regular)

        if cls.USE_ALT_PORTS and primary[1] == DataCenter.PROD_PORT:
            for port in cls.ALT_PORTS:
                alt = (regular[0], port)

                if alt not in candidates:
                    candidates.append(alt)

        return candidates

    @classmethod
    def candidates(cls, dc_id: int, test_mode: bool, ipv6: bool, media: bool = False) -> List[Endpoint]:
        now = time.monotonic()
        healthy: List[Endpoint] = []
        cooling: List[Endpoint] = []

        for endpoint in cls.static_candidates(dc_id, test_mode, ipv6, media):
            entry = cls._health.get(endpoint)

            if entry is not None and entry.fails and now - entry.last_fail < cls.COOLDOWN:
                cooling.append(endpoint)
            else:
                healthy.append(endpoint)

        # Endpoints in cooldown are still tried, but only after every healthy one,
        # least recently failed first.
        cooling.sort(key=lambda e: cls._health[e].last_fail)

        return healthy + cooling

    @classmethod
    def record_success(cls, endpoint: Endpoint, rtt: float = None):
        entry = cls._entry(endpoint)
        entry.fails = 0
        entry.last_ok = time.monotonic()

        if rtt is not None:
            entry.rtt = rtt if entry.rtt is None else entry.rtt + cls.RTT_ALPHA * (rtt - entry.rtt)

    @classmethod
    def record_failure(cls, endpoint: Endpoint):
        entry = cls._entry(endpoint)
        entry.fails += 1
        entry.last_fail = time.monotonic()

    @classmethod
    def stats(cls) -> Dict[Endpoint, dict]:
        """Snapshot of what the router currently knows, for debugging."""
        return {
            endpoint: {"fails": e.fails, "rtt": e.rtt, "last_ok": e.last_ok, "last_fail": e.last_fail}
            for endpoint, e in cls._health.items()
        }

    @classmethod
    def reset(cls):
        cls._health.clear()
