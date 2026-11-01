"""Bounded, process-local password attempt windows for the dashboard."""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _Window:
    expires: float
    attempts: int = 0


class LoginAttemptLimiter:
    """Reserve attempts synchronously before any credential lookup or hashing.

    All attempts count, including successful sign-ins. No await occurs during
    reservation, so concurrent requests on the server event loop cannot race.
    Active entries are never evicted to make room for attacker-chosen keys.
    """

    def __init__(
        self,
        *,
        ip_attempts: int = 120,
        window_seconds: int = 300,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(ip_attempts, window_seconds, max_entries) < 1:
            raise ValueError("Login limits and max_entries must be positive")
        self._ip_attempts = ip_attempts
        self._window_seconds = window_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._windows: OrderedDict[str, _Window] = OrderedDict()

    def reserve(self, client_ip: str) -> int:
        """Count an attempt and return zero, or return retry seconds if blocked.

        Entries expire in insertion order because all use the same duration.
        """
        now = self._clock()
        while self._windows:
            first = next(iter(self._windows.values()))
            if first.expires > now:
                break
            self._windows.popitem(last=False)
        window = self._windows.get(client_ip)
        if window is None:
            if len(self._windows) >= self._max_entries:
                first = next(iter(self._windows.values()))
                return max(1, math.ceil(first.expires - now))
            window = _Window(now + self._window_seconds)
            self._windows[client_ip] = window
        if window.attempts >= self._ip_attempts:
            return max(1, math.ceil(window.expires - now))
        window.attempts += 1
        return 0
