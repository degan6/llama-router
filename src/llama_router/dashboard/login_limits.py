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
        account_attempts: int = 5,
        ip_attempts: int = 20,
        window_seconds: int = 300,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if min(account_attempts, ip_attempts, window_seconds) < 1 or max_entries < 2:
            raise ValueError(
                "Login limits must be positive and max_entries at least two"
            )
        self._account_attempts = account_attempts
        self._ip_attempts = ip_attempts
        self._window_seconds = window_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._windows: OrderedDict[tuple[str, str], _Window] = OrderedDict()

    def reserve(self, client_ip: str, username: str | None) -> int:
        """Count an attempt, or return seconds until it can be retried.

        ``username`` must already be normalized, or None for malformed input.
        Entries expire in insertion order because all use the same duration.
        """
        now = self._clock()
        while self._windows:
            first = next(iter(self._windows.values()))
            if first.expires > now:
                break
            self._windows.popitem(last=False)
        limits = [(("ip", client_ip), self._ip_attempts)]
        if username is not None:
            limits.append((("account", username), self._account_attempts))
        blocked = [
            window.expires
            for key, limit in limits
            if (window := self._windows.get(key)) and window.attempts >= limit
        ]
        if blocked:
            return max(1, math.ceil(max(blocked) - now))
        missing = sum(key not in self._windows for key, _ in limits)
        if len(self._windows) + missing > self._max_entries:
            return max(1, math.ceil(next(iter(self._windows.values())).expires - now))
        for key, _ in limits:
            if key not in self._windows:
                self._windows[key] = _Window(now + self._window_seconds)
            self._windows[key].attempts += 1
        return 0
