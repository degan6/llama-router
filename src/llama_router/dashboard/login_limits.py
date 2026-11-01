"""Bounded, process-local password attempt windows for the dashboard."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass

_MAX_COOLDOWN_SECONDS = 3600
_RESET_SECONDS = 3600


@dataclass
class _Window:
    expires: float
    reset_at: float
    attempts: int = 0
    cooldown_seconds: int = 0
    blocked_until: float = 0.0


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
        self._windows: dict[str, _Window] = {}

    def reserve(self, client_ip: str) -> int:
        """Count an attempt and return zero, or return retry seconds if blocked."""
        now = self._clock()
        window = self._windows.get(client_ip)
        if window is None or max(window.expires, window.reset_at) <= now:
            if window is None and len(self._windows) >= self._max_entries:
                self._windows = {
                    ip: entry
                    for ip, entry in self._windows.items()
                    if max(entry.expires, entry.reset_at) > now
                }
                if len(self._windows) >= self._max_entries:
                    earliest_reset = min(
                        max(w.expires, w.reset_at) for w in self._windows.values()
                    )
                    return max(1, math.ceil(earliest_reset - now))
            window = _Window(now + self._window_seconds, now + _RESET_SECONDS)
            self._windows[client_ip] = window
        if window.blocked_until > now:
            return max(1, math.ceil(window.blocked_until - now))
        if window.reset_at <= now:
            window.cooldown_seconds = 0
        if window.expires <= now:
            window.attempts = 0
            window.expires = now + self._window_seconds
        if window.attempts >= self._ip_attempts:
            window.cooldown_seconds = min(
                window.cooldown_seconds * 2 or self._window_seconds,
                _MAX_COOLDOWN_SECONDS,
            )
            window.blocked_until = now + window.cooldown_seconds
            window.expires = window.blocked_until
            window.reset_at = window.blocked_until + _RESET_SECONDS
            return window.cooldown_seconds
        window.attempts += 1
        window.reset_at = now + _RESET_SECONDS
        return 0
