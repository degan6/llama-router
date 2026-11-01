"""Password hashing and signed session tokens for the dashboard."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

AUTH_COOKIE = "lr_session"
SESSION_MAX_AGE = 14 * 24 * 3600


@dataclass(frozen=True)
class DashboardUser:
    id: int
    username: str
    is_admin: bool
    auth_source: str = "local"

    @property
    def is_sso(self) -> bool:
        return self.auth_source == "oidc"


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return f"{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        # Accounts that sign in through OIDC have no password.
        return False
    try:
        sh, kh = stored.split(":")
        salt = bytes.fromhex(sh)
        expected = bytes.fromhex(kh)
    except ValueError, TypeError:
        return False
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return secrets.compare_digest(dk, expected)


@dataclass(frozen=True)
class SessionClaims:
    user_id: int
    mfa_version: int
    mfa_verified: bool
    authenticated_at: int


def sign_session(
    user_id: int, secret: str, *, mfa_version: int = 0, mfa_verified: bool = False
) -> str:
    ser = URLSafeTimedSerializer(secret, salt="lr-dash-v1")
    return ser.dumps(
        {"u": user_id, "v": mfa_version, "mfa": mfa_verified, "at": int(time.time())}
    )


def session_claims(token: str, secret: str) -> SessionClaims | None:
    ser = URLSafeTimedSerializer(secret, salt="lr-dash-v1")
    try:
        d = ser.loads(token, max_age=SESSION_MAX_AGE)
        return SessionClaims(
            int(d["u"]), int(d.get("v", 0)), d.get("mfa") is True, int(d.get("at", 0))
        )
    except BadSignature, SignatureExpired, KeyError, TypeError, ValueError:
        return None


def unsign_session(token: str, secret: str) -> int | None:
    claims = session_claims(token, secret)
    return claims.user_id if claims else None


def normalize_username(username: str) -> str:
    s = username.strip().lower()
    if len(s) < 2 or len(s) > 64:
        raise ValueError("Username must be 2–64 characters")  # noqa: RUF001
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
    if not all(c in allowed for c in s):
        raise ValueError(
            "Username may only contain letters, digits, period, underscore, hyphen"
        )
    return s


_NON_ADMIN_FORBIDDEN_PREFIXES = (
    "/api/keys",
    "/api/management-keys",
    "/api/workers",
    "/api/worker-link",
    "/api/cache",
    "/api/fallbacks",
    "/api/pulls",
    "/api/auth/allow-unauthenticated",
)


def non_admin_forbidden_get_path(path: str) -> bool:
    if path == "/users" or path.startswith("/users/"):
        return True
    for prefix in _NON_ADMIN_FORBIDDEN_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return path.startswith("/api/benchmarks/fill-missing")
