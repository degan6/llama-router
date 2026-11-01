"""Password attempt budgets, expiry, and dashboard enforcement."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from pydantic import ValidationError

from llama_router.config import Settings
from llama_router.dashboard import routes
from llama_router.dashboard.app import app as dashboard_app
from llama_router.dashboard.auth_core import AUTH_COOKIE, hash_password
from llama_router.dashboard.login_limits import LoginAttemptLimiter
from llama_router.database import Database


@pytest.mark.parametrize(
    ("ip_attempts", "window_seconds", "max_entries"),
    [(0, 300, 10_000), (120, 0, 10_000), (120, 300, 0)],
)
def test_nonpositive_limits_are_rejected(
    ip_attempts: int, window_seconds: int, max_entries: int
) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        LoginAttemptLimiter(
            ip_attempts=ip_attempts,
            window_seconds=window_seconds,
            max_entries=max_entries,
        )


def test_address_limit_expires_without_extending_on_blocked_attempts() -> None:
    now = [100.0]
    limiter = LoginAttemptLimiter(ip_attempts=5, clock=lambda: now[0])
    for _ in range(5):
        assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    assert limiter.reserve("two") == 0
    now[0] += 299.1
    assert limiter.reserve("one") == 1
    now[0] += 0.9
    assert limiter.reserve("one") == 0


def test_capacity_does_not_evict_active_limits_and_recovers() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=5, max_entries=1, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    assert limiter.reserve("two") == 3600
    for _ in range(4):
        assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    now[0] = 300
    assert limiter.reserve("two") == 3600
    now[0] = 3900
    assert limiter.reserve("two") == 0


def test_full_cooldown_starts_when_limit_is_hit() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    now[0] = 299
    assert limiter.reserve("one") == 300
    now[0] = 300
    assert limiter.reserve("one") == 299
    now[0] = 599
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 600


def test_idle_reset_preserves_longer_attempt_windows() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(
        ip_attempts=1, window_seconds=7200, max_entries=1, clock=lambda: now[0]
    )
    assert limiter.reserve("one") == 0
    now[0] = 3600
    assert limiter.reserve("two") == 3600
    assert limiter.reserve("one") == 3600
    now[0] = 7200
    assert limiter.reserve("one") == 0


def test_repeated_cooldowns_double_and_cap_at_one_hour() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    for cooldown in [300, 600, 1200, 2400, 3600, 3600]:
        assert limiter.reserve("one") == 0
        assert limiter.reserve("one") == cooldown
        now[0] += cooldown - 0.5
        assert limiter.reserve("one") == 1
        now[0] += 0.5


def test_escalation_resets_after_one_idle_hour_following_cooldown() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    now[0] = 300 + 3600
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300


def test_new_attempts_restart_the_idle_reset_timer() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    now[0] = 300 + 3599
    assert limiter.reserve("one") == 0
    now[0] += 1
    assert limiter.reserve("one") == 600


def test_attempt_window_can_expire_without_resetting_escalation() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    now[0] = 300
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    now[0] = 600
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 600


def test_capacity_cleanup_uses_idle_expiry_instead_of_insertion_order() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, max_entries=2, clock=lambda: now[0])
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 300
    now[0] = 10
    assert limiter.reserve("two") == 0
    now[0] = 20
    assert limiter.reserve("three") == 3590
    now[0] = 3610
    assert limiter.reserve("three") == 0
    assert limiter.reserve("one") == 0
    assert limiter.reserve("one") == 600


@pytest.mark.parametrize(
    "name",
    [
        "dashboard_login_ip_attempts",
        "dashboard_login_window_seconds",
    ],
)
def test_settings_reject_nonpositive_limits(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LLAMA_ROUTER_" + name.upper(), "0")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.asyncio
async def test_concurrent_attempts_reserve_before_credential_lookup(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await db.create_dashboard_user("alice", hash_password("right-password"), True)
    monkeypatch.setattr(
        routes, "login_attempt_limiter", LoginAttemptLimiter(ip_attempts=5)
    )
    calls = 0

    def verify(password: str, stored: str | None) -> bool:
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(routes, "verify_password", verify)
    responses = await asyncio.gather(
        *(
            client.post("/login", data={"username": "alice", "password": "bad"})
            for _ in range(10)
        )
    )
    assert sum(r.status_code == 303 for r in responses) == 5
    assert sum(r.status_code == 429 for r in responses) == 5
    assert calls == 5
    for response in responses:
        if response.status_code == 429:
            assert 1 <= int(response.headers["Retry-After"]) <= 300
            assert response.headers["Cache-Control"] == "no-store"
            assert AUTH_COOKIE not in response.cookies


@pytest.mark.asyncio
@pytest.mark.parametrize("username", ["alice", "missing", "bad name"])
async def test_login_limits_and_cooldown(
    dash_client: tuple[httpx.AsyncClient, Database],
    monkeypatch: pytest.MonkeyPatch,
    username: str,
) -> None:
    client, db = dash_client
    await db.create_dashboard_user("alice", hash_password("right-password"), True)
    now = [100.0]
    monkeypatch.setattr(
        routes,
        "login_attempt_limiter",
        LoginAttemptLimiter(ip_attempts=5, clock=lambda: now[0]),
    )
    for attempt in range(5):
        response = await client.post(
            "/login",
            data={"username": username if attempt % 2 else "bob", "password": "bad"},
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?error=invalid"
    response = await client.post(
        "/login",
        data={"username": " ALICE ", "password": "right-password"},
        headers={"X-Forwarded-For": "192.0.2.99", "X-Real-IP": "192.0.2.98"},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "300"
    assert AUTH_COOKIE not in response.cookies
    now[0] += 300
    response = await client.post(
        "/login", data={"username": " ALICE ", "password": "right-password"}
    )
    assert response.status_code == 303
    assert AUTH_COOKIE in response.cookies
    for _ in range(4):
        response = await client.post(
            "/login", data={"username": username, "password": "bad"}
        )
        assert response.status_code == 303
    response = await client.post(
        "/login", data={"username": "alice", "password": "right-password"}
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "600"
    assert AUTH_COOKIE not in response.cookies


@pytest.mark.asyncio
async def test_successful_signins_count_toward_address_limit(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await db.create_dashboard_user("alice", hash_password("right-password"), True)
    monkeypatch.setattr(
        routes, "login_attempt_limiter", LoginAttemptLimiter(ip_attempts=1)
    )
    response = await client.post(
        "/login", data={"username": "alice", "password": "right-password"}
    )
    assert AUTH_COOKIE in response.cookies
    response = await client.post(
        "/login", data={"username": " ALICE ", "password": "right-password"}
    )
    assert response.status_code == 429
    assert (await client.get("/")).status_code == 200


@pytest.mark.asyncio
async def test_same_account_can_sign_in_from_another_address(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await db.create_dashboard_user("alice", hash_password("right-password"), True)
    monkeypatch.setattr(
        routes, "login_attempt_limiter", LoginAttemptLimiter(ip_attempts=1)
    )
    response = await client.post(
        "/login", data={"username": "alice", "password": "bad"}
    )
    assert response.status_code == 303
    response = await client.post(
        "/login", data={"username": "alice", "password": "right-password"}
    )
    assert response.status_code == 429
    transport = httpx.ASGITransport(app=dashboard_app, client=("192.0.2.1", 12345))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as other:
        response = await other.post(
            "/login", data={"username": "alice", "password": "right-password"}
        )
    assert response.status_code == 303
    assert AUTH_COOKIE in response.cookies
