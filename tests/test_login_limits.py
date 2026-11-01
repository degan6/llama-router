"""Password attempt budgets, expiry, and dashboard enforcement."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from pydantic import ValidationError

from llama_router.config import Settings
from llama_router.dashboard import routes
from llama_router.dashboard.auth_core import AUTH_COOKIE, hash_password
from llama_router.dashboard.login_limits import LoginAttemptLimiter
from llama_router.database import Database


def test_too_small_store_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_entries"):
        LoginAttemptLimiter(max_entries=1)


def test_account_limit_spans_client_addresses_and_expires() -> None:
    now = [100.0]
    limiter = LoginAttemptLimiter(account_attempts=5, clock=lambda: now[0])
    for i in range(5):
        assert limiter.reserve(f"client-{i}", "alice") == 0
    assert limiter.reserve("another-client", "alice") == 300
    now[0] += 299.1
    assert limiter.reserve("another-client", "alice") == 1
    now[0] += 0.9
    assert limiter.reserve("another-client", "alice") == 0


def test_address_limit_spans_accounts_and_invalid_usernames() -> None:
    limiter = LoginAttemptLimiter(ip_attempts=3)
    assert limiter.reserve("one", "alice") == 0
    assert limiter.reserve("one", "bob") == 0
    assert limiter.reserve("one", None) == 0
    assert limiter.reserve("one", "carol") > 0
    assert limiter.reserve("two", "carol") == 0


def test_capacity_does_not_evict_active_limits_and_recovers() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(
        account_attempts=5, max_entries=2, clock=lambda: now[0]
    )
    assert limiter.reserve("one", "alice") == 0
    assert limiter.reserve("two", "bob") == 300
    # Existing keys still have their original budget.
    for _ in range(4):
        assert limiter.reserve("one", "alice") == 0
    assert limiter.reserve("one", "alice") == 300
    now[0] = 300
    assert limiter.reserve("two", "bob") == 0


@pytest.mark.parametrize(
    "name",
    [
        "dashboard_login_account_attempts",
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
    calls = 0

    def verify(password: str, stored: str | None) -> bool:
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(routes, "verify_password", verify)
    responses = await asyncio.gather(
        *(
            client.post("/login", data={"username": "alice", "password": "bad"})
            for _ in range(35)
        )
    )
    assert sum(r.status_code == 303 for r in responses) == 30
    assert sum(r.status_code == 429 for r in responses) == 5
    assert calls == 30
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
    for _ in range(5):
        response = await client.post(
            "/login", data={"username": username, "password": "bad"}
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login?error=invalid"
    # Changing username case/whitespace and spoofing forwarded headers cannot
    # bypass either budget. Correct credentials are also blocked until expiry.
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


@pytest.mark.asyncio
async def test_successful_signins_do_not_reset_attempt_budgets(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await db.create_dashboard_user("alice", hash_password("right-password"), True)
    monkeypatch.setattr(
        routes, "login_attempt_limiter", LoginAttemptLimiter(account_attempts=1)
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
