"""Administrator lockout reset, audit visibility, and access control."""

from __future__ import annotations

import logging

import httpx
import pytest

from llama_router.config import settings
from llama_router.dashboard import routes
from llama_router.dashboard.auth_core import AUTH_COOKIE, hash_password, sign_session
from llama_router.dashboard.login_limits import LoginAttemptLimiter
from llama_router.database import Database


async def _sign_in(client: httpx.AsyncClient, db: Database, *, admin: bool) -> int:
    user_id = await db.create_dashboard_user(
        "test-user", hash_password("test-password"), admin
    )
    client.cookies.set(AUTH_COOKIE, sign_session(user_id, settings.session_secret))
    return user_id


def test_reset_clears_only_selected_address_and_restarts_escalation() -> None:
    limiter = LoginAttemptLimiter(ip_attempts=1)
    for ip in ["192.0.2.1", "192.0.2.2"]:
        assert limiter.reserve(ip) == 0
        assert limiter.reserve(ip) == 300
    assert limiter.reset("192.0.2.1")
    assert not limiter.is_blocked("192.0.2.1")
    assert limiter.is_blocked("192.0.2.2")
    assert not limiter.reset("192.0.2.99")
    assert limiter.reserve("192.0.2.1") == 0
    assert limiter.reserve("192.0.2.1") == 300


def test_security_snapshot_keeps_history_until_idle_reset() -> None:
    now = [0.0]
    limiter = LoginAttemptLimiter(ip_attempts=1, clock=lambda: now[0])
    assert limiter.reserve("192.0.2.1") == 0
    assert limiter.limited_addresses() == []
    assert limiter.reserve("192.0.2.1") == 300
    limit = limiter.limited_addresses()[0]
    assert (limit.client_ip, limit.retry_after, limit.cooldown_seconds) == (
        "192.0.2.1",
        300,
        300,
    )
    now[0] = 300
    limit = limiter.limited_addresses()[0]
    assert limit.retry_after == 0
    assert limit.reset_after == 3600
    now[0] = 3900
    assert limiter.limited_addresses() == []


@pytest.mark.parametrize("role", ["anonymous", "viewer"])
async def test_security_requires_administrator(
    dash_client: tuple[httpx.AsyncClient, Database],
    monkeypatch: pytest.MonkeyPatch,
    role: str,
) -> None:
    client, db = dash_client
    await _sign_in(client, db, admin=False)
    if role == "anonymous":
        client.cookies.clear()
    limiter = LoginAttemptLimiter(ip_attempts=1)
    monkeypatch.setattr(routes, "login_attempt_limiter", limiter)
    limiter.reserve("192.0.2.1")
    limiter.reserve("192.0.2.1")
    response = await client.get("/security")
    assert response.status_code == 302
    assert "192.0.2.1" not in response.text
    response = await client.post("/security/reset", data={"client_ip": "192.0.2.1"})
    assert response.status_code == 302
    assert limiter.is_blocked("192.0.2.1")


async def test_admin_reset_and_lockout_are_visible_in_log(
    dash_client: tuple[httpx.AsyncClient, Database],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    client, db = dash_client
    admin_id = await _sign_in(client, db, admin=True)
    monkeypatch.setattr(
        routes, "login_attempt_limiter", LoginAttemptLimiter(ip_attempts=1)
    )
    with caplog.at_level(logging.INFO):
        response = await client.post(
            "/login", data={"username": "private-name", "password": "private-password"}
        )
        assert response.status_code == 303
        for _ in range(2):
            response = await client.post(
                "/login",
                data={"username": "private-name", "password": "private-password"},
            )
            assert response.status_code == 429
        logs = await db.get_request_logs(limit=20)
        cooldowns = [entry for entry in logs if entry.endpoint == "/login"]
        assert len(cooldowns) == 1
        assert cooldowns[0].source_ip == "127.0.0.1"
        assert cooldowns[0].status == "error"
        assert "300 seconds" in (cooldowns[0].error_detail or "")
        response = await client.get("/security")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert "127.0.0.1" in response.text
        assert "Reset limits" in response.text
        response = await client.get("/")
        assert "Login cooldown: 300 seconds" in response.text
        response = await client.post("/security/reset", data={"client_ip": "127.0.0.1"})
        assert response.status_code == 303
        assert response.headers["location"] == "/security?reset=1"
        logs = await db.get_request_logs(limit=20)
        resets = [entry for entry in logs if entry.endpoint == "/security/reset"]
        assert len(resets) == 1
        assert (
            resets[0].request_meta
            == f"Admin {admin_id} reset login limits for 127.0.0.1"
        )
        response = await client.get("/")
        assert f"Admin {admin_id} reset login limits for 127.0.0.1" in response.text
        response = await client.get("/security?reset=1")
        assert "No login cooldowns or escalation history" in response.text
        response = await client.post(
            "/login", data={"username": "test-user", "password": "test-password"}
        )
        assert response.status_code == 303
        assert AUTH_COOKIE in response.cookies
    assert "reset password login limits for 127.0.0.1" in caplog.text
    assert "Password sign-in blocked" in caplog.text
    assert "private-name" not in caplog.text
    assert "private-password" not in caplog.text
    assert all("private-" not in str(entry) for entry in logs)


async def test_cross_site_reset_is_refused(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await _sign_in(client, db, admin=True)
    limiter = LoginAttemptLimiter(ip_attempts=1)
    monkeypatch.setattr(routes, "login_attempt_limiter", limiter)
    limiter.reserve("192.0.2.1")
    limiter.reserve("192.0.2.1")
    response = await client.post(
        "/security/reset",
        data={"client_ip": "192.0.2.1"},
        headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403
    assert limiter.is_blocked("192.0.2.1")


async def test_capacity_rejections_do_not_log_fake_cooldowns(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await _sign_in(client, db, admin=True)
    limiter = LoginAttemptLimiter(ip_attempts=1, max_entries=1)
    monkeypatch.setattr(routes, "login_attempt_limiter", limiter)
    limiter.reserve("192.0.2.1")
    for _ in range(2):
        response = await client.post(
            "/login", data={"username": "test-user", "password": "test-password"}
        )
        assert response.status_code == 429
    logs = await db.get_request_logs(limit=20)
    assert not [entry for entry in logs if entry.endpoint == "/login"]
    assert limiter.limited_addresses() == []


async def test_management_keys_cannot_view_or_reset_login_limits(
    dash_client: tuple[httpx.AsyncClient, Database], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, db = dash_client
    await _sign_in(client, db, admin=True)
    response = await client.post(
        "/api/management-keys",
        json={"name": "security-test", "privileges": ["keys:write"]},
    )
    assert response.status_code == 200
    token = response.json()["management_key"]
    client.cookies.clear()
    headers = {"Authorization": f"Bearer {token}"}
    limiter = LoginAttemptLimiter(ip_attempts=1)
    monkeypatch.setattr(routes, "login_attempt_limiter", limiter)
    limiter.reserve("192.0.2.1")
    limiter.reserve("192.0.2.1")
    response = await client.get("/security", headers=headers)
    assert response.status_code == 403
    response = await client.post(
        "/security/reset", data={"client_ip": "192.0.2.1"}, headers=headers
    )
    assert response.status_code == 403
    assert limiter.is_blocked("192.0.2.1")
