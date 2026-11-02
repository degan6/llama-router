"""Users see only requests attributable to their own current API keys."""

from __future__ import annotations

import httpx
import pytest

from llama_router.config import settings
from llama_router.dashboard.auth_core import AUTH_COOKIE, hash_password, sign_session
from llama_router.database import Database
from llama_router.models import RequestLog


async def test_log_ownership_filters_before_pagination(db: Database) -> None:
    owner = await db.create_dashboard_user(
        "owner", hash_password("password-123"), False
    )
    other = await db.create_dashboard_user(
        "other", hash_password("password-123"), False
    )
    keys = [
        await db.create_api_key(str(i), str(i), "balanced", True, owner_user_id=uid)
        for i, uid in enumerate([owner, owner, other, None])
    ]
    for i, key in enumerate([*keys, None]):
        await db.save_request_log(
            RequestLog(protocol="ollama", endpoint=f"/request/{i}", api_key_id=key)
        )
    assert await db.count_request_logs() == 5
    assert await db.count_request_logs(owner_user_id=owner) == 2
    rows = await db.get_request_logs(limit=1, owner_user_id=owner)
    assert [r.endpoint for r in rows] == ["/request/1"]
    rows = await db.get_request_logs(limit=1, offset=1, owner_user_id=owner)
    assert [r.endpoint for r in rows] == ["/request/0"]
    await db.delete_api_key(keys[1])
    assert await db.count_request_logs(owner_user_id=owner) == 1
    assert await db.count_request_logs() == 5


@pytest.mark.parametrize("page", ["1", "2", "-1", "invalid", "999"])
async def test_dashboard_logs_and_live_count_are_user_scoped(
    dash_client: tuple[httpx.AsyncClient, Database], page: str
) -> None:
    client, db = dash_client
    owner = await db.create_dashboard_user(
        "owner", hash_password("password-123"), False
    )
    other = await db.create_dashboard_user(
        "other", hash_password("password-123"), False
    )
    admin = await db.create_dashboard_user("admin", hash_password("password-123"), True)
    for i, uid in enumerate([owner, other, None]):
        key = await db.create_api_key(
            str(i), str(i), "balanced", True, owner_user_id=uid
        )
        await db.save_request_log(
            RequestLog(
                protocol="ollama",
                endpoint=f"/unique-request-{i}",
                api_key_id=key,
                status="error",
                error_detail="internal-backend-address",
            )
        )
    await db.save_request_log(RequestLog(protocol="system", endpoint="/system-event"))
    client.cookies.set(AUTH_COOKIE, sign_session(owner, settings.session_secret))
    response = await client.get(f"/?log_page={page}&owner_user_id={other}")
    assert response.status_code == 200
    assert 'id="log-pane"' in response.text
    assert "/unique-request-0" in response.text
    assert "/unique-request-1" not in response.text
    assert "/unique-request-2" not in response.text
    assert "/system-event" not in response.text
    assert "internal-backend-address" not in response.text
    response = await client.get(f"/api/status?owner_user_id={other}")
    assert response.json()["log_total"] == 1

    client.cookies.set(AUTH_COOKIE, sign_session(admin, settings.session_secret))
    response = await client.get("/")
    for endpoint in [
        "/unique-request-0",
        "/unique-request-1",
        "/unique-request-2",
        "/system-event",
    ]:
        assert endpoint in response.text
    assert "internal-backend-address" in response.text
    assert (await client.get("/api/status")).json()["log_total"] == 4

    client.cookies.set(AUTH_COOKIE, sign_session(other, settings.session_secret))
    await db.delete_owned_api_key(
        (await db.list_api_keys(owner_user_id=other))[0]["id"], other
    )
    response = await client.get("/")
    assert "No requests logged for your current API keys yet." in response.text
    assert "/unique-request-0" not in response.text
    assert (await client.get("/api/status")).json()["log_total"] == 0
