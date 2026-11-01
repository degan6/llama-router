"""API keys dashboard users issue to themselves."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException
from starlette.requests import Request

from llama_router.auth import key_hash, routing_preferences_from_request
from llama_router.config import settings
from llama_router.dashboard.auth_core import AUTH_COOKIE, hash_password, sign_session
from llama_router.dashboard.middleware import invalidate_dashboard_user_count_cache
from llama_router.database import Database

DashClient = tuple[httpx.AsyncClient, Database]


def _as(user_id: int) -> dict[str, str]:
    token = sign_session(user_id, settings.session_secret.strip())
    return {"Cookie": f"{AUTH_COOKIE}={token}"}


async def _users(db: Database) -> tuple[int, int, int]:
    admin = await db.create_dashboard_user("adm", hash_password("pw-123456789"), True)
    ann = await db.create_dashboard_user("ann", hash_password("pw-123456789"), False)
    bob = await db.create_dashboard_user("bob", hash_password("pw-123456789"), False)
    invalidate_dashboard_user_count_cache()
    return admin, ann, bob


async def test_viewer_issues_lists_and_revokes_own_key(dash_client: DashClient) -> None:
    c, db = dash_client
    _, ann, _ = await _users(db)

    page = await c.get("/my-keys", headers=_as(ann))
    assert page.status_code == 200
    assert "my-keys-body" in page.text

    resp = await c.post(
        "/api/my-keys",
        json={"routing_mode": "latency", "allow_fallback": False},
        headers=_as(ann),
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # Admin defaults not set yet: local providers only, no cap.
    assert (data["locality"], data["daily_spend_cap_usd"]) == ("local", None)
    found = await db.lookup_api_key(key_hash(data["api_key"]))
    assert found is not None
    assert (found["routing_mode"], found["allow_fallback"]) == ("latency", False)

    mine = (await c.get("/api/my-keys", headers=_as(ann))).json()
    assert [k["id"] for k in mine["keys"]] == [data["id"]]
    assert mine["keys"][0]["owner_username"] == "ann"
    assert "api_key" not in mine["keys"][0]

    gone = await c.delete(f"/api/my-keys/{data['id']}", headers=_as(ann))
    assert gone.status_code == 200
    assert await db.lookup_api_key(key_hash(data["api_key"])) is None


async def test_users_cannot_see_or_revoke_others_keys(dash_client: DashClient) -> None:
    c, db = dash_client
    admin, ann, bob = await _users(db)
    key = (await c.post("/api/my-keys", json={}, headers=_as(ann))).json()

    assert (await c.get("/api/my-keys", headers=_as(bob))).json()["keys"] == []
    resp = await c.delete(f"/api/my-keys/{key['id']}", headers=_as(bob))
    assert resp.status_code == 404
    # Not even an admin revokes through this API; they use /api/keys.
    resp = await c.delete(f"/api/my-keys/{key['id']}", headers=_as(admin))
    assert resp.status_code == 404
    assert await db.lookup_api_key(key_hash(key["api_key"])) is not None


async def test_viewer_still_cannot_use_admin_key_api(dash_client: DashClient) -> None:
    c, db = dash_client
    _, ann, _ = await _users(db)
    resp = await c.post("/api/keys/generate", json={}, headers=_as(ann))
    assert resp.status_code == 403
    resp = await c.put(
        "/api/keys/self-service", json={"locality": "any"}, headers=_as(ann)
    )
    assert resp.status_code == 403


async def test_admin_defaults_apply_to_new_keys(dash_client: DashClient) -> None:
    c, db = dash_client
    admin, ann, _ = await _users(db)
    resp = await c.put(
        "/api/keys/self-service",
        json={"locality": "any", "daily_spend_cap_usd": "2.50"},
        headers=_as(admin),
    )
    assert resp.status_code == 200
    assert resp.json() == {"locality": None, "daily_spend_cap_usd": 2.5}

    # The user can't override the limits.
    data = (
        await c.post(
            "/api/my-keys",
            json={"locality": "cloud", "daily_spend_cap_usd": None},
            headers=_as(ann),
        )
    ).json()
    found = await db.lookup_api_key(key_hash(data["api_key"]))
    assert found is not None
    assert (found["locality"], found["daily_spend_cap_usd"]) == (None, 2.5)

    listed = await c.get("/api/keys", headers=_as(admin))
    [row] = listed.json()["keys"]
    assert (row["owner_user_id"], row["owner_username"]) == (ann, "ann")

    bad = await c.put(
        "/api/keys/self-service", json={"locality": "moon"}, headers=_as(admin)
    )
    assert bad.status_code == 400


@pytest.mark.parametrize("is_admin", [False, True], ids=["viewer", "admin"])
@pytest.mark.parametrize("header", ["API-KEY", "Authorization"])
async def test_deleting_user_deletes_keys_and_rejects_cached_auth(
    dash_client: DashClient,
    monkeypatch: pytest.MonkeyPatch,
    is_admin: bool,
    header: str,
) -> None:
    c, db = dash_client
    admin, ann, _ = await _users(db)
    owner = ann
    if is_admin:
        owner = await db.create_dashboard_user(
            "second-admin", hash_password("pw"), True
        )

    # Issue both before warming the cache: creating a key also invalidates it.
    keys = []
    for _ in range(2):
        issued = await c.post("/api/my-keys", json={}, headers=_as(owner))
        assert issued.status_code == 200
        keys.append(issued.json())
    await db.set_allow_unauthenticated(False)

    def request(plain: str) -> Request:
        value = f"Bearer {plain}" if header == "Authorization" else plain
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/",
                "headers": [(header.lower().encode(), value.encode())],
            }
        )

    lookup = AsyncMock(wraps=db.lookup_api_key)
    monkeypatch.setattr(db, "lookup_api_key", lookup)
    prefs = await routing_preferences_from_request(db, request(keys[0]["api_key"]))
    assert prefs is not None
    assert prefs.key_id == keys[0]["id"]
    assert lookup.await_count > 0
    lookup.reset_mock()
    cached = await routing_preferences_from_request(db, request(keys[0]["api_key"]))
    assert cached == prefs
    lookup.assert_not_awaited()  # Prove the key is served from the auth cache.

    resp = await c.post(f"/users/{owner}/delete", headers=_as(admin))
    assert resp.status_code == 303
    assert resp.headers["location"] == "/users"
    assert await db.get_dashboard_user_by_id(owner) is None
    assert await db.list_api_keys(owner_user_id=owner) == []
    for key in keys:
        assert await db.lookup_api_key(key_hash(key["api_key"])) is None
        with pytest.raises(HTTPException) as rejected:
            await routing_preferences_from_request(db, request(key["api_key"]))
        assert rejected.value.status_code == 401
        assert rejected.value.detail == "Invalid API-KEY"


async def test_deleting_admin_preserves_unowned_shared_keys(
    dash_client: DashClient,
) -> None:
    c, db = dash_client
    admin, _, _ = await _users(db)
    other_admin = await db.create_dashboard_user(
        "second-admin", hash_password("pw"), True
    )
    issued = await c.post("/api/keys/generate", json={}, headers=_as(admin))
    assert issued.status_code == 200
    plain = issued.json()["api_key"]
    [shared] = await db.list_api_keys()
    assert shared["owner_user_id"] is None

    resp = await c.post(f"/users/{admin}/delete", headers=_as(other_admin))
    assert resp.status_code == 303
    assert await db.get_dashboard_user_by_id(admin) is None
    assert await db.lookup_api_key(key_hash(plain)) is not None
    listed = await c.get("/api/keys", headers=_as(other_admin))
    assert listed.status_code == 200
    assert [key["id"] for key in listed.json()["keys"]] == [shared["id"]]


async def test_needs_a_signed_in_user(dash_client: DashClient) -> None:
    c, _ = dash_client
    # No users yet: the dashboard is open, but keys need an owner.
    resp = await c.post("/api/my-keys", json={})
    assert resp.status_code == 403
