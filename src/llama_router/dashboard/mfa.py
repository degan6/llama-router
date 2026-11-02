"""Local dashboard password + WebAuthn, enrollment and account security.

Protocol verification uses py_webauthn, not custom cryptography:
https://duo-labs.github.io/py_webauthn/
"""

from __future__ import annotations

import json
import secrets
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.parse_authentication_credential_json import (
    parse_authentication_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from ..config import settings
from . import deps
from .auth_core import AUTH_COOKIE, SESSION_MAX_AGE, session_claims, sign_session
from .mfa_store import FLOW_TTL, Credential, Flow, LocalAccount, MfaStore, digest
from .routes import _cookie_secure, merge_dash_template_ctx, templates

router = APIRouter()
PENDING_COOKIE = "lr_second_factor"
RECENT_AUTH_SECONDS = 300


class CeremonyStart(BaseModel):
    name: str = Field(default="My authenticator", min_length=1, max_length=100)


class CeremonyFinish(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    credential: str = Field(min_length=1, max_length=65536)


class RecoveryAttempt(BaseModel):
    code: str = Field(min_length=1, max_length=100)


def _private(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


def _origin() -> tuple[str, str]:
    origin = settings.dashboard_webauthn_origin
    host = urlsplit(origin).hostname
    if not origin or not host:
        raise HTTPException(
            503, "Configure LLAMA_ROUTER_DASHBOARD_WEBAUTHN_ORIGIN to use WebAuthn"
        )
    return origin, host


def _csrf(request: Request) -> None:
    # Cross-origin pages cannot set this header without a CORS preflight.
    # These routes do not grant CORS access. Also reject mismatched Origins.
    origin, _ = _origin()
    if (
        request.headers.get("x-llama-router-security") != "1"
        or request.headers.get("origin", origin) != origin
    ):
        raise HTTPException(403, "Security requests must come from this dashboard")


async def _valid_flow(token: str, purpose: str) -> tuple[Flow, LocalAccount]:
    store = MfaStore(deps.get_db())
    flow = await store.flow(token, purpose)
    account = await store.account(flow.user_id) if flow else None
    if (
        flow is None
        or account is None
        or flow.state["version"] != str(account.version)
        or flow.state["password_tag"] != account.password_tag
        or flow.state.get("session_version") != str(account.session_version)
    ):
        raise HTTPException(401, "Sign-in expired. Sign in again.")
    return flow, account


async def _pending(request: Request) -> tuple[Flow, LocalAccount]:
    return await _valid_flow(request.cookies.get(PENDING_COOKIE, ""), "pending")


async def _session_account(request: Request, *, recent: bool = False) -> LocalAccount:
    secret = await deps.get_dashboard_session_secret()
    claims = session_claims(request.cookies.get(AUTH_COOKIE, ""), secret)
    account = await MfaStore(deps.get_db()).account(claims.user_id) if claims else None
    if (
        account is None
        or claims is None
        or claims.version != account.session_version
        or claims.username != account.username
        or claims.mfa_version != account.version
        or (account.enabled and not claims.mfa_verified)
    ):
        raise HTTPException(403, "Sign in with a local account")
    if recent and (time.time() - claims.authenticated_at > RECENT_AUTH_SECONDS):
        raise HTTPException(403, "Sign in again before changing security settings")
    return account


async def _set_session(
    request: Request, response: Response, account: LocalAccount, *, verified: bool
) -> None:
    secret = await deps.get_dashboard_session_secret()
    response.set_cookie(
        AUTH_COOKIE,
        sign_session(
            account.id,
            secret,
            account.session_version,
            account.username,
            mfa_version=account.version,
            mfa_verified=verified,
        ),
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request)
        or settings.dashboard_webauthn_origin.startswith("https://"),
        max_age=SESSION_MAX_AGE,
    )
    response.delete_cookie(PENDING_COOKIE)
    await deps.get_db().touch_dashboard_user_login(account.id)
    _private(response)


async def password_login_response(
    request: Request, user_id: int, next_url: str
) -> Response:
    """Issue a session only when all required factors have been satisfied."""
    store = MfaStore(deps.get_db())
    account = await store.account(user_id)
    if account is None:
        raise HTTPException(401, "Invalid login")
    if (
        settings.dashboard_webauthn_origin
        and request.headers.get("origin", settings.dashboard_webauthn_origin)
        != settings.dashboard_webauthn_origin
    ):
        raise HTTPException(403, "Sign in from the configured dashboard origin")
    if not account.enabled and not settings.dashboard_require_second_factor:
        response = RedirectResponse(next_url, status_code=303)
        await _set_session(request, response, account, verified=False)
        return response
    token = await store.new_flow(
        account,
        "pending",
        next=next_url,
        mode="verify" if account.enabled else "enroll",
    )
    response = RedirectResponse("/login/second-factor", status_code=303)
    response.delete_cookie(AUTH_COOKIE)
    response.set_cookie(
        PENDING_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=_cookie_secure(request)
        or settings.dashboard_webauthn_origin.startswith("https://"),
        max_age=FLOW_TTL,
    )
    return _private(response)


@router.get("/login/second-factor")
async def second_factor_page(request: Request) -> Response:
    try:
        flow, _ = await _pending(request)
    except HTTPException:
        return _private(RedirectResponse("/login", status_code=303))
    return _private(
        templates.TemplateResponse(
            request,
            "second_factor.html",
            {"enrolling": flow.state["mode"] == "enroll", "dash_user": None},
        )
    )


@router.get("/account/security")
async def security_page(request: Request) -> Response:
    account = await _session_account(request)
    credentials = await MfaStore(deps.get_db()).credentials(account.id)
    return _private(
        templates.TemplateResponse(
            request,
            "security.html",
            merge_dash_template_ctx(
                request,
                {
                    "credentials": credentials,
                    "webauthn_configured": bool(settings.dashboard_webauthn_origin),
                    "mfa_required": settings.dashboard_require_second_factor,
                },
            ),
        )
    )


async def _registration_account(request: Request) -> tuple[LocalAccount, str]:
    if request.url.path.startswith("/login/"):
        flow, account = await _pending(request)
        if flow.state["mode"] != "enroll" or account.enabled:
            raise HTTPException(
                403, "Complete second factor before adding an authenticator"
            )
        return account, flow.token
    return await _session_account(request, recent=True), ""


@router.post("/account/security/register/options")
@router.post("/login/second-factor/register/options")
async def registration_options(request: Request, body: CeremonyStart) -> Response:
    _csrf(request)
    account, pending = await _registration_account(request)
    origin, rp_id = _origin()
    store = MfaStore(deps.get_db())
    credentials = await store.credentials(account.id)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="llama-router",
        user_name=account.username,
        user_id=f"llama-router:{account.id}".encode(),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.id))
            for c in credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
    )
    token = await store.new_flow(
        account,
        "register",
        challenge=bytes_to_base64url(options.challenge),
        origin=origin,
        rp_id=rp_id,
        name=body.name.strip() or "My authenticator",
        pending=digest(pending) if pending else "",
    )
    return _private(
        JSONResponse({"token": token, "options": json.loads(options_to_json(options))})
    )


def _codes() -> list[str]:
    # 128 bits per recovery code; fast hashing is safe for random secrets.
    return [secrets.token_hex(16) for _ in range(10)]


@router.post("/account/security/register/verify")
@router.post("/login/second-factor/register/verify")
async def registration_verify(request: Request, body: CeremonyFinish) -> Response:
    _csrf(request)
    account, pending = await _registration_account(request)
    flow, owner = await _valid_flow(body.token, "register")
    if owner.id != account.id or flow.state["pending"] != (
        digest(pending) if pending else ""
    ):
        raise HTTPException(403, "Enrollment belongs to another sign-in")
    try:
        verified = verify_registration_response(
            credential=body.credential,
            expected_challenge=base64url_to_bytes(flow.state["challenge"]),
            expected_rp_id=flow.state["rp_id"],
            expected_origin=flow.state["origin"],
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError) as exc:
        raise HTTPException(
            400, "Authenticator registration could not be verified"
        ) from exc
    codes = _codes() if not account.enabled else []
    credential = Credential(
        bytes_to_base64url(verified.credential_id),
        account.id,
        flow.state["name"],
        bytes_to_base64url(verified.credential_public_key),
        verified.sign_count,
    )
    store = MfaStore(deps.get_db())
    try:
        saved = await store.register(flow, account, credential, codes)
    except IntegrityError as exc:
        raise HTTPException(409, "This authenticator is already registered") from exc
    if not saved:
        raise HTTPException(401, "Enrollment expired. Sign in again.")
    updated = await store.account(account.id)
    assert updated is not None  # account row is locked during registration  # noqa: S101
    response = JSONResponse(
        {"ok": True, "recovery_codes": codes, "next": "/account/security"}
    )
    await _set_session(request, response, updated, verified=True)
    return response


@router.post("/login/second-factor/authenticate/options")
async def authentication_options(request: Request) -> Response:
    _csrf(request)
    pending, account = await _pending(request)
    if not account.enabled:
        raise HTTPException(403, "Enroll an authenticator first")
    origin, rp_id = _origin()
    store = MfaStore(deps.get_db())
    credentials = await store.credentials(account.id)
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.id))
            for c in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    token = await store.new_flow(
        account,
        "authenticate",
        challenge=bytes_to_base64url(options.challenge),
        origin=origin,
        rp_id=rp_id,
        pending=digest(pending.token),
    )
    return _private(
        JSONResponse({"token": token, "options": json.loads(options_to_json(options))})
    )


@router.post("/login/second-factor/authenticate/verify")
async def authentication_verify(request: Request, body: CeremonyFinish) -> Response:
    _csrf(request)
    pending, account = await _pending(request)
    flow, owner = await _valid_flow(body.token, "authenticate")
    if (
        owner.id != account.id
        or flow.state["pending"] != digest(pending.token)
        or not account.enabled
    ):
        raise HTTPException(403, "Challenge belongs to another sign-in")
    store = MfaStore(deps.get_db())
    try:
        parsed = parse_authentication_credential_json(body.credential)
        credential = next(
            (c for c in await store.credentials(account.id) if c.id == parsed.id), None
        )
        if credential is None:
            raise ValueError("Unknown credential")
        verified = verify_authentication_response(
            credential=parsed,
            expected_challenge=base64url_to_bytes(flow.state["challenge"]),
            expected_rp_id=flow.state["rp_id"],
            expected_origin=flow.state["origin"],
            credential_public_key=base64url_to_bytes(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError) as exc:
        raise HTTPException(400, "Second factor could not be verified") from exc
    if not await store.finish_authentication(
        flow, account, credential=credential, sign_count=verified.new_sign_count
    ):
        raise HTTPException(401, "Challenge expired. Sign in again.")
    response = JSONResponse({"ok": True, "next": pending.state["next"]})
    await _set_session(request, response, account, verified=True)
    return response


@router.post("/login/second-factor/recovery")
async def recovery_login(request: Request, body: RecoveryAttempt) -> Response:
    _csrf(request)
    pending, account = await _pending(request)
    if not account.enabled or not await MfaStore(deps.get_db()).finish_authentication(
        pending, account, recovery_code=body.code
    ):
        raise HTTPException(401, "Invalid recovery code. Sign in again.")
    response = JSONResponse({"ok": True, "next": "/account/security"})
    await _set_session(request, response, account, verified=True)
    return response


@router.post("/account/security/recovery-codes")
async def regenerate_codes(request: Request) -> Response:
    _csrf(request)
    account = await _session_account(request, recent=True)
    if not account.enabled:
        raise HTTPException(400, "Register an authenticator first")
    codes = _codes()
    if not await MfaStore(deps.get_db()).replace_codes(account, codes):
        raise HTTPException(401, "Sign in again")
    return _private(JSONResponse({"recovery_codes": codes}))


@router.delete("/account/security/credentials/{credential_id}")
async def remove_credential(request: Request, credential_id: str) -> Response:
    _csrf(request)
    account = await _session_account(request, recent=True)
    if not await MfaStore(deps.get_db()).delete_credential(account, credential_id):
        raise HTTPException(
            400,
            "Keep at least one authenticator; register a replacement first",
        )
    updated = await MfaStore(deps.get_db()).account(account.id)
    if updated is None:
        raise HTTPException(401, "Sign in again")
    response = JSONResponse({"ok": True})
    await _set_session(request, response, updated, verified=True)
    return response
