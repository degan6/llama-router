"""Administrator controls for dashboard password lockouts."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..request_logger import log_request
from . import deps, routes
from .auth_core import DashboardUser

logger = logging.getLogger(__name__)
router = APIRouter()


def _admin(request: Request) -> DashboardUser:
    user = getattr(request.state, "dashboard_user", None)
    if not isinstance(user, DashboardUser) or not user.is_admin:
        raise HTTPException(status_code=403, detail="Administrator sign-in required")
    return user


@router.get("/security", response_class=HTMLResponse)
async def security_page(request: Request) -> Response:
    """Show IP cooldowns and retained escalation history to administrators."""
    _admin(request)
    return routes.templates.TemplateResponse(
        request,
        "security.html",
        routes.merge_dash_template_ctx(
            request, {"login_limits": routes.login_attempt_limiter.limited_addresses()}
        ),
        headers={"Cache-Control": "no-store"},
    )


@router.post("/security/reset")
async def reset_login_limit(request: Request, client_ip: str = Form(...)) -> Response:
    """Clear one IP's login limits and record which administrator reset it."""
    admin = _admin(request)
    if not routes.login_attempt_limiter.reset(client_ip):
        raise HTTPException(status_code=404, detail="No login limit for this address")
    logger.info(
        "Administrator %d reset password login limits for %s", admin.id, client_ip
    )
    await log_request(
        deps.get_db(),
        provider=None,
        protocol="dashboard",
        endpoint="/security/reset",
        request=request,
        model=None,
        duration_ms=0.0,
        request_meta=f"Admin {admin.id} reset login limits for {client_ip}",
    )
    return RedirectResponse(url="/security?reset=1", status_code=303)
