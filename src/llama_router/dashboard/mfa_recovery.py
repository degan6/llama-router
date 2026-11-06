"""Operator recovery using the configured database, without starting servers."""

import logging

from ..database import Database
from .mfa_store import MfaStore

logger = logging.getLogger(__name__)


async def reset_second_factor(username: str) -> int:
    """Remove factors and revoke sessions; the required-enrollment policy remains."""
    db = Database()
    await db.connect()
    try:
        user = await db.get_dashboard_user_by_username(username)
        if user is None or user.get("auth_source", "local") != "local":
            logger.error("No local dashboard account with that username")
            return 1
        await MfaStore(db).reset(int(user["id"]))
        logger.warning(
            "Second factor reset for local dashboard user %s; sessions revoked",
            username,
        )
        return 0
    finally:
        await db.close()
