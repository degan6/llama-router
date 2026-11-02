"""Persistent, atomic WebAuthn state. Random tokens and recovery codes are hashed.

SQLAlchemy result values are dynamically typed at the database boundary; convert
all of them to the dataclasses here before passing them to authentication code.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import Database
from ..db_sql import cursor_rowcount

FLOW_TTL = 300


def digest(value: str) -> str:
    """Hash high-entropy flow tokens and recovery codes, never passwords."""
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class LocalAccount:
    id: int
    username: str
    version: int
    enabled: bool
    password_tag: str
    session_version: int = 0


@dataclass(frozen=True)
class Credential:
    id: str
    user_id: int
    name: str
    public_key: str
    sign_count: int


@dataclass(frozen=True)
class Flow:
    token: str
    user_id: int
    purpose: str
    state: dict[str, str]


class MfaStore:
    """Use the router database and its existing transactional session factory."""

    def __init__(self, db: Database):
        self.db = db

    async def account(self, user_id: int) -> LocalAccount | None:
        row = await self.db._select_one(
            "SELECT id, username, password_hash, mfa_version, mfa_enabled, "
            "session_version "
            "FROM dashboard_users WHERE id = ? AND auth_source = 'local'",
            (user_id,),
        )
        if row is None:
            return None
        return LocalAccount(
            int(row["id"]),
            str(row["username"]),
            int(row["mfa_version"]),
            bool(row["mfa_enabled"]),
            digest(str(row["password_hash"])),
            int(row["session_version"]),
        )

    async def credentials(self, user_id: int) -> list[Credential]:
        rows = await self.db._select_all(
            "SELECT * FROM dashboard_credentials WHERE user_id = ? ORDER BY name",
            (user_id,),
        )
        return [
            Credential(
                str(r["credential_id"]),
                int(r["user_id"]),
                str(r["name"]),
                str(r["public_key"]),
                int(r["sign_count"]),
            )
            for r in rows
        ]

    async def flow(self, token: str, purpose: str) -> Flow | None:
        row = await self.db._select_one(
            "SELECT user_id, state FROM dashboard_auth_flows "
            "WHERE token_hash = ? AND purpose = ? AND expires_at > ?",
            (digest(token), purpose, int(time.time())),
        )
        if row is None:
            return None
        state: dict[str, str] = json.loads(str(row["state"]))
        return Flow(token, int(row["user_id"]), purpose, state)

    async def new_flow(self, account: LocalAccount, purpose: str, **state: str) -> str:
        token = secrets.token_urlsafe(32)
        state.update(
            version=str(account.version),
            password_tag=account.password_tag,
            session_version=str(account.session_version),
        )
        # Bound storage without a background cleanup service.
        await self.db._execute(
            "DELETE FROM dashboard_auth_flows WHERE expires_at <= ?",
            (int(time.time()),),
        )
        await self.db._execute(
            "INSERT INTO dashboard_auth_flows "
            "(token_hash, user_id, purpose, state, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                digest(token),
                account.id,
                purpose,
                json.dumps(state),
                int(time.time()) + FLOW_TTL,
            ),
        )
        return token

    async def consume(self, session: AsyncSession, flow: Flow) -> bool:
        """A conditional delete makes concurrent submissions single-use."""
        return await self._consume_hash(session, digest(flow.token))

    async def _consume_hash(self, session: AsyncSession, token_hash: str) -> bool:
        result = await session.execute(
            text(
                "DELETE FROM dashboard_auth_flows WHERE token_hash = :token "
                "AND expires_at > :now"
            ),
            {"token": token_hash, "now": int(time.time())},
        )
        return cursor_rowcount(result) == 1

    async def finish_authentication(
        self,
        flow: Flow,
        account: LocalAccount,
        *,
        credential: Credential | None = None,
        sign_count: int = 0,
        recovery_code: str | None = None,
    ) -> bool:
        async with self.db._require_session_factory()() as session, session.begin():
            if not await self._lock_account(session, account):
                return False
            if not await self.consume(session, flow):
                return False
            pending = flow.state.get("pending")
            if pending and not await self._consume_hash(session, pending):
                return False
            if recovery_code is not None:
                result = await session.execute(
                    text(
                        "DELETE FROM dashboard_recovery_codes "
                        "WHERE user_id = :uid AND code_hash = :code"
                    ),
                    {"uid": account.id, "code": digest(recovery_code.strip().lower())},
                )
                if cursor_rowcount(result) != 1:
                    return False
            elif credential is not None:
                result = await session.execute(
                    text(
                        "UPDATE dashboard_credentials SET sign_count = :new "
                        "WHERE credential_id = :cid AND user_id = :uid "
                        "AND sign_count = :old"
                    ),
                    {
                        "new": sign_count,
                        "cid": credential.id,
                        "uid": account.id,
                        "old": credential.sign_count,
                    },
                )
                if cursor_rowcount(result) != 1:
                    return False
            else:
                return False
            return True

    async def _lock_account(self, session: AsyncSession, account: LocalAccount) -> bool:
        # UPDATE locks the account on all supported databases, including SQLite.
        result = await session.execute(
            text(
                "UPDATE dashboard_users SET mfa_version = mfa_version "
                "WHERE id = :uid AND mfa_version = :version "
                "AND session_version = :session_version"
            ),
            {
                "uid": account.id,
                "version": account.version,
                "session_version": account.session_version,
            },
        )
        return cursor_rowcount(result) == 1

    async def register(
        self,
        flow: Flow,
        account: LocalAccount,
        credential: Credential,
        codes: list[str],
    ) -> bool:
        async with self.db._require_session_factory()() as session, session.begin():
            if not await self._lock_account(session, account) or not await self.consume(
                session, flow
            ):
                return False
            # Initial forced enrollment must also consume the password proof.
            pending = flow.state.get("pending")
            if pending and not await self._consume_hash(session, pending):
                return False
            await session.execute(
                text(
                    "INSERT INTO dashboard_credentials "
                    "(credential_hash, credential_id, user_id, name, "
                    "public_key, sign_count) "
                    "VALUES (:hash, :cid, :uid, :name, :key, :count)"
                ),
                {
                    "hash": digest(credential.id),
                    "cid": credential.id,
                    "uid": account.id,
                    "name": credential.name,
                    "key": credential.public_key,
                    "count": credential.sign_count,
                },
            )
            await session.execute(
                text(
                    "UPDATE dashboard_users SET mfa_enabled = 1, "
                    "mfa_version = mfa_version + 1 WHERE id = :uid"
                ),
                {"uid": account.id},
            )
            if codes:
                await self._replace_codes(session, account.id, codes)
            return True

    async def _replace_codes(
        self, session: AsyncSession, user_id: int, codes: list[str]
    ) -> None:
        await session.execute(
            text("DELETE FROM dashboard_recovery_codes WHERE user_id = :uid"),
            {"uid": user_id},
        )
        for code in codes:
            await session.execute(
                text(
                    "INSERT INTO dashboard_recovery_codes (code_hash, user_id) "
                    "VALUES (:code, :uid)"
                ),
                {"code": digest(code), "uid": user_id},
            )

    async def replace_codes(self, account: LocalAccount, codes: list[str]) -> bool:
        async with self.db._require_session_factory()() as session, session.begin():
            if not await self._lock_account(session, account):
                return False
            await self._replace_codes(session, account.id, codes)
            return True

    async def delete_credential(
        self, account: LocalAccount, credential_id: str
    ) -> bool:
        async with self.db._require_session_factory()() as session, session.begin():
            if not await self._lock_account(session, account):
                return False
            count = await session.execute(
                text("SELECT COUNT(*) FROM dashboard_credentials WHERE user_id = :uid"),
                {"uid": account.id},
            )
            if int(count.scalar_one()) <= 1:
                return False
            result = await session.execute(
                text(
                    "DELETE FROM dashboard_credentials "
                    "WHERE user_id = :uid AND credential_id = :cid"
                ),
                {"uid": account.id, "cid": credential_id},
            )
            removed = cursor_rowcount(result) == 1
            if removed:
                await session.execute(
                    text(
                        "UPDATE dashboard_users SET mfa_version = mfa_version + 1 "
                        "WHERE id = :uid"
                    ),
                    {"uid": account.id},
                )
            return removed

    async def reset(self, user_id: int) -> None:
        """Operator-only reset; revoke sessions and pending login proofs too."""
        async with self.db._require_session_factory()() as session, session.begin():
            await session.execute(
                text(
                    "UPDATE dashboard_users SET mfa_enabled = 0, "
                    "mfa_version = mfa_version + 1 WHERE id = :uid"
                ),
                {"uid": user_id},
            )
            for table in (
                "dashboard_credentials",
                "dashboard_recovery_codes",
                "dashboard_auth_flows",
            ):
                await session.execute(
                    text(f"DELETE FROM {table} WHERE user_id = :uid"),  # noqa: S608 - fixed table names
                    {"uid": user_id},
                )
