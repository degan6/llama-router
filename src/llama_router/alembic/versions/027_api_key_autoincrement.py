"""Prevent SQLite from reusing API-key IDs referenced by retained request logs.

Revision ID: 027_api_key_autoincrement
Revises: 026_session_version
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "027_api_key_autoincrement"
down_revision = "026_session_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        return

    # Deleted keys can have higher IDs than any key still in the table.
    last_id = connection.execute(
        sa.text(
            "SELECT MAX(COALESCE((SELECT MAX(id) FROM api_keys), 0), "
            "COALESCE((SELECT MAX(api_key_id) FROM request_log), 0))"
        )
    ).scalar_one()
    with op.batch_alter_table(
        "api_keys", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ):
        pass
    connection.execute(sa.text("DELETE FROM sqlite_sequence WHERE name = 'api_keys'"))
    connection.execute(
        sa.text(
            "INSERT INTO sqlite_sequence (name, seq) VALUES ('api_keys', :last_id)"
        ),
        {"last_id": last_id},
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table(
            "api_keys", recreate="always", table_kwargs={"sqlite_autoincrement": False}
        ):
            pass
