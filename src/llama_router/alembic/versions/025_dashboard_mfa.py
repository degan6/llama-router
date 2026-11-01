"""WebAuthn credentials, recovery codes and expiring authentication flows."""

import sqlalchemy as sa
from alembic import op

revision = "025_dashboard_mfa"
down_revision = "024_api_key_owner"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {c["name"] for c in inspector.get_columns("dashboard_users")}
    tables = set(inspector.get_table_names())
    if "mfa_version" not in columns:
        op.add_column(
            "dashboard_users",
            sa.Column("mfa_version", sa.Integer(), nullable=False, server_default="0"),
        )
    if "mfa_enabled" not in columns:
        op.add_column(
            "dashboard_users",
            sa.Column("mfa_enabled", sa.Integer(), nullable=False, server_default="0"),
        )
    if "dashboard_credentials" not in tables:
        op.create_table(
            "dashboard_credentials",
            sa.Column("credential_hash", sa.String(64), primary_key=True),
            sa.Column("credential_id", sa.Text(), nullable=False),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("dashboard_users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("public_key", sa.Text(), nullable=False),
            sa.Column("sign_count", sa.BigInteger(), nullable=False),
        )
    if "dashboard_recovery_codes" not in tables:
        op.create_table(
            "dashboard_recovery_codes",
            sa.Column("code_hash", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("dashboard_users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
        )
    if "dashboard_auth_flows" not in tables:
        op.create_table(
            "dashboard_auth_flows",
            sa.Column("token_hash", sa.String(64), primary_key=True),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("dashboard_users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("purpose", sa.String(20), nullable=False),
            sa.Column("state", sa.Text(), nullable=False),
            sa.Column("expires_at", sa.BigInteger(), nullable=False, index=True),
        )


def downgrade() -> None:
    op.drop_table("dashboard_auth_flows")
    op.drop_table("dashboard_recovery_codes")
    op.drop_table("dashboard_credentials")
    with op.batch_alter_table("dashboard_users") as batch:
        batch.drop_column("mfa_enabled")
        batch.drop_column("mfa_version")
