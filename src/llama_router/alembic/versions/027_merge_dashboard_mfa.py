"""Merge WebAuthn and upstream session security migrations."""

revision = "027_merge_dashboard_mfa"
down_revision = ("025_dashboard_mfa", "026_session_version")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
