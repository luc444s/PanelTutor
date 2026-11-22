"""restore the legacy users.is_superadmin database default

Revision ID: 20261119_0011
Revises: 20260715_0010
Create Date: 2026-11-19 00:00:00.000000
"""

from alembic import op

revision = "20261119_0011"
down_revision = "20260715_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE users ALTER COLUMN is_superadmin SET DEFAULT false"
    )
    op.execute(
        "UPDATE users SET is_superadmin = false WHERE is_superadmin IS NULL"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE users ALTER COLUMN is_superadmin DROP DEFAULT"
    )
