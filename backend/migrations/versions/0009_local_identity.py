"""Add local identity, session administration, and MFA storage."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0009_local_identity"
down_revision = "0008_findings_alerting"
branch_labels = None
depends_on = None

TABLES = [
    "mfa_credentials",
    "mfa_recovery_codes",
    "auth_challenges",
    "auth_policy",
    "local_security_events",
]

USER_COLUMNS = {
    "display_name": sa.Column("display_name", sa.String(255), nullable=False, server_default=""),
    "must_change_password": sa.Column(
        "must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()
    ),
    "password_changed_at": sa.Column("password_changed_at", sa.DateTime(timezone=True)),
    "mfa_enabled": sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    "last_login_at": sa.Column("last_login_at", sa.DateTime(timezone=True)),
    "deactivated_at": sa.Column("deactivated_at", sa.DateTime(timezone=True)),
}
SESSION_COLUMNS = {
    "initial_ip": sa.Column("initial_ip", sa.String(128), nullable=False, server_default="unknown"),
    "last_ip": sa.Column("last_ip", sa.String(128), nullable=False, server_default="unknown"),
    "user_agent": sa.Column("user_agent", sa.String(512), nullable=False, server_default=""),
    "restricted": sa.Column("restricted", sa.Boolean(), nullable=False, server_default=sa.false()),
}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    user_existing = {column["name"] for column in inspector.get_columns("app_users")}
    session_existing = {column["name"] for column in inspector.get_columns("sessions")}
    for name, column in USER_COLUMNS.items():
        if name not in user_existing:
            op.add_column("app_users", column)
    for name, column in SESSION_COLUMNS.items():
        if name not in session_existing:
            op.add_column("sessions", column)
    for name in TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(inspect(bind).get_table_names())
    for name in reversed(TABLES):
        if name in existing:
            op.drop_table(name)
    for name in reversed(SESSION_COLUMNS):
        op.drop_column("sessions", name)
    for name in reversed(USER_COLUMNS):
        op.drop_column("app_users", name)
