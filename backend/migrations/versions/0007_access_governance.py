"""Add read-only access governance inventory."""

from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0007_access_governance"
down_revision = "0006_security_posture"
branch_labels = None
depends_on = None

TABLES = [
    "tailnet_credentials",
    "device_invites",
    "tailnet_contacts",
    "log_streaming_configurations",
]


def upgrade() -> None:
    bind = op.get_bind()
    for name in TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(inspect(bind).get_table_names())
    for name in reversed(TABLES):
        if name in existing:
            op.drop_table(name)
