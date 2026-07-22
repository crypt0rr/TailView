"""Add durable findings and signed notification outbox."""

from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0008_findings_alerting"
down_revision = "0007_access_governance"
branch_labels = None
depends_on = None

TABLES = [
    "findings",
    "finding_occurrences",
    "finding_transitions",
    "notification_endpoints",
    "notification_deliveries",
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
