"""Add durable flow aggregates and network usage reports."""

from alembic import op

from app.models import Base

revision = "0011_network_reports"
down_revision = "0010_saved_views"
branch_labels = None
depends_on = None

TABLES = (
    "flow_aggregates",
    "flow_aggregate_states",
    "report_schedules",
    "report_runs",
    "report_artifacts",
)


def upgrade() -> None:
    bind = op.get_bind()
    for name in TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    for name in reversed(TABLES):
        Base.metadata.tables[name].drop(bind=bind, checkfirst=True)
