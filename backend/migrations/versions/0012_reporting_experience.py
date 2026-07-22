"""Add versioned report options and durable generation lifecycle."""

import sqlalchemy as sa
from alembic import op

revision = "0012_reporting_experience"
down_revision = "0011_network_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    schedule_columns = {column["name"] for column in inspector.get_columns("report_schedules")}
    if "report_options" not in schedule_columns:
        op.add_column(
            "report_schedules",
            sa.Column("report_options", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )
    run_columns = {column["name"] for column in inspector.get_columns("report_runs")}
    additions = {
        "retry_of_id": sa.Column("retry_of_id", sa.String(length=36), nullable=True),
        "report_options": sa.Column(
            "report_options", sa.JSON(), nullable=False, server_default=sa.text("'{}'")
        ),
        "snapshot_schema_version": sa.Column(
            "snapshot_schema_version", sa.Integer(), nullable=False, server_default="1"
        ),
        "generation_stage": sa.Column(
            "generation_stage", sa.String(length=32), nullable=False, server_default="queued"
        ),
        "progress": sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
    }
    for name, column in additions.items():
        if name not in run_columns:
            op.add_column("report_runs", column)
    inspector = sa.inspect(bind)
    foreign_keys = inspector.get_foreign_keys("report_runs")
    if not any(key.get("constrained_columns") == ["retry_of_id"] for key in foreign_keys):
        op.create_foreign_key(
            "fk_report_runs_retry_of_id",
            "report_runs",
            "report_runs",
            ["retry_of_id"],
            ["id"],
            ondelete="SET NULL",
        )
    indexes = {index["name"] for index in inspector.get_indexes("report_runs")}
    if "ix_report_runs_retry_of_id" not in indexes:
        op.create_index("ix_report_runs_retry_of_id", "report_runs", ["retry_of_id"])


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    indexes = {index["name"] for index in inspector.get_indexes("report_runs")}
    if "ix_report_runs_retry_of_id" in indexes:
        op.drop_index("ix_report_runs_retry_of_id", table_name="report_runs")
    retry_key = next(
        (
            key
            for key in inspector.get_foreign_keys("report_runs")
            if key.get("constrained_columns") == ["retry_of_id"]
        ),
        None,
    )
    if retry_key and retry_key.get("name"):
        op.drop_constraint(str(retry_key["name"]), "report_runs", type_="foreignkey")
    for column in (
        "progress",
        "generation_stage",
        "snapshot_schema_version",
        "report_options",
        "retry_of_id",
    ):
        op.drop_column("report_runs", column)
    op.drop_column("report_schedules", "report_options")
