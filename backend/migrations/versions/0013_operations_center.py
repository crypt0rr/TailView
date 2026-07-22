"""Add production operations telemetry and backup verification."""

import sqlalchemy as sa
from alembic import op

revision = "0013_operations_center"
down_revision = "0012_reporting_experience"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table("operational_job_states"):
        op.create_table(
            "operational_job_states",
            sa.Column("name", sa.String(64), primary_key=True),
            sa.Column("category", sa.String(32), nullable=False),
            sa.Column("interval_seconds", sa.Integer(), nullable=False),
            sa.Column("last_started_at", sa.DateTime(timezone=True)),
            sa.Column("last_finished_at", sa.DateTime(timezone=True)),
            sa.Column("last_success_at", sa.DateTime(timezone=True)),
            sa.Column("last_status", sa.String(32), nullable=False, server_default="never"),
            sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        )
        op.create_index(
            "ix_operational_job_states_category", "operational_job_states", ["category"]
        )
        op.create_index(
            "ix_operational_job_states_heartbeat_at", "operational_job_states", ["heartbeat_at"]
        )
    if not inspector.has_table("operational_job_runs"):
        op.create_table(
            "operational_job_runs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("name", sa.String(64), nullable=False),
            sa.Column("category", sa.String(32), nullable=False),
            sa.Column("interval_seconds", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="running"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
            sa.Column("duration_ms", sa.BigInteger()),
            sa.Column("processed", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_class", sa.String(128), nullable=False, server_default=""),
            sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("sync_job_id", sa.String(36)),
            sa.Column("report_run_id", sa.String(36)),
        )
        for name, columns in (
            ("ix_operational_job_runs_name", ["name"]),
            ("ix_operational_job_runs_category", ["category"]),
            ("ix_operational_job_runs_status", ["status"]),
            ("ix_operational_job_runs_sync_job_id", ["sync_job_id"]),
            ("ix_operational_job_runs_report_run_id", ["report_run_id"]),
            ("ix_operational_job_runs_started_id", ["started_at", "id"]),
            ("ix_operational_job_runs_name_status", ["name", "status"]),
        ):
            op.create_index(name, "operational_job_runs", columns)
    if not inspector.has_table("operational_signal_states"):
        op.create_table(
            "operational_signal_states",
            sa.Column("key", sa.String(160), primary_key=True),
            sa.Column(
                "consecutive_observations", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("last_present", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("last_evaluated_at", sa.DateTime(timezone=True)),
        )
    if not inspector.has_table("cleanup_runs"):
        op.create_table(
            "cleanup_runs",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("trigger", sa.String(32), nullable=False, server_default="scheduled"),
            sa.Column("preview", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("deleted", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("error_class", sa.String(128), nullable=False, server_default=""),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True)),
        )
        op.create_index("ix_cleanup_runs_status", "cleanup_runs", ["status"])
    if not inspector.has_table("backup_verifications"):
        op.create_table(
            "backup_verifications",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("filename", sa.String(255), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column("size", sa.BigInteger(), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
            sa.Column("postgres_version", sa.String(64), nullable=False, server_default=""),
            sa.Column("migration_revision", sa.String(128), nullable=False, server_default=""),
            sa.Column("checks", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("error_class", sa.String(128), nullable=False, server_default=""),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_backup_verifications_status", "backup_verifications", ["status"]
        )
        op.create_index(
            "ix_backup_verifications_verified_id",
            "backup_verifications",
            ["verified_at", "id"],
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    for table in (
        "backup_verifications",
        "cleanup_runs",
        "operational_signal_states",
        "operational_job_runs",
        "operational_job_states",
    ):
        if inspector.has_table(table):
            op.drop_table(table)
