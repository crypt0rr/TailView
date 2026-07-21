"""Add independently synchronized inventory source tables."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0004_inventory_sources"
down_revision = "0003_flow_query_indexes"
branch_labels = None
depends_on = None

TABLES = [
    "tailnet_services",
    "service_hosts",
    "service_endpoints",
    "dns_configurations",
    "webhook_endpoints",
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    user_columns = {column["name"] for column in inspector.get_columns("tailnet_users")}
    if "active" not in user_columns:
        op.add_column(
            "tailnet_users",
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        )
    if "ix_tailnet_users_active" not in {
        index["name"] for index in inspector.get_indexes("tailnet_users")
    }:
        op.create_index("ix_tailnet_users_active", "tailnet_users", ["active"])
    device_columns = {column["name"] for column in inspector.get_columns("devices")}
    if "active" not in device_columns:
        op.add_column(
            "devices",
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        )
    if "ix_devices_active" not in {index["name"] for index in inspector.get_indexes("devices")}:
        op.create_index("ix_devices_active", "devices", ["active"])
    for name in TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)
    sync_columns = {column["name"] for column in inspect(bind).get_columns("sync_jobs")}
    additions = {
        "attempted": sa.Column("attempted", sa.Integer(), nullable=False, server_default="0"),
        "succeeded": sa.Column("succeeded", sa.Integer(), nullable=False, server_default="0"),
        "failed": sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        "partial_success": sa.Column(
            "partial_success", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        "details": sa.Column("details", sa.JSON(), nullable=False, server_default="{}"),
    }
    for name, column in additions.items():
        if name not in sync_columns:
            op.add_column("sync_jobs", column)


def downgrade() -> None:
    with op.batch_alter_table("sync_jobs") as batch:
        batch.drop_column("details")
        batch.drop_column("failed")
        batch.drop_column("partial_success")
        batch.drop_column("succeeded")
        batch.drop_column("attempted")
    op.drop_index("ix_devices_active", table_name="devices")
    op.drop_column("devices", "active")
    op.drop_index("ix_tailnet_users_active", table_name="tailnet_users")
    op.drop_column("tailnet_users", "active")
    for name in reversed(TABLES):
        op.drop_table(name)
