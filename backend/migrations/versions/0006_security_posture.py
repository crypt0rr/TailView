"""Add device posture, connectivity, integrations, and tailnet settings."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0006_security_posture"
down_revision = "0005_device_key_expiry_state"
branch_labels = None
depends_on = None

TABLES = [
    "device_connectivity",
    "device_posture_states",
    "device_posture_attributes",
    "posture_integrations",
    "tailnet_security_settings",
]


def upgrade() -> None:
    bind = op.get_bind()
    columns = {column["name"] for column in inspect(bind).get_columns("devices")}
    if "inventory_details" not in columns:
        op.add_column(
            "devices",
            sa.Column("inventory_details", sa.JSON(), server_default="{}", nullable=False),
        )
    for name in TABLES:
        Base.metadata.tables[name].create(bind=bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(inspect(bind).get_table_names())
    for name in reversed(TABLES):
        if name in existing:
            op.drop_table(name)
    columns = {column["name"] for column in inspect(bind).get_columns("devices")}
    if "inventory_details" in columns:
        op.drop_column("devices", "inventory_details")
