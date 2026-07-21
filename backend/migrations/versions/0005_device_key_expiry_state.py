"""Store the device key-expiry enabled state."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0005_device_key_expiry_state"
down_revision = "0004_inventory_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("devices")}
    if "key_expiry_disabled" not in columns:
        op.add_column(
            "devices",
            sa.Column("key_expiry_disabled", sa.Boolean(), nullable=True),
        )


def downgrade() -> None:
    columns = {column["name"] for column in inspect(op.get_bind()).get_columns("devices")}
    if "key_expiry_disabled" in columns:
        op.drop_column("devices", "key_expiry_disabled")
