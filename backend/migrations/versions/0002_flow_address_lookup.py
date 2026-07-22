"""Add the physical endpoint lookup index."""

from alembic import op
from sqlalchemy import inspect

revision = "0002_flow_address_lookup"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

INDEX_NAME = "ix_flows_source_category_end"


def upgrade() -> None:
    indexes = {item["name"] for item in inspect(op.get_bind()).get_indexes("flows")}
    if INDEX_NAME not in indexes:
        op.create_index(INDEX_NAME, "flows", ["source_device_id", "category", "end"])


def downgrade() -> None:
    indexes = {item["name"] for item in inspect(op.get_bind()).get_indexes("flows")}
    if INDEX_NAME in indexes:
        op.drop_index(INDEX_NAME, table_name="flows")
