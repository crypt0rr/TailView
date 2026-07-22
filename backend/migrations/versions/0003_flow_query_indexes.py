"""Add indexes for flow keyset pagination and filtering."""

from alembic import op
from sqlalchemy import inspect

revision = "0003_flow_query_indexes"
down_revision = "0002_flow_address_lookup"
branch_labels = None
depends_on = None

INDEXES = {
    "ix_flows_start_id": ["start", "id"],
    "ix_flows_category_start_id": ["category", "start", "id"],
    "ix_flows_protocol_start_id": ["protocol", "start", "id"],
    "ix_flows_destination_port_start_id": ["destination_port", "start", "id"],
}


def upgrade() -> None:
    existing = {item["name"] for item in inspect(op.get_bind()).get_indexes("flows")}
    for name, columns in INDEXES.items():
        if name not in existing:
            op.create_index(name, "flows", columns)


def downgrade() -> None:
    existing = {item["name"] for item in inspect(op.get_bind()).get_indexes("flows")}
    for name in reversed(INDEXES):
        if name in existing:
            op.drop_index(name, table_name="flows")
