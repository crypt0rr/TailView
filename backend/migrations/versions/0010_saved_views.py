"""Complete saved views and personal page defaults."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

from app.models import Base

revision = "0010_saved_views"
down_revision = "0009_local_identity"
branch_labels = None
depends_on = None

COLUMNS = {
    "description": sa.Column("description", sa.String(500), nullable=False, server_default=""),
    "visibility": sa.Column("visibility", sa.String(16), nullable=False, server_default="private"),
    "schema_version": sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
    "revision": sa.Column("revision", sa.Integer(), nullable=False, server_default="1"),
    "updated_at": sa.Column(
        "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    ),
}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing = {column["name"] for column in inspector.get_columns("saved_views")}
    for name, column in COLUMNS.items():
        if name not in existing:
            op.add_column("saved_views", column)
    Base.metadata.tables["saved_view_defaults"].create(bind=bind, checkfirst=True)
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_saved_views_page_visibility "
        "ON saved_views (page, visibility)"
    )
    op.execute(
        "WITH ranked AS ("
        " SELECT id, row_number() OVER ("
        "  PARTITION BY owner_id, page, lower(name) ORDER BY created_at, id"
        " ) AS duplicate_number FROM saved_views"
        ") UPDATE saved_views SET name = left(saved_views.name, 108) || "
        "' (legacy ' || ranked.duplicate_number || ')' FROM ranked "
        "WHERE saved_views.id = ranked.id AND ranked.duplicate_number > 1"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_saved_views_owner_page_lower_name "
        "ON saved_views (owner_id, page, lower(name))"
    )


def downgrade() -> None:
    bind = op.get_bind()
    if "saved_view_defaults" in set(inspect(bind).get_table_names()):
        op.drop_table("saved_view_defaults")
    op.execute("DROP INDEX IF EXISTS uq_saved_views_owner_page_lower_name")
    op.execute("DROP INDEX IF EXISTS ix_saved_views_page_visibility")
    for name in reversed(COLUMNS):
        op.drop_column("saved_views", name)
