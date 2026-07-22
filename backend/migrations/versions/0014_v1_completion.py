"""Complete device workspaces and normalize local telemetry."""

import sqlalchemy as sa
from alembic import op

revision = "0014_v1_completion"
down_revision = "0013_operations_center"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("local_metadata")}
    additions = (
        ("functional_groups", sa.JSON(), sa.text("'[]'")),
        ("custom_roles", sa.JSON(), sa.text("'[]'")),
        ("primary_role_override", sa.String(64), None),
        ("default_map_visible", sa.Boolean(), sa.true()),
        ("revision", sa.Integer(), sa.text("1")),
    )
    for name, kind, default in additions:
        if name not in columns:
            op.add_column(
                "local_metadata",
                sa.Column(name, kind, nullable=default is None, server_default=default),
            )
    op.execute(
        "UPDATE local_metadata SET functional_groups = json_build_array(function) "
        "WHERE function IS NOT NULL AND function <> '' AND json_array_length(functional_groups) = 0"
    )
    op.execute("UPDATE local_metadata SET default_map_visible = NOT hidden")

    telemetry_columns = {
        column["name"] for column in inspector.get_columns("telemetry_observations")
    }
    telemetry_additions = (
        ("collector_device_id", sa.String(128)),
        ("client_version", sa.String(64)),
        ("udp", sa.Boolean()),
        ("ipv4", sa.Boolean()),
        ("ipv6", sa.Boolean()),
        ("mapping_varies_by_dest_ip", sa.Boolean()),
        ("preferred_derp", sa.String(64)),
        ("endpoints", sa.JSON()),
        ("derp_latency", sa.JSON()),
    )
    for name, kind in telemetry_additions:
        if name not in telemetry_columns:
            default = (
                sa.text("'[]'")
                if name == "endpoints"
                else sa.text("'{}'")
                if name == "derp_latency"
                else sa.text("''")
                if name == "client_version"
                else None
            )
            op.add_column("telemetry_observations", sa.Column(name, kind, server_default=default))
    # The initial migration builds from current ORM metadata, so a new install
    # already has these objects. Existing installations need them added here.
    telemetry_inspector = sa.inspect(bind)
    foreign_keys = telemetry_inspector.get_foreign_keys("telemetry_observations")
    if not any(
        foreign_key.get("constrained_columns") == ["collector_device_id"]
        for foreign_key in foreign_keys
    ):
        op.create_foreign_key(
            "fk_telemetry_collector_device",
            "telemetry_observations",
            "devices",
            ["collector_device_id"],
            ["id"],
            ondelete="SET NULL",
        )
    indexes = {
        index["name"] for index in telemetry_inspector.get_indexes("telemetry_observations")
    }
    if "ix_telemetry_collector_device_time" not in indexes:
        op.create_index(
            "ix_telemetry_collector_device_time",
            "telemetry_observations",
            ["collector_device_id", "observed_at"],
        )

    if not inspector.has_table("device_history_events"):
        op.create_table(
            "device_history_events",
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "device_id",
                sa.String(128),
                sa.ForeignKey("devices.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("event_type", sa.String(64), nullable=False),
            sa.Column("source", sa.String(32), nullable=False, server_default="device_sync"),
            sa.Column("changed_fields", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
            sa.Column("before", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("after", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
            sa.Column("actor_id", sa.String(36)),
            sa.Column("correlation_id", sa.String(128), nullable=False, server_default=""),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_device_history_events_device_id", "device_history_events", ["device_id"]
        )
        op.create_index(
            "ix_device_history_events_event_type", "device_history_events", ["event_type"]
        )
        op.create_index("ix_device_history_events_source", "device_history_events", ["source"])
        op.create_index("ix_device_history_events_actor_id", "device_history_events", ["actor_id"])
        op.create_index(
            "ix_device_history_device_time_id",
            "device_history_events",
            ["device_id", "occurred_at", "id"],
        )
        op.create_index(
            "ix_device_history_source_type", "device_history_events", ["source", "event_type"]
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if inspector.has_table("device_history_events"):
        op.drop_table("device_history_events")
    for name in (
        "collector_device_id",
        "client_version",
        "udp",
        "ipv4",
        "ipv6",
        "mapping_varies_by_dest_ip",
        "preferred_derp",
        "endpoints",
        "derp_latency",
    ):
        op.drop_column("telemetry_observations", name)
    for name in (
        "functional_groups",
        "custom_roles",
        "primary_role_override",
        "default_map_visible",
        "revision",
    ):
        op.drop_column("local_metadata", name)
