"""Prepare and verify the PostgreSQL 0013 -> current release migration rehearsal."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from app.models import (
    AppUser,
    Device,
    Finding,
    Flow,
    LocalMetadata,
    OperationalJobRun,
    ReportArtifact,
    ReportRun,
    SavedView,
    Session,
    TailnetUser,
    TelemetryObservation,
)
from app.security import hash_password, verify_password

EXPECTED_HEAD = "0014_v1_completion"
FIXTURE_IDS = {
    "user": "upgrade-user",
    "session": "upgrade-session",
    "tailnet_user": "upgrade-tailnet-user",
    "device": "upgrade-device",
    "view": "upgrade-view",
    "finding": "upgrade-finding",
    "report": "upgrade-report",
    "job": "upgrade-job",
    "telemetry": "upgrade-telemetry",
}


def engine() -> Engine:
    return create_engine(os.environ["DATABASE_URL"])


def prepare() -> None:
    now = datetime.now(UTC)
    db_engine = engine()
    with OrmSession(db_engine) as session:
        account = AppUser(
            id=FIXTURE_IDS["user"],
            username="upgrade-admin",
            display_name="Upgrade Administrator",
            password_hash=hash_password("preserved-upgrade-password"),
            role="administrator",
        )
        session.add_all(
            [
                account,
                Session(
                    id=FIXTURE_IDS["session"],
                    token_hash="a" * 64,
                    csrf_hash="b" * 64,
                    user_id=account.id,
                    expires_at=now + timedelta(hours=1),
                ),
                TailnetUser(
                    id=FIXTURE_IDS["tailnet_user"],
                    display_name="Upgrade Owner",
                    login_name="upgrade@example.com",
                ),
            ]
        )
        session.flush()
        device = Device(
            id=FIXTURE_IDS["device"],
            name="upgrade-device.example.ts.net",
            owner_id=FIXTURE_IDS["tailnet_user"],
            online=True,
            authorized=True,
        )
        session.add(device)
        session.flush()
        session.add_all(
            [
                LocalMetadata(
                    device_id=device.id,
                    display_name="Preserved device",
                    function="production",
                    hidden=True,
                ),
                TelemetryObservation(
                    id=FIXTURE_IDS["telemetry"],
                    collector_node_id=device.id,
                    collector_device_id=device.id,
                    observed_at=now,
                    payload={"fixture": True},
                ),
                Flow(
                    fingerprint="c" * 64,
                    source_device_id=device.id,
                    source="100.64.0.1",
                    destination="100.64.0.2",
                    category="virtual",
                    start=now,
                    end=now,
                    logged=now,
                ),
                SavedView(
                    id=FIXTURE_IDS["view"],
                    owner_id=account.id,
                    name="Preserved view",
                    page="flows",
                    state={"range": "24h"},
                ),
                Finding(
                    id=FIXTURE_IDS["finding"],
                    fingerprint="d" * 64,
                    source="operations",
                    category="upgrade",
                    severity="high",
                    title="Preserved finding",
                    summary="Migration fixture",
                    subject_type="device",
                    subject_id=device.id,
                ),
                OperationalJobRun(
                    id=FIXTURE_IDS["job"],
                    name="upgrade-fixture",
                    category="testing",
                    interval_seconds=300,
                    status="success",
                ),
            ]
        )
        session.flush()
        report = ReportRun(
            id=FIXTURE_IDS["report"],
            period_key="upgrade-fixture",
            requested_by=account.id,
            saved_view_id=FIXTURE_IDS["view"],
            title="Preserved report",
            status="completed",
            range_start=now - timedelta(hours=24),
            range_end=now,
        )
        session.add(report)
        session.flush()
        session.add(
            ReportArtifact(
                run_id=report.id,
                format="json",
                content_type="application/json",
                filename="preserved.json",
                content_hash="e" * 64,
                size=2,
                content=b"{}",
            )
        )
        session.commit()

    legacy_columns = {
        "telemetry_observations": (
            "collector_device_id",
            "client_version",
            "udp",
            "ipv4",
            "ipv6",
            "mapping_varies_by_dest_ip",
            "preferred_derp",
            "endpoints",
            "derp_latency",
        ),
        "local_metadata": (
            "functional_groups",
            "custom_roles",
            "primary_role_override",
            "default_map_visible",
            "revision",
        ),
    }
    with db_engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS device_history_events"))
        for table, columns in legacy_columns.items():
            for column in columns:
                connection.execute(
                    text(f'ALTER TABLE "{table}" DROP COLUMN IF EXISTS "{column}" CASCADE')
                )
        connection.execute(
            text("UPDATE alembic_version SET version_num = '0013_operations_center'")
        )
    db_engine.dispose()


def verify() -> None:
    db_engine = engine()
    with db_engine.connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        assert revision == EXPECTED_HEAD
        db_inspector = inspect(connection)
        assert db_inspector.has_table("device_history_events")
        local_columns = {item["name"] for item in db_inspector.get_columns("local_metadata")}
        telemetry_columns = {
            item["name"] for item in db_inspector.get_columns("telemetry_observations")
        }
        assert {
            "functional_groups",
            "custom_roles",
            "primary_role_override",
            "default_map_visible",
            "revision",
        }.issubset(local_columns)
        assert {"collector_device_id", "client_version", "endpoints", "derp_latency"}.issubset(
            telemetry_columns
        )

    with OrmSession(db_engine) as session:
        for model, identifier in (
            (AppUser, FIXTURE_IDS["user"]),
            (Session, FIXTURE_IDS["session"]),
            (Device, FIXTURE_IDS["device"]),
            (SavedView, FIXTURE_IDS["view"]),
            (Finding, FIXTURE_IDS["finding"]),
            (ReportRun, FIXTURE_IDS["report"]),
            (OperationalJobRun, FIXTURE_IDS["job"]),
            (TelemetryObservation, FIXTURE_IDS["telemetry"]),
        ):
            assert session.get(model, identifier) is not None
        metadata = session.get(LocalMetadata, FIXTURE_IDS["device"])
        assert metadata is not None
        assert metadata.display_name == "Preserved device"
        assert metadata.functional_groups == ["production"]
        assert metadata.default_map_visible is False
        artifact = session.scalar(
            select(ReportArtifact).where(ReportArtifact.run_id == FIXTURE_IDS["report"])
        )
        assert artifact is not None and artifact.content == b"{}"
        assert session.scalar(select(Flow).where(Flow.fingerprint == "c" * 64)) is not None
        account = session.get(AppUser, FIXTURE_IDS["user"])
        assert account is not None
        assert verify_password(account.password_hash, "preserved-upgrade-password")
    db_engine.dispose()


if __name__ == "__main__":
    if sys.argv[1:] == ["prepare"]:
        prepare()
    elif sys.argv[1:] == ["verify"]:
        verify()
    else:
        raise SystemExit("Usage: release_upgrade_check.py prepare|verify")
