from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import api
from app.config import Settings
from app.models import (
    AppUser,
    Base,
    Device,
    Flow,
    FlowAggregate,
    FlowAggregateState,
    ReportArtifact,
    ReportRun,
    ReportSchedule,
    SavedView,
)
from app.reporting import (
    aggregate_report_data,
    artifact_payloads,
    build_report_snapshot,
    cleanup_flow_data,
    next_schedule_time,
    rebuild_aggregate_range,
    render_csv_bundle,
    update_flow_aggregates,
)
from app.schemas import ReportGenerateRequest, ReportScheduleRequest


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


def flow(
    fingerprint: str,
    started: datetime,
    source: str = "source-1",
    destination: str = "destination-1",
    byte_count: int = 100,
) -> Flow:
    return Flow(
        fingerprint=fingerprint,
        source_device_id=source,
        destination_device_id=destination,
        source="100.64.0.1",
        destination="100.64.0.2",
        protocol=6,
        source_port=50000,
        destination_port=443,
        category="virtual",
        tx_bytes=byte_count,
        rx_bytes=byte_count,
        tx_packets=2,
        rx_packets=3,
        start=started,
        end=started + timedelta(minutes=1),
        logged=started + timedelta(minutes=2),
    )


@pytest.mark.asyncio
async def test_aggregate_rebuild_is_exact_and_captures_late_records(db) -> None:
    now = datetime(2026, 7, 22, 12, 30, tzinfo=UTC)
    db.add_all(
        [
            flow("one", now - timedelta(hours=2), byte_count=100),
            flow("two", now - timedelta(hours=2), byte_count=250),
        ]
    )
    await db.commit()
    await rebuild_aggregate_range(db, "hourly", now - timedelta(hours=3), now)
    await db.commit()
    row = await db.scalar(select(FlowAggregate))
    assert row is not None
    assert row.reported_bytes == 700
    assert row.reported_packets == 10
    assert row.record_count == 2
    db.expunge(row)

    db.add(flow("late", now - timedelta(hours=2), byte_count=50))
    await db.commit()
    await rebuild_aggregate_range(db, "hourly", now - timedelta(hours=3), now)
    await db.commit()
    assert await db.scalar(select(func.count()).select_from(FlowAggregate)) == 1
    row = await db.scalar(select(FlowAggregate))
    assert row is not None and row.reported_bytes == 800 and row.record_count == 3


@pytest.mark.asyncio
async def test_aggregate_filters_match_report_dimensions(db) -> None:
    now = datetime(2026, 7, 22, 12, tzinfo=UTC)
    db.add_all(
        [
            Device(id="source-1", name="Gateway", hostname="gateway"),
            Device(id="destination-1", name="Database", hostname="db"),
            flow("included", now - timedelta(hours=1), byte_count=300),
            flow("other", now - timedelta(hours=1), source="other", byte_count=900),
        ]
    )
    await db.commit()
    await rebuild_aggregate_range(db, "hourly", now - timedelta(hours=2), now)
    await db.commit()
    result = await aggregate_report_data(
        db,
        now - timedelta(hours=2),
        now,
        {"source": "Gateway", "protocol": "6", "port": "443", "resolution": "resolved"},
    )
    assert result["totals"] == {
        "reported_bytes": 600,
        "reported_packets": 5,
        "record_count": 1,
    }
    assert result["top_devices"][0]["name"] in {"Gateway", "Database"}


@pytest.mark.asyncio
async def test_report_snapshot_and_all_artifact_formats(db) -> None:
    now = datetime(2026, 7, 22, 12, tzinfo=UTC)
    db.add_all(
        [
            Device(id="source-1", name="Gateway", hostname="gateway", approved_routes=[]),
            Device(id="destination-1", name="Database", hostname="db", approved_routes=[]),
            flow("one", now - timedelta(hours=2), byte_count=1000),
            flow("two", now - timedelta(hours=1), byte_count=2000),
        ]
    )
    db.add(
        FlowAggregateState(
            granularity="hourly",
            coverage_start=now - timedelta(days=2),
            coverage_end=now + timedelta(hours=1),
            last_success=now,
        )
    )
    await db.commit()
    await rebuild_aggregate_range(db, "hourly", now - timedelta(days=1), now)
    run = ReportRun(
        period_key="manual:test",
        title="Gateway report",
        range_start=now - timedelta(days=1),
        range_end=now,
        filters={},
    )
    db.add(run)
    await db.commit()
    snapshot = await build_report_snapshot(db, run)
    payloads = artifact_payloads(snapshot)

    assert snapshot["schema_version"] == "1"
    assert snapshot["coverage"]["complete"] is True
    assert set(payloads) == {"pdf", "json", "csv"}
    assert payloads["pdf"][2].startswith(b"%PDF")
    assert json.loads(payloads["json"][2])["report_id"] == run.id
    with zipfile.ZipFile(BytesIO(render_csv_bundle(snapshot))) as archive:
        assert {
            "metadata.csv",
            "summary.csv",
            "timeseries.csv",
            "top_devices.csv",
            "top_pairs.csv",
            "top_services.csv",
        }.issubset(archive.namelist())


def test_schedule_time_handles_dst_and_frequency() -> None:
    daily = ReportSchedule(
        name="Daily",
        frequency="daily",
        timezone="Europe/Amsterdam",
        local_time="02:30",
        created_by="admin",
    )
    result = next_schedule_time(daily, datetime(2026, 3, 28, 23, tzinfo=UTC))
    assert result.astimezone(UTC).date().isoformat() == "2026-03-29"
    # 02:30 does not exist on this transition; execution shifts to the first valid minute.
    assert result.hour == 1

    weekly = ReportSchedule(
        name="Weekly",
        frequency="weekly",
        timezone="UTC",
        local_time="08:00",
        weekday=0,
        created_by="admin",
    )
    assert next_schedule_time(weekly, datetime(2026, 7, 22, tzinfo=UTC)).weekday() == 0


@pytest.mark.asyncio
async def test_raw_cleanup_waits_for_successful_aggregate_coverage(db) -> None:
    now = datetime(2026, 7, 22, 12, tzinfo=UTC)
    old = flow("old", now - timedelta(days=40))
    db.add(old)
    await db.commit()
    settings = Settings(flow_retention_days=30)
    await cleanup_flow_data(db, settings, now)
    assert await db.get(Flow, old.id) is not None

    await update_flow_aggregates(db, now)
    await cleanup_flow_data(db, settings, now)
    assert await db.get(Flow, old.id) is None


@pytest.mark.asyncio
async def test_saved_view_and_report_models_preserve_revision(db) -> None:
    admin = AppUser(username="admin", password_hash="hash", role="administrator")
    db.add(admin)
    await db.flush()
    view = SavedView(
        owner_id=admin.id,
        name="Gateway traffic",
        page="flows",
        state={
            "range": "7d",
            "category": "virtual",
            "source": "Gateway",
            "destination": "",
            "protocol": "6",
            "port": "443",
            "resolution": "all",
            "ranking_limit": 10,
        },
        revision=4,
    )
    db.add(view)
    await db.commit()
    assert view.revision == 4

    schedule = await api.create_report_schedule(
        ReportScheduleRequest(
            name="Weekly gateway",
            saved_view_id=view.id,
            frequency="weekly",
            timezone="Europe/Amsterdam",
            local_time="08:30",
            weekday=1,
        ),
        admin,
        None,
        db,
    )
    assert schedule["next_run_at"] is not None
    queued = await api.generate_network_report(
        ReportGenerateRequest(saved_view_id=view.id, range="90d"),
        admin,
        None,
        db,
    )
    assert queued["status"] == "queued"


@pytest.mark.asyncio
async def test_authenticated_download_has_safe_metadata(db) -> None:
    viewer = AppUser(username="viewer", password_hash="hash", role="viewer")
    run = ReportRun(
        period_key="manual:download",
        title="Download test",
        status="completed",
        range_start=datetime(2026, 7, 21, tzinfo=UTC),
        range_end=datetime(2026, 7, 22, tzinfo=UTC),
        completed_at=datetime(2026, 7, 22, tzinfo=UTC),
    )
    db.add_all([viewer, run])
    await db.flush()
    db.add(
        ReportArtifact(
            run_id=run.id,
            format="pdf",
            content_type="application/pdf",
            filename="download-test.pdf",
            content_hash="a" * 64,
            size=8,
            content=b"%PDFtest",
        )
    )
    await db.commit()
    response = await api.download_report(run.id, viewer, db, "pdf")
    assert response.body == b"%PDFtest"
    assert response.headers["x-tailview-content-sha256"] == "a" * 64
    assert "download-test.pdf" in response.headers["content-disposition"]
