from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from app import main, operations
from app.config import Settings
from app.findings import collect_findings
from app.models import (
    BackupVerification,
    Base,
    CleanupRun,
    Flow,
    FlowAggregateState,
    OperationalJobRun,
    OperationalJobState,
)
from app.operations import instrument_job, operations_summary, retention_snapshot, storage_snapshot


@pytest.fixture
async def database(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(operations, "engine", engine)
    monkeypatch.setattr(operations, "SessionLocal", factory)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_instrumented_job_records_success_and_failure(database) -> None:
    async def success() -> int:
        return 7

    assert await instrument_job("test-success", "testing", 60, success)() == 7

    async def failure() -> None:
        raise ValueError("unsafe details must not be persisted")

    with pytest.raises(ValueError):
        await instrument_job("test-failure", "testing", 60, failure)()
    async with database() as session:
        rows = (
            await session.scalars(select(OperationalJobRun).order_by(OperationalJobRun.name))
        ).all()
        assert [(row.name, row.status, row.error_class) for row in rows] == [
            ("test-failure", "failed", "ValueError"),
            ("test-success", "success", ""),
        ]
        failed = await session.get(OperationalJobState, "test-failure")
        assert failed is not None and failed.consecutive_failures == 1


@pytest.mark.asyncio
async def test_operations_summary_detects_overdue_jobs_and_queue_age(database) -> None:
    now = datetime.now(UTC)
    async with database() as session:
        session.add_all(
            [
                OperationalJobState(
                    name="scheduler",
                    category="runtime",
                    interval_seconds=30,
                    last_status="success",
                    heartbeat_at=now - timedelta(seconds=5),
                ),
                OperationalJobState(
                    name="stalled",
                    category="aggregation",
                    interval_seconds=60,
                    last_status="running",
                    heartbeat_at=now - timedelta(minutes=20),
                ),
                BackupVerification(
                    filename="verified.dump",
                    content_hash="a" * 64,
                    size=10,
                    status="success",
                    verified_at=now - timedelta(hours=12),
                ),
            ]
        )
        await session.commit()
        value = await operations_summary(session)
        assert value["status"] == "degraded"
        assert value["degraded_jobs"] == 1
        stalled = next(item for item in value["jobs"] if item["name"] == "stalled")
        assert stalled["overdue"] is True and stalled["unhealthy"] is True
        assert value["backup"]["stale"] is False


@pytest.mark.asyncio
async def test_retention_never_expires_raw_flows_before_aggregate_coverage(database) -> None:
    now = datetime.now(UTC)
    settings = Settings(flow_retention_days=30)
    async with database() as session:
        session.add(
            Flow(
                fingerprint="old-flow",
                source="100.64.0.1",
                destination="100.64.0.2",
                category="virtual",
                start=now - timedelta(days=40),
                end=now - timedelta(days=40) + timedelta(seconds=1),
                logged=now - timedelta(days=40),
            )
        )
        await session.commit()
        blocked = await retention_snapshot(session, settings)
        assert blocked["raw_flow_cleanup_blocked"] is True
        assert blocked["eligible"]["raw_flows"] == 0
        session.add_all(
            [
                FlowAggregateState(
                    granularity=granularity,
                    coverage_start=now - timedelta(days=60),
                    coverage_end=now,
                    last_success=now,
                )
                for granularity in ("hourly", "daily")
            ]
        )
        await session.commit()
        covered = await retention_snapshot(session, settings)
        assert covered["raw_flow_cleanup_blocked"] is False
        assert covered["eligible"]["raw_flows"] == 1
        storage = await storage_snapshot(session)
        assert storage["database_bytes"] is None
        assert storage["counts"]["raw_flows"] == 1


@pytest.mark.asyncio
async def test_operations_findings_require_persistent_failures(database) -> None:
    now = datetime.now(UTC)
    async with database() as session:
        session.add(
            OperationalJobState(
                name="network-reports",
                category="reporting",
                interval_seconds=30,
                last_status="failed",
                consecutive_failures=1,
                heartbeat_at=now,
            )
        )
        session.add(CleanupRun(status="failed", error_class="FirstFailure", started_at=now))
        session.add(
            BackupVerification(
                filename="old.dump",
                content_hash="b" * 64,
                size=10,
                status="success",
                verified_at=now - timedelta(hours=72),
            )
        )
        await session.commit()
        candidates, complete = await collect_findings(session, now)
        assert "operations" in complete
        assert not any(item.source == "operations" for item in candidates)
        state = await session.get(OperationalJobState, "network-reports")
        assert state is not None
        state.consecutive_failures = 2
        session.add(
            CleanupRun(
                status="failed", error_class="SecondFailure", started_at=now + timedelta(seconds=1)
            )
        )
        await session.commit()
        candidates, _ = await collect_findings(session, now + timedelta(seconds=2))
        categories = {item.category for item in candidates if item.source == "operations"}
        assert {
            "repeated_job_failure",
            "cleanup_failure",
            "stale_backup_verification",
        }.issubset(categories)


@pytest.mark.asyncio
async def test_readiness_checks_database_scheduler_and_encryption(database, monkeypatch) -> None:
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    async with operations.engine.begin() as connection:
        await connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(64))"))
        await connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('0014_v1_completion')")
        )
    monkeypatch.setattr(main, "engine", operations.engine)
    monkeypatch.setattr(main, "packaged_schema_heads", lambda: ("0014_v1_completion",))
    monkeypatch.setattr(
        main,
        "settings",
        SimpleNamespace(
            production=False,
            encryption_key=key,
            demo_mode=False,
            tailview_version="1.0.0-rc.1",
            tailview_revision="abc123",
            tailview_build_time="2026-07-22T12:00:00Z",
        ),
    )
    request = Request(
        {"type": "http", "method": "GET", "path": "/health/ready", "headers": []}
    )
    request.scope["app"] = SimpleNamespace(
        state=SimpleNamespace(scheduler=SimpleNamespace(running=True))
    )
    response = await main.ready(request)
    assert response.status_code == 200
    body = json.loads(bytes(response.body))
    assert body["checks"] == {
        "database": True,
        "migrations": True,
        "scheduler": True,
        "encryption": True,
    }
    assert body["schema"] == {
        "expected": ["0014_v1_completion"],
        "current": ["0014_v1_completion"],
    }
    assert body["version"]["application"] == "1.0.0-rc.1"
    monkeypatch.setattr(
        main,
        "settings",
        SimpleNamespace(
            production=False,
            encryption_key="bad",
            demo_mode=False,
            tailview_version="dev",
            tailview_revision="unknown",
            tailview_build_time="unknown",
        ),
    )
    failed = await main.ready(request)
    assert failed.status_code == 503
    assert json.loads(bytes(failed.body))["checks"]["encryption"] is False


@pytest.mark.asyncio
async def test_readiness_rejects_missing_older_newer_and_multiple_revisions(
    database, monkeypatch
) -> None:
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    monkeypatch.setattr(main, "engine", operations.engine)
    monkeypatch.setattr(main, "packaged_schema_heads", lambda: ("0014_v1_completion",))
    monkeypatch.setattr(
        main,
        "settings",
        SimpleNamespace(
            production=True,
            encryption_key=key,
            demo_mode=True,
            tailview_version="dev",
            tailview_revision="unknown",
            tailview_build_time="unknown",
        ),
    )
    request = Request({"type": "http", "method": "GET", "path": "/health/ready", "headers": []})
    request.scope["app"] = SimpleNamespace(state=SimpleNamespace(scheduler=None))
    async with operations.engine.begin() as connection:
        await connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(64))"))

    for revisions in [[], ["0013_operations_center"], ["0015_future"], ["a", "b"]]:
        async with operations.engine.begin() as connection:
            await connection.execute(text("DELETE FROM alembic_version"))
            for revision in revisions:
                await connection.execute(
                    text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                    {"revision": revision},
                )
        response = await main.ready(request)
        assert response.status_code == 503
        assert json.loads(bytes(response.body))["checks"]["migrations"] is False

    monkeypatch.setattr(
        main, "packaged_schema_heads", lambda: ("0014_v1_completion", "0014_other")
    )
    async with operations.engine.begin() as connection:
        await connection.execute(text("DELETE FROM alembic_version"))
        await connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('0014_v1_completion')")
        )
    response = await main.ready(request)
    assert response.status_code == 503
