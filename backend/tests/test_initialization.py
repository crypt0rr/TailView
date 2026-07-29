from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import initialization_status
from app.config import Settings
from app.models import Base, Capability, SyncJob


def settings(*, configured: bool) -> Settings:
    return Settings(
        _env_file=None,
        environment="test",
        tailscale_tailnet="-",
        tailscale_oauth_client_id="client" if configured else "",
        tailscale_oauth_client_secret="secret" if configured else "",
        inventory_interval_seconds=300,
    )


@pytest.mark.asyncio
async def test_initialization_distinguishes_collecting_attention_and_ready() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        missing = await initialization_status(session, settings(configured=False))
        assert missing == {
            "state": "attention",
            "expected_wait_minutes": 5,
            "started_at": None,
            "detail": "Read-only Tailscale credentials are not configured.",
        }

        collecting = await initialization_status(session, settings(configured=True))
        assert collecting["state"] == "collecting"
        assert collecting["expected_wait_minutes"] == 5
        assert collecting["started_at"] is None
        assert "normally appears within 5 minutes" in collecting["detail"]

        failed_job = SyncJob(kind="devices", status="failed", finished_at=datetime.now(UTC))
        session.add(failed_job)
        await session.commit()

        attention = await initialization_status(session, settings(configured=True))
        assert attention["state"] == "attention"
        assert attention["started_at"] == failed_job.started_at

        session.add(
            Capability(
                name="device_inventory",
                status="upstream_error",
                source="test",
                last_success=datetime.now(UTC),
            )
        )
        await session.commit()

        ready = await initialization_status(session, settings(configured=True))
        assert ready["state"] == "ready"
        assert ready["detail"] == "Initial device synchronization completed successfully."
    await engine.dispose()


@pytest.mark.asyncio
async def test_successful_empty_device_inventory_is_ready() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(
            Capability(
                name="device_inventory",
                status="available",
                source="test",
                last_success=datetime.now(UTC),
            )
        )
        await session.commit()

        result = await initialization_status(session, settings(configured=True))

        assert result["state"] == "ready"
    await engine.dispose()


@pytest.mark.asyncio
async def test_stale_or_cancelled_initial_device_jobs_need_attention() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        stale = SyncJob(
            kind="devices",
            status="running",
            started_at=datetime.now(UTC) - timedelta(minutes=7),
        )
        session.add(stale)
        await session.commit()

        result = await initialization_status(session, settings(configured=True))
        assert result["state"] == "attention"

        stale.status = "cancelled"
        stale.started_at = datetime.now(UTC)
        await session.commit()

        result = await initialization_status(session, settings(configured=True))
        assert result["state"] == "attention"
    await engine.dispose()
