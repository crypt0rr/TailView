import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import capabilities
from app.models import AppUser, Base, Capability, TailnetService


@pytest.mark.asyncio
async def test_successfully_empty_service_inventory_is_not_in_use_until_data_arrives() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    viewer = AppUser(username="viewer", password_hash="unused", role="viewer")
    async with factory() as session:
        session.add(
            Capability(
                name="services",
                status="available",
                source="test",
                requirement="all:read",
                detail="Synchronized",
            )
        )
        await session.commit()

        empty = await capabilities(viewer, session)

        assert empty["navigation"]["/services"] == {
            "count": 0,
            "evaluated": True,
            "in_use": False,
            "status": "not_configured",
            "detail": (
                "Successfully synchronized; no Tailscale Services are currently configured."
            ),
            "checked_at": empty["navigation"]["/services"]["checked_at"],
        }

        session.add(TailnetService(id="svc:web", name="svc:web", present=True))
        await session.commit()

        populated = await capabilities(viewer, session)

        assert populated["navigation"]["/services"]["count"] == 1
        assert populated["navigation"]["/services"]["in_use"] is True
        assert populated["navigation"]["/services"]["status"] == "active"
    await engine.dispose()
