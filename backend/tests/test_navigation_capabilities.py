import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import capabilities, devices
from app.models import AppUser, Base, Capability, Device, TailnetService


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


@pytest.mark.asyncio
async def test_subnet_navigation_and_page_use_all_device_roles() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    viewer = AppUser(username="viewer", password_hash="unused", role="viewer")
    async with factory() as session:
        session.add(Capability(name="routes", status="available", source="test"))
        await session.commit()

        empty = await capabilities(viewer, session)
        assert empty["navigation"]["/subnet-routers"]["in_use"] is False
        assert empty["navigation"]["/subnet-routers"]["status"] == "not_configured"

        session.add(
            Device(
                id="node-router",
                name="combined-router.example.ts.net",
                roles=["exit_node", "subnet_router"],
                primary_role="exit_node",
                advertised_routes=["0.0.0.0/0", "10.20.0.0/16"],
            )
        )
        await session.commit()

        populated = await capabilities(viewer, session)
        assert populated["navigation"]["/subnet-routers"]["count"] == 1
        assert populated["navigation"]["/subnet-routers"]["in_use"] is True
        page = await devices(
            viewer,
            session,
            cursor=None,
            limit=50,
            search="",
            role="subnet_router",
            status_filter="",
            owner="",
            key_expiry="",
            posture_result="",
        )
        assert [item["id"] for item in page["items"]] == ["node-router"]
    await engine.dispose()
