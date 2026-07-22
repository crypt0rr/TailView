from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import (
    _flow_dict,
    device_dict,
    flow_identity,
    preferred_device_label,
    service_address_map,
)
from app.models import Base, Device, Flow, TailnetService, TailnetUser


def test_device_response_prefers_owner_display_name() -> None:
    device = Device(
        id="node-1",
        name="database.example.ts.net",
        hostname="database",
        owner_id="user-1",
        online=True,
        authorized=True,
        addresses=[],
        tags=[],
        advertised_routes=[],
        approved_routes=[],
        roles=["service_hosting"],
        primary_role="service_hosting",
    )
    owner = TailnetUser(
        id="user-1",
        display_name="Alice Example",
        login_name="alice@example.com",
    )

    response = device_dict(device, owner=owner)

    assert response["owner_display_name"] == "Alice Example"
    assert response["owner_login_name"] == "alice@example.com"
    assert response["owner_id"] == "user-1"


def test_flow_identity_prefers_device_name_and_retains_raw_value() -> None:
    identity = flow_identity(
        "node-1", "100.64.0.1", {"node-1": "database.example.ts.net"}, "Unresolved"
    )

    assert identity == {
        "id": "node-1",
        "label": "database.example.ts.net",
        "raw": "100.64.0.1",
    }


def test_flow_identity_retains_unresolved_address() -> None:
    identity = flow_identity(None, "192.0.2.10", {}, "Unresolved")

    assert identity == {"id": None, "label": "192.0.2.10", "raw": "192.0.2.10"}


def test_export_label_prefers_device_name() -> None:
    assert preferred_device_label("node-1", "100.64.0.1", {"node-1": "database"}) == "database"


@pytest.mark.asyncio
async def test_service_address_attribution_requires_an_unambiguous_exact_match() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add_all(
            [
                TailnetService(id="svc:web", name="Web", addresses=["100.100.100.1"]),
                TailnetService(id="svc:a", name="A", addresses=["100.100.100.2"]),
                TailnetService(id="svc:b", name="B", addresses=["100.100.100.2"]),
            ]
        )
        await session.commit()
        addresses = await service_address_map(session)
        assert addresses == {"100.100.100.1": ("svc:web", "Web")}
        now = datetime.now(UTC)
        flow = Flow(
            fingerprint="service-flow",
            source="100.64.0.1",
            destination="100.100.100.1",
            category="virtual",
            tx_bytes=1,
            rx_bytes=2,
            tx_packets=1,
            rx_packets=1,
            start=now,
            end=now,
            logged=now,
            raw={},
        )
        item = _flow_dict(flow, {}, addresses)
        assert item["destination"] == "Web"
        assert item["destination_service_id"] == "svc:web"
    await engine.dispose()
