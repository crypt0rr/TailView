from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import device as device_endpoint
from app.config import Settings
from app.models import AppUser, Base, Capability, Device, Flow, TailnetUser


def make_flow(
    fingerprint: str,
    *,
    source_device_id: str,
    destination: str,
    category: str = "physical",
    age_hours: int = 1,
) -> Flow:
    end = datetime.now(UTC) - timedelta(hours=age_hours)
    return Flow(
        fingerprint=fingerprint,
        reporting_node_id="observer-node",
        source_device_id=source_device_id,
        destination_device_id=None,
        source="100.100.1.1",
        destination=destination,
        protocol=None,
        source_port=None,
        destination_port=41641,
        category=category,
        tx_bytes=100,
        rx_bytes=50,
        tx_packets=1,
        rx_packets=1,
        start=end - timedelta(seconds=5),
        end=end,
        logged=end + timedelta(seconds=1),
        raw={},
    )


@pytest.mark.asyncio
async def test_device_endpoint_attributes_only_matching_recent_physical_flows() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        owner = TailnetUser(id="owner", display_name="Owner", login_name="owner@example.com")
        selected = Device(
            id="selected-node",
            name="selected.example.ts.net",
            hostname="selected",
            owner_id="owner",
            online=True,
            authorized=True,
            addresses=["100.100.1.1", "fd7a:115c:a1e0::1"],
            tags=[],
            advertised_routes=[],
            approved_routes=[],
            roles=["standard_node"],
            primary_role="standard_node",
        )
        other = Device(
            id="other-node",
            name="other.example.ts.net",
            hostname="other",
            owner_id=None,
            online=True,
            authorized=True,
            addresses=["100.100.2.2"],
            tags=[],
            advertised_routes=[],
            approved_routes=[],
            roles=["standard_node"],
            primary_role="standard_node",
        )
        observer = Device(
            id="observer-node",
            name="observer.example.ts.net",
            hostname="observer",
            owner_id=None,
            online=True,
            authorized=True,
            addresses=["100.100.3.3"],
            tags=[],
            advertised_routes=[],
            approved_routes=[],
            roles=["standard_node"],
            primary_role="standard_node",
        )
        session.add_all(
            [
                owner,
                selected,
                other,
                observer,
                Capability(
                    name="network_flow_logs",
                    status="available",
                    source="test",
                ),
                make_flow("included", source_device_id=selected.id, destination="8.8.8.8"),
                make_flow("unrelated", source_device_id=other.id, destination="9.9.9.9"),
                make_flow(
                    "virtual",
                    source_device_id=selected.id,
                    destination="1.1.1.1",
                    category="virtual",
                ),
                make_flow(
                    "expired",
                    source_device_id=selected.id,
                    destination="4.4.4.4",
                    age_hours=200,
                ),
            ]
        )
        await session.commit()

        result = await device_endpoint(
            device_id=selected.id,
            _=AppUser(username="viewer", password_hash="unused", role="viewer"),
            db=session,
            settings=Settings(flow_retention_days=30),
            address_hours=168,
        )

        inventory = result["address_inventory"]
        assert inventory["status"] == "available"
        assert [item["address"] for item in inventory["observed"]] == ["8.8.8.8"]
        assert inventory["observed"][0]["observers"] == [
            {"id": "observer-node", "name": "observer.example.ts.net"}
        ]
        assert len(inventory["tailnet"]) == 2

        with pytest.raises(HTTPException) as exc_info:
            await device_endpoint(
                device_id=selected.id,
                _=AppUser(username="viewer", password_hash="unused", role="viewer"),
                db=session,
                settings=Settings(),
                address_hours=48,
            )
        assert exc_info.value.status_code == 422
    await engine.dispose()
