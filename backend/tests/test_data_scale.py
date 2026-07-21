from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import dashboard, devices, export_flows, flows, flows_summary
from app.config import Settings
from app.flow_data import decode_cursor, encode_cursor, fill_series
from app.models import AppUser, Base, Device, Flow, LocalMetadata


def make_device(device_id: str, name: str) -> Device:
    return Device(
        id=device_id,
        name=name,
        hostname=name.split(".")[0],
        online=True,
        authorized=True,
        addresses=[],
        tags=[],
        advertised_routes=[],
        approved_routes=[],
        roles=["standard_node"],
        primary_role="standard_node",
    )


def make_flow(
    fingerprint: str,
    started_at: datetime,
    *,
    source_device_id: str | None = "node-a",
    destination_device_id: str | None = "node-b",
    source: str = "100.64.0.1",
    destination: str = "100.64.0.2",
    category: str = "virtual",
    protocol: int | None = 6,
    port: int | None = 443,
    byte_count: int = 150,
) -> Flow:
    return Flow(
        fingerprint=fingerprint,
        reporting_node_id=source_device_id,
        source_device_id=source_device_id,
        destination_device_id=destination_device_id,
        source=source,
        destination=destination,
        protocol=protocol,
        source_port=50000,
        destination_port=port,
        category=category,
        tx_bytes=byte_count - 50,
        rx_bytes=50,
        tx_packets=2,
        rx_packets=1,
        start=started_at,
        end=started_at + timedelta(seconds=5),
        logged=started_at + timedelta(seconds=10),
        raw={},
    )


@pytest.fixture
async def db_session():  # type: ignore[no-untyped-def]
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


VIEWER = AppUser(username="viewer", password_hash="unused", role="viewer")


def test_versioned_cursors_are_typed_and_reject_wrong_kinds() -> None:
    cursor = encode_cursor("flows", {"start": "2026-01-01T00:00:00+00:00", "id": 4})
    assert decode_cursor(cursor, "flows") == {
        "v": 1,
        "kind": "flows",
        "start": "2026-01-01T00:00:00+00:00",
        "id": 4,
    }
    with pytest.raises(HTTPException):
        decode_cursor(cursor, "devices")


def test_series_fills_empty_utc_buckets() -> None:
    now = datetime(2026, 7, 21, 12, 2, tzinfo=UTC)
    series = fill_series(
        [(datetime(2026, 7, 21, 11, 5, tzinfo=UTC), 300, 5, 2)],
        now=now,
        hours=1,
    )
    assert len(series) == 13
    assert sum(point["reported_bytes"] for point in series) == 300
    assert sum(point["record_count"] for point in series) == 2


def test_flow_query_indexes_cover_keyset_and_allowlisted_filters() -> None:
    index_names = {index.name for index in Flow.__table__.indexes}
    assert {
        "ix_flows_start_id",
        "ix_flows_category_start_id",
        "ix_flows_protocol_start_id",
        "ix_flows_destination_port_start_id",
    } <= index_names


@pytest.mark.asyncio
async def test_flow_keyset_is_stable_when_newer_rows_are_inserted(db_session) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    db_session.add_all(
        [
            make_device("node-a", "alpha.example.ts.net"),
            make_device("node-b", "beta.example.ts.net"),
            make_flow("one", now - timedelta(minutes=1)),
            make_flow("two", now - timedelta(minutes=1)),
            make_flow("three", now - timedelta(minutes=1)),
        ]
    )
    await db_session.commit()
    first = await flows(
        VIEWER,
        db_session,
        cursor=None,
        limit=2,
        source="",
        destination="",
        category="",
        protocol=None,
        port=None,
        resolution="all",
        hours=24,
    )
    assert first["next_cursor"]
    db_session.add(make_flow("newer", now))
    await db_session.commit()
    second = await flows(
        VIEWER,
        db_session,
        cursor=first["next_cursor"],
        limit=2,
        source="",
        destination="",
        category="",
        protocol=None,
        port=None,
        resolution="all",
        hours=24,
    )
    first_ids = {item["id"] for item in first["items"]}
    second_ids = {item["id"] for item in second["items"]}
    assert first_ids.isdisjoint(second_ids)
    assert [item["destination"] for item in second["items"]] == ["beta.example.ts.net"]


@pytest.mark.asyncio
async def test_flow_filters_summary_dashboard_and_export_agree(db_session) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    db_session.add_all(
        [
            make_device("node-a", "alpha.example.ts.net"),
            make_device("node-b", "beta.example.ts.net"),
            LocalMetadata(device_id="node-a", display_name="Friendly Alpha"),
            make_flow("match", now - timedelta(minutes=5), byte_count=500),
            make_flow(
                "other",
                now - timedelta(minutes=4),
                destination_device_id=None,
                destination="203.0.113.10",
                category="physical",
                protocol=17,
                port=53,
                byte_count=900,
            ),
        ]
    )
    await db_session.commit()
    result = await flows(
        VIEWER,
        db_session,
        cursor=None,
        limit=100,
        source="Friendly Alpha",
        destination="beta",
        category="virtual",
        protocol=6,
        port=443,
        resolution="resolved",
        hours=24,
    )
    assert len(result["items"]) == 1
    assert result["items"][0]["reported_bytes"] == 500

    summary = await flows_summary(
        VIEWER,
        db_session,
        source="Friendly Alpha",
        destination="beta",
        category="virtual",
        protocol=6,
        port=443,
        resolution="resolved",
        hours=24,
    )
    assert summary["reported_bytes"] == 500
    assert summary["reported_packets"] == 3
    assert summary["record_count"] == 1

    overview = await dashboard(VIEWER, db_session, hours=24)
    assert sum(point["reported_bytes"] for point in overview["traffic_series"]) == 1400
    assert overview["top_pairs"][0]["reported_bytes"] in {500, 900}

    response = await export_flows(
        "csv",
        VIEWER,
        db_session,
        Settings(export_row_limit=1),
        source="",
        destination="",
        category="",
        protocol=None,
        port=None,
        resolution="all",
        hours=24,
    )
    body = "".join([chunk async for chunk in response.body_iterator])
    assert response.headers["x-tailview-export-limit"] == "1"
    assert response.headers["x-tailview-export-truncated"] == "true"
    assert len(body.strip().splitlines()) == 2


@pytest.mark.asyncio
async def test_device_keyset_uses_display_name_and_filters(db_session) -> None:  # type: ignore[no-untyped-def]
    db_session.add_all(
        [
            make_device("node-z", "zulu.example.ts.net"),
            make_device("node-a", "alpha.example.ts.net"),
            LocalMetadata(device_id="node-z", display_name="Aardvark"),
        ]
    )
    await db_session.commit()
    first = await devices(
        VIEWER,
        db_session,
        cursor=None,
        limit=1,
        search="",
        role="",
        status_filter="online",
        owner="",
        key_expiry="",
    )
    second = await devices(
        VIEWER,
        db_session,
        cursor=first["next_cursor"],
        limit=1,
        search="",
        role="",
        status_filter="online",
        owner="",
        key_expiry="",
    )
    assert [first["items"][0]["name"], second["items"][0]["name"]] == [
        "Aardvark",
        "alpha.example.ts.net",
    ]


@pytest.mark.asyncio
async def test_expiring_key_overview_excludes_expired_and_long_lived_keys(db_session) -> None:  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    expired = make_device("expired", "expired.example.ts.net")
    expired.key_expiry = now - timedelta(days=1)
    expired.key_expiry_disabled = False
    expiring = make_device("expiring", "expiring.example.ts.net")
    expiring.key_expiry = now + timedelta(days=7)
    expiring.key_expiry_disabled = False
    valid = make_device("valid", "valid.example.ts.net")
    valid.key_expiry = now + timedelta(days=30)
    valid.key_expiry_disabled = False
    disabled = make_device("disabled", "disabled.example.ts.net")
    disabled.key_expiry = now - timedelta(days=365)
    disabled.key_expiry_disabled = True
    db_session.add_all([expired, expiring, valid, disabled])
    await db_session.commit()

    overview = await dashboard(VIEWER, db_session, hours=24)
    page = await devices(
        VIEWER,
        db_session,
        cursor=None,
        limit=50,
        search="",
        role="",
        status_filter="",
        owner="",
        key_expiry="within_14_days",
    )

    assert overview["expiring_keys"] == 1
    assert [item["id"] for item in page["items"]] == ["expiring"]

    disabled_page = await devices(
        VIEWER,
        db_session,
        cursor=None,
        limit=50,
        search="",
        role="",
        status_filter="",
        owner="",
        key_expiry="disabled",
    )
    assert [item["id"] for item in disabled_page["items"]] == ["disabled"]
