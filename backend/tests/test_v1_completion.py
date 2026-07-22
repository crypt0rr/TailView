from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from starlette.requests import Request

from app.api import (
    device_access,
    device_history,
    telemetry,
    telemetry_observations,
    telemetry_summary,
    update_metadata,
)
from app.config import Settings
from app.models import AppUser, Base, Device, Flow, LocalMetadata, PolicySnapshot
from app.schemas import MetadataUpdate


def request_for(body: bytes = b"", signature: str = "") -> Request:
    sent = False

    async def receive() -> dict[str, object]:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    headers = [(b"user-agent", b"pytest")]
    if signature:
        headers.append((b"x-tailview-signature", signature.encode()))
    request = Request(
        {
            "type": "http",
            "method": "PUT",
            "path": "/",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "scheme": "http",
            "server": ("test", 80),
        },
        receive,
    )
    request.state.correlation_id = "test-correlation"
    return request


@pytest.mark.asyncio
async def test_metadata_is_revisioned_audited_and_added_to_device_history() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    administrator = AppUser(
        id="admin", username="admin", password_hash="unused", role="administrator"
    )
    async with factory() as session:
        session.add_all([administrator, Device(id="node", name="node.example.ts.net")])
        await session.commit()
        result = await update_metadata(
            "node",
            MetadataUpdate(
                display_name="Database",
                functional_groups=["production", "data"],
                custom_roles=["database"],
                primary_role_override="database",
                criticality="critical",
                default_map_visible=False,
            ),
            administrator,
            None,
            session,
            request_for(),
        )
        assert result["revision"] == 1
        metadata = await session.get(LocalMetadata, "node")
        assert metadata is not None
        assert metadata.hidden is True
        assert metadata.function == "production"

        history = await device_history(
            "node", administrator, session, cursor=None, limit=50, source="", event_type=""
        )
        assert history["items"][0]["changed_fields"] == [
            "display_name",
            "functional_groups",
            "custom_roles",
            "primary_role_override",
            "criticality",
            "default_map_visible",
        ]
        with pytest.raises(HTTPException) as exc:
            await update_metadata(
                "node",
                MetadataUpdate(expected_revision=999),
                administrator,
                None,
                session,
                request_for(),
            )
        assert exc.value.status_code == 409
    await engine.dispose()


@pytest.mark.asyncio
async def test_device_access_keeps_current_policy_and_historical_observation_distinct() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    viewer = AppUser(username="viewer", password_hash="unused", role="viewer")
    now = datetime.now(UTC)
    async with factory() as session:
        session.add_all(
            [
                Device(id="source", name="source.example.ts.net", addresses=["100.64.0.1"]),
                Device(id="target", name="target.example.ts.net", addresses=["100.64.0.2"]),
                Device(id="historic", name="historic.example.ts.net", addresses=["100.64.0.3"]),
                PolicySnapshot(
                    id="policy",
                    hujson='{"hosts":{"src-host":"100.64.0.1","dst-host":"100.64.0.2"},"grants":[{"src":["src-host"],"dst":["dst-host"],"ip":["tcp:443"]}]}',
                    normalized={
                        "hosts": {"src-host": "100.64.0.1", "dst-host": "100.64.0.2"},
                        "grants": [{"src": ["src-host"], "dst": ["dst-host"], "ip": ["tcp:443"]}],
                    },
                    valid=True,
                ),
                Flow(
                    fingerprint="current-pair",
                    source_device_id="source",
                    destination_device_id="target",
                    source="100.64.0.1",
                    destination="100.64.0.2",
                    category="virtual",
                    tx_bytes=10,
                    rx_bytes=5,
                    tx_packets=1,
                    rx_packets=1,
                    start=now - timedelta(minutes=2),
                    end=now - timedelta(minutes=1),
                    logged=now,
                    raw={},
                ),
                Flow(
                    fingerprint="historic-pair",
                    source_device_id="source",
                    destination_device_id="historic",
                    source="100.64.0.1",
                    destination="100.64.0.3",
                    category="virtual",
                    tx_bytes=20,
                    rx_bytes=5,
                    tx_packets=1,
                    rx_packets=1,
                    start=now - timedelta(minutes=2),
                    end=now - timedelta(minutes=1),
                    logged=now,
                    raw={},
                ),
            ]
        )
        await session.commit()
        result = await device_access("source", viewer, session, hours=24)
        states = {item["destination"]["id"]: item["state"] for item in result["items"]}
        assert states["target"] == "both"
        assert states["historic"] == "historical_without_current_allow"
        assert "not labelled a bypass" in result["notice"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_signed_telemetry_is_normalized_resolved_and_filterable() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    viewer = AppUser(username="viewer", password_hash="unused", role="viewer")
    settings = Settings(TAILVIEW_TELEMETRY_SECRET="test-secret")
    async with factory() as session:
        session.add(Device(id="collector", name="collector.example.ts.net"))
        await session.commit()
        payload = {
            "observedAt": datetime.now(UTC).timestamp(),
            "status": {
                "Version": "1.84.0",
                "Self": {"ID": "collector", "TailscaleIPs": ["100.64.0.1"]},
            },
            "netcheck": {
                "UDP": True,
                "IPv4": True,
                "IPv6": False,
                "PreferredDERP": 1,
                "RegionLatency": {"1": 0.01},
            },
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        signature = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        await telemetry(request_for(body, signature), session, settings)

        summary = await telemetry_summary(viewer, session)
        assert summary["counts"] == {"collectors": 1, "fresh": 1, "stale": 0, "unmapped": 0}
        assert summary["collectors"][0]["collector_name"] == "collector.example.ts.net"
        page = await telemetry_observations(
            viewer, session, collector="collector", hours=24, freshness="", cursor=None, limit=50
        )
        assert page["items"][0]["udp"] is True
        assert page["items"][0]["ipv6"] is False

        old_body = json.dumps(
            {"observedAt": (datetime.now(UTC) - timedelta(days=2)).timestamp()}
        ).encode()
        old_signature = hmac.new(b"test-secret", old_body, hashlib.sha256).hexdigest()
        with pytest.raises(HTTPException) as exc:
            await telemetry(request_for(old_body, old_signature), session, settings)
        assert exc.value.status_code == 422
    await engine.dispose()
