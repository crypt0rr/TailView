from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.sync as sync_module
from app.models import Base, Device, ServiceHost, TailnetService, WebhookEndpoint
from app.sync import (
    _devices_worker,
    _routes_worker,
    _services_worker,
    _webhooks_worker,
    build_address_index,
    build_user_login_index,
    classify,
    parse_time,
    preferred_device_id,
    redact,
    redact_webhook_url,
    split_endpoint,
)
from app.tailscale import TailscaleError


def test_classification_is_multi_role_and_deterministic() -> None:
    roles, primary = classify({"tags": ["tag:infra"], "os": "linux"}, ["0.0.0.0/0", "10.0.0.0/8"])
    assert roles == ["exit_node", "subnet_router", "tagged_server"]
    assert primary == "exit_node"


def test_redaction_is_recursive() -> None:
    assert redact({"Authorization": "Bearer x", "nested": {"clientSecret": "x"}, "safe": 1}) == {
        "Authorization": "[REDACTED]",
        "nested": {"clientSecret": "[REDACTED]"},
        "safe": 1,
    }


def test_endpoint_parser_handles_ipv4_ipv6_and_missing_ports() -> None:
    assert split_endpoint("100.64.0.1:443") == ("100.64.0.1", 443)
    assert split_endpoint("[fd7a::1]:53") == ("fd7a::1", 53)
    assert split_endpoint("100.64.0.1") == ("100.64.0.1", None)


def test_rfc3339_time_parser() -> None:
    assert parse_time("2026-07-20T10:00:00Z") == datetime(2026, 7, 20, 10, tzinfo=UTC)
    assert parse_time(None) is None


def test_address_index_matches_exact_addresses_and_omits_ambiguity() -> None:
    index = build_address_index(
        [
            ("node-a", ["100.64.0.1", "fd7a::1"]),
            ("node-b", ["100.64.0.2", "fd7a::1"]),
        ]
    )
    assert index == {"100.64.0.1": "node-a", "100.64.0.2": "node-b"}


def test_inventory_identity_mapping_uses_node_id_and_resolves_login_owner() -> None:
    users = build_user_login_index([("user-123", "Alice@Example.com")])
    device = {"id": "legacy-456", "nodeId": "nABC123CNTRL", "user": "alice@example.com"}

    assert preferred_device_id(device) == "nABC123CNTRL"
    assert users[str(device["user"]).casefold()] == "user-123"


def test_webhook_url_redaction_removes_credentials_query_and_fragment() -> None:
    assert (
        redact_webhook_url("https://user:secret@example.com:8443/hook?token=secret#fragment")
        == "https://example.com:8443/hook"
    )


class FakeInventoryClient:
    async def devices(self) -> list[dict[str, object]]:
        return [
            {
                "nodeId": "disabled-device",
                "name": "disabled.example.ts.net",
                "expires": "2024-01-01T00:00:00Z",
            },
            {
                "nodeId": "unknown-device",
                "name": "unknown.example.ts.net",
                "expires": "2026-08-01T00:00:00Z",
            },
        ]

    async def device(self, device_id: str) -> dict[str, object]:
        if device_id == "disabled-device":
            return {"nodeId": device_id, "keyExpiryDisabled": True}
        return {"nodeId": device_id}

    async def routes(self, device_id: str) -> dict[str, object]:
        if device_id == "failed":
            raise TailscaleError(403, "denied")
        return {"advertisedRoutes": ["10.0.0.0/8"], "enabledRoutes": ["10.0.0.0/8"]}

    async def services(self) -> list[dict[str, object]]:
        return [{"id": "svc:web", "name": "svc:web", "addrs": ["100.100.100.10"]}]

    async def service(self, service_id: str) -> dict[str, object]:
        assert service_id == "svc:web"
        return {"ports": ["tcp:443"], "status": "Connected", "futureField": "retained"}

    async def service_hosts(self, service_id: str) -> list[dict[str, object]]:
        return [
            {
                "nodeId": "successful",
                "advertised": True,
                "approved": True,
                "status": "Connected",
                "endpoints": [{"protocol": "tcp", "port": 443, "type": "layer4"}],
            }
        ]

    async def service_host_approval(self, service_id: str, device_id: str) -> dict[str, object]:
        assert service_id == "svc:web" and device_id == "successful"
        return {"approved": True}

    async def webhooks(self) -> list[dict[str, object]]:
        return [
            {
                "id": "hook-1",
                "url": "https://user:pass@example.com/hook?secret=value",
                "subscriptions": ["nodeCreated"],
                "enabled": True,
            }
        ]


@pytest.mark.asyncio
async def test_devices_normalize_key_expiry_disabled_without_inference() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        result = await _devices_worker(session, FakeInventoryClient())  # type: ignore[arg-type]
        assert result[:3] == (2, 2, 0)
        assert result[3]["detail_succeeded"] == 2
        await session.commit()
        disabled = await session.get(Device, "disabled-device")
        unknown = await session.get(Device, "unknown-device")
        assert disabled and disabled.key_expiry_disabled is True
        assert disabled.key_expiry and disabled.key_expiry.date().isoformat() == "2024-01-01"
        assert unknown and unknown.key_expiry_disabled is None
    await engine.dispose()


@pytest.mark.asyncio
async def test_device_detail_failure_preserves_last_reported_expiry_state() -> None:
    class FailingDetailClient:
        async def devices(self) -> list[dict[str, object]]:
            return [{"nodeId": "server", "name": "server.example.ts.net"}]

        async def device(self, device_id: str) -> dict[str, object]:
            raise TailscaleError(503, "unavailable")

    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        existing = Device(
            id="server",
            name="server.example.ts.net",
            key_expiry_disabled=True,
            addresses=[],
            tags=[],
            advertised_routes=[],
            approved_routes=[],
            roles=["standard_node"],
            primary_role="standard_node",
            raw={},
        )
        session.add(existing)
        await session.commit()

        result = await _devices_worker(session, FailingDetailClient())  # type: ignore[arg-type]
        await session.commit()

        assert result[3]["detail_failure_statuses"] == {"upstream_error": 1}
        assert (await session.get(Device, "server")).key_expiry_disabled is True  # type: ignore[union-attr]
    await engine.dispose()


@pytest.mark.asyncio
async def test_routes_retain_successes_and_report_partial_results() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for device_id in ("successful", "failed"):
            session.add(
                Device(
                    id=device_id,
                    name=device_id,
                    addresses=[],
                    tags=[],
                    advertised_routes=["192.0.2.0/24"],
                    approved_routes=[],
                    roles=["standard_node"],
                    primary_role="standard_node",
                    raw={},
                )
            )
        await session.commit()
        attempted, succeeded, failed, details = await _routes_worker(
            session,
            FakeInventoryClient(),  # type: ignore[arg-type]
        )
        assert (attempted, succeeded, failed) == (2, 1, 1)
        assert details["failure_statuses"] == {"permission_denied": 1}
        assert (await session.get(Device, "successful")).advertised_routes == ["10.0.0.0/8"]  # type: ignore[union-attr]
        assert (await session.get(Device, "failed")).advertised_routes == ["192.0.2.0/24"]  # type: ignore[union-attr]
    await engine.dispose()


@pytest.mark.asyncio
async def test_services_and_webhooks_are_normalized_without_secret_urls() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        client = FakeInventoryClient()
        assert (await _services_worker(session, client))[1:] == (
            1,
            0,
            {"listed": 1, "failure_statuses": {}},
        )  # type: ignore[arg-type]
        assert (await _webhooks_worker(session, client))[:3] == (1, 1, 0)  # type: ignore[arg-type]
        await session.commit()
        service = await session.get(TailnetService, "svc:web")
        assert service and service.status == "connected" and service.ports == ["tcp:443"]
        host = await session.scalar(select(ServiceHost))
        assert host and host.device_id == "successful" and host.approved is True
        webhook = await session.get(WebhookEndpoint, "hook-1")
        assert webhook and webhook.url_display == "https://example.com/hook"
        assert webhook.raw["url"] == "https://example.com/hook"
    await engine.dispose()


@pytest.mark.asyncio
async def test_inventory_orchestrator_continues_after_one_source_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def source(name: str, *, fail: bool = False):  # type: ignore[no-untyped-def]
        async def run() -> None:
            calls.append(name)
            if fail:
                raise RuntimeError("source failed")

        return run

    monkeypatch.setattr(sync_module, "sync_users", source("users", fail=True))
    monkeypatch.setattr(sync_module, "sync_devices", source("devices"))
    monkeypatch.setattr(sync_module, "sync_routes", source("routes"))
    monkeypatch.setattr(sync_module, "sync_services", source("services"))
    monkeypatch.setattr(sync_module, "sync_dns", source("dns"))
    monkeypatch.setattr(sync_module, "sync_webhooks", source("webhooks"))

    await sync_module.sync_inventory()

    assert calls == ["users", "devices", "routes", "services", "dns", "webhooks"]
