from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import capabilities, governance_credentials, security_governance
from app.models import (
    AppUser,
    Base,
    Capability,
    DeviceInvite,
    LogStreamingConfiguration,
    TailnetContact,
    TailnetCredential,
)
from app.sync import _credentials_worker


def admin() -> AppUser:
    return AppUser(username="admin", password_hash="unused", role="administrator")


@pytest.mark.asyncio
async def test_governance_summary_findings_and_masked_inventory() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    async with factory() as session:
        session.add_all(
            [
                TailnetCredential(
                    id="tskey-auth-testCNTRL-123456",
                    display_id="tskey-auth-…123456",
                    credential_type="auth_key",
                    description="CI enrollment",
                    scopes=["auth_keys"],
                    reusable=True,
                    expires_at=now + timedelta(days=5),
                ),
                DeviceInvite(
                    id="invite-1",
                    device_id="node-1",
                    recipient="contractor@example.test",
                    status="pending",
                    created_at=now - timedelta(days=20),
                ),
                TailnetContact(
                    contact_type="security",
                    value="security@example.test",
                    verified=False,
                ),
                LogStreamingConfiguration(
                    log_type="configuration",
                    enabled=True,
                    status="connected",
                ),
            ]
        )
        await session.commit()

        result = await security_governance(admin(), session)
        page = await governance_credentials(
            admin(),
            session,
            cursor=None,
            limit=50,
            credential_type="",
            status_filter="",
            scope="",
            expiry_days=None,
            search="",
        )

        assert result["counts"]["credentials"] == 1
        assert result["counts"]["enabled_streams"] == 1
        assert {finding["kind"] for finding in result["findings"]} == {
            "reusable_auth_key",
            "credential_expiring",
            "write_capable_scope",
            "pending_device_invite",
            "unverified_contact",
        }
        assert page["items"][0]["display_id"] == "tskey-auth-…123456"
        assert page["items"][0]["id"] != "tskey-auth-testCNTRL-123456"
        assert "raw" not in page["items"][0]
    await engine.dispose()


@pytest.mark.asyncio
async def test_governance_navigation_moves_back_when_data_arrives() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for name in (
            "credential_inventory",
            "device_invites",
            "tailnet_contacts",
            "log_streaming",
        ):
            session.add(Capability(name=name, status="available", source="test"))
        await session.commit()
        empty = await capabilities(admin(), session)
        assert empty["navigation"]["/security/governance"]["in_use"] is False

        session.add(
            TailnetCredential(
                id="tskey-api-testCNTRL-1",
                display_id="tskey-api-…NTRL-1",
                credential_type="api_access_token",
            )
        )
        await session.commit()
        populated = await capabilities(admin(), session)
        assert populated["navigation"]["/security/governance"]["in_use"] is True
    await engine.dispose()


class FakeKeysClient:
    async def keys(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "tskey-auth-exampleCNTRL-654321",
                "description": "Provisioning",
                "reusable": True,
                "secret": "must-not-survive",
            }
        ]


class NestedCapabilityKeysClient:
    async def keys(self) -> list[dict[str, Any]]:
        return [
            {
                "id": "tskey-auth-nestedCNTRL-111111",
                "tags": True,
                "scopes": False,
                "reusable": "invalid",
                "secret": "must-not-survive",
                "capabilities": {
                    "devices": {
                        "create": {
                            "tags": ["tag:production"],
                            "reusable": True,
                            "ephemeral": False,
                            "preauthorized": True,
                        }
                    }
                },
            },
            {
                "id": "tskey-auth-topCNTRL-222222",
                "tags": [],
                "scopes": ["auth_keys:read"],
                "reusable": False,
                "ephemeral": True,
                "preApproved": False,
                "capabilities": {
                    "devices": {
                        "create": {
                            "tags": ["tag:must-not-override-empty"],
                            "reusable": True,
                            "ephemeral": False,
                            "preauthorized": True,
                        }
                    }
                },
            },
        ]


@pytest.mark.asyncio
async def test_credential_worker_redacts_raw_secret_values() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _credentials_worker(session, FakeKeysClient())  # type: ignore[arg-type]
        await session.commit()
        row = await session.scalar(select(TailnetCredential))
        assert row is not None
        assert row.display_id.endswith("654321")
        assert str(row.raw["secret"]).startswith("[RED")
    await engine.dispose()


@pytest.mark.asyncio
async def test_credential_worker_normalizes_nested_capabilities_and_malformed_lists() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        result = await _credentials_worker(
            session, NestedCapabilityKeysClient()  # type: ignore[arg-type]
        )
        await session.commit()
        rows = (
            await session.scalars(select(TailnetCredential).order_by(TailnetCredential.id))
        ).all()

        assert result[:3] == (2, 2, 0)
        nested, top_level = rows
        assert nested.tags == ["tag:production"]
        assert nested.scopes == []
        assert nested.reusable is True
        assert nested.ephemeral is False
        assert nested.preapproved is True
        assert str(nested.raw["secret"]).startswith("[RED")
        assert top_level.tags == []
        assert top_level.scopes == ["auth_keys:read"]
        assert top_level.reusable is False
        assert top_level.ephemeral is True
        assert top_level.preapproved is False
    await engine.dispose()
