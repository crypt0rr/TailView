from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import dns_settings
from app.models import AppUser, Base, Capability, DnsConfiguration


@pytest.mark.asyncio
async def test_dns_settings_returns_complete_normalized_snapshot_and_provenance() -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(UTC)
    async with factory() as session:
        session.add_all(
            [
                DnsConfiguration(
                    id="current",
                    magic_dns=True,
                    override_local_dns=False,
                    nameservers=["1.1.1.1", {"address": "100.64.0.53"}],
                    search_paths=["example.internal"],
                    split_dns={"routes": {"example.internal": ["100.64.0.53"]}},
                    raw={},
                    synced_at=now,
                ),
                Capability(
                    name="dns",
                    status="available",
                    source="Tailscale DNS API",
                    requirement="dns:read",
                    detail="",
                    last_success=now,
                    checked_at=now,
                ),
            ]
        )
        await session.commit()

        result = await dns_settings(
            AppUser(username="admin", password_hash="unused", role="administrator"),
            session,
        )

        assert result["available"] is True
        assert result["magic_dns"] is True
        assert result["nameservers"][1]["address"] == "100.64.0.53"
        assert result["split_dns"]["routes"]["example.internal"] == ["100.64.0.53"]
        assert result["required_scope"] == "dns:read"
        assert result["source"] == "Tailscale DNS API"
        assert "raw" not in result
    await engine.dispose()
