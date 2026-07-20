from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditEvent, Capability, Device, Flow, PolicySnapshot, TailnetUser


async def seed_demo(session: AsyncSession) -> None:
    if (await session.scalar(select(func.count()).select_from(Device))) or 0:
        return
    now = datetime.now(UTC)
    users = [
        TailnetUser(
            id="u-alice",
            display_name="Alice Admin",
            login_name="alice@example.com",
            role="admin",
            status="active",
            source="demo",
        ),
        TailnetUser(
            id="u-bob",
            display_name="Bob Builder",
            login_name="bob@example.com",
            role="member",
            status="active",
            source="demo",
        ),
        TailnetUser(
            id="u-carol",
            display_name="Carol Chen",
            login_name="carol@example.com",
            role="member",
            status="active",
            source="demo",
        ),
    ]
    session.add_all(users)
    devices = [
        Device(
            id="n-laptop",
            name="alice-laptop.demo.ts.net",
            hostname="alice-laptop",
            os="macOS",
            version="1.84.0",
            owner_id="u-alice",
            online=True,
            authorized=True,
            last_seen=now,
            created=now - timedelta(days=160),
            addresses=["100.64.0.10", "fd7a:115c:a1e0::10"],
            tags=[],
            roles=["user_workstation"],
            primary_role="user_workstation",
            source="demo",
        ),
        Device(
            id="n-api",
            name="api-prod.demo.ts.net",
            hostname="api-prod",
            os="linux",
            version="1.84.0",
            online=True,
            authorized=True,
            last_seen=now,
            created=now - timedelta(days=300),
            addresses=["100.64.0.20"],
            tags=["tag:prod", "tag:server"],
            roles=["tagged_server", "service_host"],
            primary_role="service_host",
            source="demo",
        ),
        Device(
            id="n-db",
            name="database.demo.ts.net",
            hostname="database",
            os="linux",
            version="1.82.5",
            online=True,
            authorized=True,
            last_seen=now - timedelta(minutes=2),
            created=now - timedelta(days=420),
            addresses=["100.64.0.30"],
            tags=["tag:prod", "tag:database"],
            roles=["tagged_server", "infrastructure_node"],
            primary_role="infrastructure_node",
            source="demo",
        ),
        Device(
            id="n-router",
            name="ams-router.demo.ts.net",
            hostname="ams-router",
            os="linux",
            version="1.84.0",
            online=True,
            authorized=True,
            last_seen=now,
            created=now - timedelta(days=90),
            addresses=["100.64.0.40"],
            tags=["tag:infra"],
            advertised_routes=["10.10.0.0/16", "0.0.0.0/0", "::/0"],
            approved_routes=["10.10.0.0/16", "0.0.0.0/0", "::/0"],
            roles=["exit_node", "subnet_router", "infrastructure_node"],
            primary_role="exit_node",
            source="demo",
        ),
        Device(
            id="n-phone",
            name="bob-phone.demo.ts.net",
            hostname="bob-phone",
            os="iOS",
            version="1.83.2",
            owner_id="u-bob",
            online=False,
            authorized=True,
            last_seen=now - timedelta(hours=7),
            created=now - timedelta(days=45),
            addresses=["100.64.0.50"],
            tags=[],
            roles=["mobile_device"],
            primary_role="mobile_device",
            source="demo",
        ),
        Device(
            id="n-dev",
            name="carol-dev.demo.ts.net",
            hostname="carol-dev",
            os="windows",
            version="1.84.0",
            owner_id="u-carol",
            online=True,
            authorized=True,
            last_seen=now,
            created=now - timedelta(days=14),
            addresses=["100.64.0.60"],
            tags=[],
            roles=["user_workstation"],
            primary_role="user_workstation",
            source="demo",
        ),
    ]
    session.add_all(devices)
    pairs = [
        ("n-laptop", "n-api", 443, 8400000),
        ("n-api", "n-db", 5432, 22000000),
        ("n-dev", "n-api", 443, 4200000),
        ("n-phone", "n-api", 443, 900000),
    ]
    for hour in range(24):
        for src, dst, port, volume in pairs:
            start = now - timedelta(hours=hour, minutes=hour % 7)
            raw = f"{src}:{dst}:{port}:{start.isoformat()}"
            session.add(
                Flow(
                    fingerprint=hashlib.sha256(raw.encode()).hexdigest(),
                    reporting_node_id=src,
                    source_device_id=src,
                    destination_device_id=dst,
                    source=src,
                    destination=dst,
                    protocol=6,
                    destination_port=port,
                    category="virtual",
                    tx_bytes=volume // (hour + 1),
                    rx_bytes=volume // (hour + 2),
                    tx_packets=300,
                    rx_packets=240,
                    start=start,
                    end=start + timedelta(seconds=5),
                    logged=start + timedelta(seconds=8),
                    raw={"demo": True},
                )
            )
    policy_source = """{
      // Demo policy: members can use the API service.
      "groups": {"group:engineering": ["alice@example.com", "carol@example.com"]},
      "grants": [
        {"src": ["group:engineering"], "dst": ["tag:server"], "ip": ["tcp:443"]},
        {"src": ["tag:server"], "dst": ["tag:database"], "ip": ["tcp:5432"]}
      ],
      "ssh": [{"action": "check", "src": ["group:engineering"], "dst": ["tag:server"],
               "users": ["autogroup:nonroot"]}]
    }"""
    session.add(
        PolicySnapshot(
            id=hashlib.sha256(policy_source.encode()).hexdigest(),
            hujson=policy_source,
            normalized={
                "groups": {"group:engineering": ["alice@example.com", "carol@example.com"]},
                "grants": [
                    {"src": ["group:engineering"], "dst": ["tag:server"], "ip": ["tcp:443"]},
                    {"src": ["tag:server"], "dst": ["tag:database"], "ip": ["tcp:5432"]},
                ],
                "ssh": [
                    {
                        "action": "check",
                        "src": ["group:engineering"],
                        "dst": ["tag:server"],
                        "users": ["autogroup:nonroot"],
                    }
                ],
            },
            valid=True,
        )
    )
    session.add(
        AuditEvent(
            id="demo-audit-1",
            event_time=now - timedelta(hours=5),
            action="UPDATE",
            actor={"displayName": "Alice Admin", "loginName": "alice@example.com"},
            target={"type": "POLICY", "name": "Tailnet policy"},
            old=None,
            new={"summary": "Added database access"},
            raw={"demo": True},
        )
    )
    requirements = {
        "device_inventory": "devices:core:read",
        "user_inventory": "users:read",
        "routes": "devices:routes:read",
        "policy": "policy_file:read plus device read scopes",
        "network_flow_logs": "logs:network:read; Premium or Enterprise; logging enabled",
        "configuration_audit_logs": "logs:configuration:read",
        "services": "services:read",
        "dns": "dns:read",
        "webhooks": "webhooks:read",
        "local_telemetry": "optional agent profile and local Tailscale socket",
    }
    for name, requirement in requirements.items():
        session.add(
            Capability(
                name=name,
                status="available" if name != "local_telemetry" else "feature_disabled",
                source="Synthetic demo fixture",
                requirement=requirement,
                detail="Synthetic data; never mixed with real tailnet data",
                last_success=now if name != "local_telemetry" else None,
            )
        )
    await session.commit()
