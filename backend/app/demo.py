from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    AuditEvent,
    Capability,
    Device,
    DeviceConnectivity,
    DeviceInvite,
    DevicePostureAttribute,
    DevicePostureState,
    DnsConfiguration,
    Finding,
    FindingOccurrence,
    FindingTransition,
    Flow,
    LogStreamingConfiguration,
    PolicySnapshot,
    PostureIntegration,
    ServiceEndpoint,
    ServiceHost,
    TailnetContact,
    TailnetCredential,
    TailnetSecuritySettings,
    TailnetService,
    TailnetUser,
    WebhookEndpoint,
)


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
    await session.flush()
    for demo_device in devices:
        session.add(
            DevicePostureState(
                device_id=demo_device.id,
                status="available" if demo_device.id != "n-phone" else "stale",
                last_success=now - timedelta(hours=8) if demo_device.id == "n-phone" else now,
                checked_at=now,
            )
        )
        session.add_all(
            [
                DevicePostureAttribute(
                    device_id=demo_device.id,
                    key="node:os",
                    namespace="node",
                    value=demo_device.os.casefold(),
                    value_type="string",
                    synced_at=now,
                ),
                DevicePostureAttribute(
                    device_id=demo_device.id,
                    key="node:tsVersion",
                    namespace="node",
                    value=demo_device.version,
                    value_type="string",
                    synced_at=now,
                ),
                DevicePostureAttribute(
                    device_id=demo_device.id,
                    key="node:tsAutoUpdate",
                    namespace="node",
                    value=demo_device.id not in {"n-phone", "n-db"},
                    value_type="boolean",
                    synced_at=now,
                ),
            ]
        )
    session.add(
        DeviceConnectivity(
            device_id="n-laptop",
            mapping_varies_by_dest_ip=False,
            derp="ams",
            endpoints=["192.0.2.10:41641", "10.0.0.22:41641"],
            latency={"ams": 0.012, "fra": 0.021},
            client_supports={"hairPinning": True},
            retrieved_at=now,
        )
    )
    session.add(
        PostureIntegration(
            id="demo-edr",
            name="Demo endpoint security",
            provider="synthetic",
            status="connected",
            synced_at=now,
        )
    )
    session.add(
        TailnetSecuritySettings(
            id="current",
            values={
                "devicesApprovalOn": True,
                "devicesAutoUpdatesOn": True,
                "devicesKeyDurationDays": 180,
                "networkFlowLoggingOn": True,
                "postureIdentityCollectionOn": True,
            },
            synced_at=now,
        )
    )
    demo_findings = [
        Finding(
            id="demo-finding-open",
            fingerprint="demo-finding-open",
            source="posture",
            category="posture_failure",
            severity="high",
            title="Production API fails required posture",
            summary="api-prod fails the current auto-update posture requirement.",
            remediation="Review auto-update state and the affected policy rule.",
            subject_type="device",
            subject_id="n-api",
            subject_display="api-prod.demo.ts.net",
            visibility="viewer",
            evidence={"posture": "posture:updated", "demo": True},
            link_path="/devices?device=n-api",
            status="open",
            first_seen=now - timedelta(hours=3),
            last_seen=now,
            last_evaluated=now,
            occurrence_count=2,
        ),
        Finding(
            id="demo-finding-ack",
            fingerprint="demo-finding-ack",
            source="policy",
            category="lateral_movement",
            severity="medium",
            title="Broad lateral access under review",
            summary="A demo policy rule expands to multiple unrestricted device pairs.",
            remediation="Validate intended access and narrow destinations and ports.",
            subject_type="policy_rule",
            subject_id="demo-policy-rule",
            subject_display='$["grants"][1]',
            visibility="viewer",
            evidence={"demo": True},
            link_path="/policy",
            status="acknowledged",
            first_seen=now - timedelta(days=2),
            last_seen=now,
            last_evaluated=now,
            acknowledged_at=now - timedelta(days=1),
        ),
        Finding(
            id="demo-finding-suppressed",
            fingerprint="demo-finding-suppressed",
            source="sync_health",
            category="repeated_sync_failure",
            severity="medium",
            title="Optional source repeatedly unavailable",
            summary="Synthetic source failure retained for lifecycle demonstration.",
            remediation="Inspect source capability and synchronization history.",
            subject_type="sync_source",
            subject_id="demo-source",
            subject_display="demo_optional_source",
            visibility="viewer",
            evidence={"demo": True},
            link_path="/sync",
            status="suppressed",
            suppression_reason="Planned maintenance",
            suppressed_until=now + timedelta(days=7),
            first_seen=now - timedelta(days=5),
            last_seen=now,
            last_evaluated=now,
        ),
        Finding(
            id="demo-finding-resolved",
            fingerprint="demo-finding-resolved",
            source="device_keys",
            category="credential_expiry",
            severity="medium",
            title="Device key expiry remediated",
            summary="A previously expiring demo device key is no longer reported.",
            remediation="No current action is required.",
            subject_type="device",
            subject_id="n-dev",
            subject_display="carol-dev.demo.ts.net",
            visibility="viewer",
            evidence={"demo": True},
            link_path="/devices?device=n-dev",
            status="resolved",
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(days=10),
            last_evaluated=now,
            resolved_at=now - timedelta(days=9),
        ),
    ]
    session.add_all(demo_findings)
    await session.flush()
    session.add_all(
        [
            FindingOccurrence(
                finding_id="demo-finding-open",
                event_type="reopened",
                severity="high",
                evidence={"demo": True},
                occurred_at=now - timedelta(hours=3),
            ),
            FindingTransition(
                finding_id="demo-finding-open",
                from_status="resolved",
                to_status="open",
                reason="Finding recurred",
                occurred_at=now - timedelta(hours=3),
            ),
        ]
    )
    session.add(
        TailnetService(
            id="svc:api",
            name="svc:api",
            comment="Synthetic production API Service",
            addresses=["100.100.100.10"],
            tags=["tag:prod"],
            ports=["tcp:443"],
            status="connected",
            source="demo",
            raw={"demo": True},
        )
    )
    await session.flush()
    session.add(
        ServiceHost(
            id="svc:api:n-api",
            service_id="svc:api",
            device_id="n-api",
            advertised=True,
            approved=True,
            status="connected",
            raw={"demo": True},
        )
    )
    await session.flush()
    session.add(
        ServiceEndpoint(
            id=hashlib.sha256(b"svc:api:n-api:tcp:443").hexdigest(),
            service_id="svc:api",
            host_id="svc:api:n-api",
            protocol="tcp",
            port=443,
            endpoint_type="tcp",
            raw={"demo": True},
        )
    )
    session.add(
        DnsConfiguration(
            id="current",
            magic_dns=True,
            override_local_dns=False,
            nameservers=["100.100.100.100"],
            search_paths=["demo.ts.net"],
            split_dns={},
            raw={"demo": True},
        )
    )
    session.add(
        WebhookEndpoint(
            id="demo-webhook",
            url_display="https://events.example.test/tailscale",
            subscriptions=["nodeCreated", "nodeDeleted"],
            enabled=True,
            source="demo",
            raw={"demo": True},
        )
    )
    session.add_all(
        [
            TailnetCredential(
                id="tskey-auth-demoCNTRL-000001",
                display_id="tskey-auth-…000001",
                credential_type="auth_key",
                description="Reusable CI enrollment",
                creator_id="u-alice",
                scopes=["auth_keys:read"],
                tags=["tag:server"],
                reusable=True,
                ephemeral=False,
                preapproved=True,
                created_at=now - timedelta(days=50),
                expires_at=now + timedelta(days=10),
                present=True,
                source="demo",
                raw={"demo": True},
            ),
            TailnetCredential(
                id="tskey-api-demoCNTRL-000002",
                display_id="tskey-api-…000002",
                credential_type="api_access_token",
                description="Read-only reporting",
                creator_id="u-alice",
                scopes=["all:read"],
                created_at=now - timedelta(days=20),
                expires_at=now + timedelta(days=60),
                present=True,
                source="demo",
                raw={"demo": True},
            ),
            DeviceInvite(
                id="invite-demo-1",
                device_id="n-api",
                inviter_id="u-alice",
                recipient="contractor@example.test",
                status="pending",
                created_at=now - timedelta(days=20),
                expires_at=now + timedelta(days=2),
                raw={"demo": True},
            ),
            TailnetContact(
                contact_type="security",
                value="security@example.test",
                verified=True,
                raw={"demo": True},
            ),
            LogStreamingConfiguration(
                log_type="configuration",
                enabled=True,
                destination_type="https",
                destination_display="https://siem.example.test/tailscale",
                status="connected",
                raw={"demo": True},
            ),
            LogStreamingConfiguration(
                log_type="network",
                enabled=False,
                destination_type="unknown",
                status="disabled",
                raw={"demo": True},
            ),
        ]
    )
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
      "postures": {"posture:updated": ["node:tsVersion >= '1.84.0'", "node:tsAutoUpdate == true"]},
      "grants": [
        {"src": ["group:engineering"], "dst": ["tag:server"], "ip": ["tcp:443"],
         "srcPosture": ["posture:updated"]},
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
                "postures": {
                    "posture:updated": [
                        "node:tsVersion >= '1.84.0'",
                        "node:tsAutoUpdate == true",
                    ]
                },
                "grants": [
                    {
                        "src": ["group:engineering"],
                        "dst": ["tag:server"],
                        "ip": ["tcp:443"],
                        "srcPosture": ["posture:updated"],
                    },
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
        "services": "all:read (no granular Services scope is documented)",
        "dns": "dns:read",
        "webhooks": "webhooks:read",
        "device_posture": "devices:posture_attributes:read",
        "posture_integrations": "feature_settings:read",
        "tailnet_settings": "feature_settings:read",
        "credential_inventory": "all:read or granular key read scopes",
        "device_invites": "devices_invites:read",
        "tailnet_contacts": "account_settings:read",
        "log_streaming": "log_streaming:read",
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
