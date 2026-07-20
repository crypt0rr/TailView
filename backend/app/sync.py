from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db import SessionLocal
from .models import (
    AuditEvent,
    Capability,
    Credential,
    Device,
    Flow,
    PolicySnapshot,
    RawPayload,
    SyncJob,
    TailnetUser,
)
from .policy import parse_policy
from .security import SecretBox
from .tailscale import TailscaleClient, TailscaleError, capability_status


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def redact(value: Any) -> Any:
    sensitive = {"authorization", "token", "secret", "key", "password"}
    if isinstance(value, dict):
        return {
            k: "[REDACTED]" if any(s in k.casefold() for s in sensitive) else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


async def client_for(session: AsyncSession, settings: Settings) -> TailscaleClient | None:
    if not settings.tailscale_tailnet:
        return None
    if settings.tailscale_api_token or settings.tailscale_oauth_client_secret:
        return TailscaleClient(
            settings.tailscale_tailnet,
            settings.tailscale_api_token,
            settings.tailscale_oauth_client_id,
            settings.tailscale_oauth_client_secret,
        )
    credential = await session.scalar(
        select(Credential).order_by(Credential.created_at.desc()).limit(1)
    )
    if not credential or not settings.encryption_key:
        return None
    secret = SecretBox(settings.encryption_key).decrypt(credential.encrypted_secret)
    return TailscaleClient(
        settings.tailscale_tailnet,
        secret if credential.kind == "api_token" else "",
        credential.client_id or "",
        secret if credential.kind == "oauth" else "",
    )


async def lock_job(session: AsyncSession, key: int) -> bool:
    if session.bind and session.bind.dialect.name == "postgresql":
        return bool(await session.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}))
    return True


async def unlock_job(session: AsyncSession, key: int) -> None:
    if session.bind and session.bind.dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})


async def record_payload(session: AsyncSession, source: str, payload: Any) -> None:
    safe = redact(payload)
    canonical = json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(f"{source}:{canonical}".encode()).hexdigest()
    if not await session.get(RawPayload, digest):
        session.add(RawPayload(id=digest, source=source, payload=safe))


def classify(device: dict[str, Any], routes: list[str]) -> tuple[list[str], str]:
    roles: list[str] = []
    if any(r in {"0.0.0.0/0", "::/0"} for r in routes):
        roles.append("exit_node")
    if any(r not in {"0.0.0.0/0", "::/0"} for r in routes):
        roles.append("subnet_router")
    tags = device.get("tags", []) or []
    if tags:
        roles.append("tagged_server")
    os_name = str(device.get("os", "")).casefold()
    if os_name in {"ios", "android"}:
        roles.append("mobile_device")
    elif not tags and device.get("user"):
        roles.append("user_workstation")
    if not roles:
        roles.append("standard_node")
    return roles, roles[0]


async def sync_inventory() -> None:
    settings = get_settings()
    async with SessionLocal() as session:
        if not await lock_job(session, 81001):
            return
        job = SyncJob(kind="inventory", status="running")
        session.add(job)
        await session.commit()
        client = await client_for(session, settings)
        if not client:
            job.status = "skipped"
            job.error = "No Tailscale credentials configured"
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await unlock_job(session, 81001)
            return
        processed = 0
        try:
            users = await client.users()
            await record_payload(session, "users", users)
            for item in users:
                upstream_id = str(item.get("id", item.get("userId", item.get("loginName", ""))))
                if not upstream_id:
                    continue
                user = await session.get(TailnetUser, upstream_id) or TailnetUser(id=upstream_id)
                user.display_name = str(item.get("displayName", item.get("name", "")))
                user.login_name = str(item.get("loginName", item.get("email", "")))
                user.role = str(item.get("role", "member"))
                user.status = str(item.get("status", "unknown"))
                user.raw = redact(item)
                user.synced_at = datetime.now(UTC)
                session.add(user)
            devices = await client.devices()
            await record_payload(session, "devices", devices)
            for item in devices:
                upstream_id = str(item.get("id", item.get("nodeId", "")))
                if not upstream_id:
                    continue
                route_body: dict[str, Any] = {}
                try:
                    route_body = await client.routes(upstream_id)
                except TailscaleError:
                    pass
                advertised = list(
                    route_body.get("advertisedRoutes", item.get("advertisedRoutes", [])) or []
                )
                approved = list(
                    route_body.get(
                        "enabledRoutes",
                        route_body.get("approvedRoutes", item.get("enabledRoutes", [])),
                    )
                    or []
                )
                roles, primary = classify(item, advertised)
                device = await session.get(Device, upstream_id) or Device(
                    id=upstream_id, name=str(item.get("name", upstream_id))
                )
                device.name = str(item.get("name", upstream_id))
                device.hostname = str(item.get("hostname", device.name.split(".")[0]))
                device.os = str(item.get("os", "unknown"))
                device.version = str(item.get("clientVersion", ""))
                device.owner_id = str(item.get("user")) if item.get("user") else None
                device.online = item.get("connectedToControl", item.get("online"))
                device.authorized = item.get("authorized")
                device.last_seen = parse_time(item.get("lastSeen"))
                device.created = parse_time(item.get("created"))
                device.key_expiry = parse_time(item.get("expires"))
                device.addresses = list(item.get("addresses", []))
                device.tags = list(item.get("tags", []))
                device.advertised_routes = advertised
                device.approved_routes = approved
                device.roles = roles
                device.primary_role = primary
                device.raw = redact(item)
                device.synced_at = datetime.now(UTC)
                session.add(device)
                processed += 1
            await session.commit()
            job.status = "success"
            job.processed = processed
            capability = await session.get(Capability, "device_inventory") or Capability(
                name="device_inventory", source="Tailscale device API"
            )
            capability.status = "available"
            capability.requirement = "devices:core:read"
            capability.last_success = datetime.now(UTC)
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        except TailscaleError as exc:
            job.status = "failed"
            job.error = f"Upstream returned HTTP {exc.status}"
            capability = await session.get(Capability, "device_inventory") or Capability(
                name="device_inventory", source="Tailscale device API"
            )
            capability.status = capability_status(exc)
            capability.detail = f"Upstream returned HTTP {exc.status}"
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        finally:
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await client.close()
            await unlock_job(session, 81001)


async def sync_policy() -> None:
    settings = get_settings()
    async with SessionLocal() as session:
        if not await lock_job(session, 81002):
            return
        job = SyncJob(kind="policy", status="running")
        session.add(job)
        await session.commit()
        client = await client_for(session, settings)
        if not client:
            job.status = "skipped"
            job.error = "No Tailscale credentials configured"
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await unlock_job(session, 81002)
            return
        try:
            source = await client.policy()
            parsed = parse_policy(source)
            snapshot = await session.get(PolicySnapshot, parsed.snapshot_id)
            if not snapshot:
                session.add(
                    PolicySnapshot(
                        id=parsed.snapshot_id,
                        hujson=source,
                        normalized=parsed.normalized,
                        valid=True,
                        unsupported=parsed.unsupported,
                    )
                )
            await record_payload(session, "policy", parsed.normalized)
            job.status = "success"
            job.processed = 1
        except (TailscaleError, ValueError) as exc:
            job.status = "failed"
            job.error = type(exc).__name__
        finally:
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await client.close()
            await unlock_job(session, 81002)


def split_endpoint(value: str) -> tuple[str, int | None]:
    if not value:
        return "", None
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit(":", 1)
    elif value.count(":") == 1:
        host, port = value.rsplit(":", 1)
    else:
        return value, None
    return host.strip("[]"), int(port) if port.isdigit() else None


async def sync_logs(kind: str) -> None:
    settings = get_settings()
    key = 81003 if kind == "flows" else 81004
    async with SessionLocal() as session:
        if not await lock_job(session, key):
            return
        job = SyncJob(kind=kind, status="running")
        session.add(job)
        await session.commit()
        client = await client_for(session, settings)
        if not client:
            job.status = "skipped"
            job.error = "No Tailscale credentials configured"
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await unlock_job(session, key)
            return
        end = datetime.now(UTC)
        start = end - timedelta(minutes=11)
        processed = 0
        try:
            logs = await (client.flows(start, end) if kind == "flows" else client.audit(start, end))
            await record_payload(session, kind, logs)
            if kind == "audit":
                for event in logs:
                    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"))
                    eid = hashlib.sha256(canonical.encode()).hexdigest()
                    if await session.get(AuditEvent, eid):
                        continue
                    session.add(
                        AuditEvent(
                            id=eid,
                            event_time=parse_time(event.get("eventTime")) or end,
                            action=str(event.get("action", "UNKNOWN")),
                            actor=event.get("actor", {}),
                            target=event.get("target", {}),
                            old=event.get("old"),
                            new=event.get("new"),
                            raw=redact(event),
                        )
                    )
                    processed += 1
            else:
                for message in logs:
                    for category in ("virtual", "subnet", "exit", "physical"):
                        for count in message.get(f"{category}Traffic", []) or []:
                            canonical = json.dumps(
                                {
                                    "nodeId": message.get("nodeId"),
                                    "logged": message.get("logged"),
                                    "category": category,
                                    "count": count,
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            )
                            fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
                            if await session.scalar(
                                select(Flow.id).where(Flow.fingerprint == fingerprint)
                            ):
                                continue
                            src, src_port = split_endpoint(str(count.get("src", "")))
                            dst, dst_port = split_endpoint(str(count.get("dst", "")))
                            src_device = (
                                await session.scalar(
                                    select(Device.id).where(Device.addresses.contains([src]))
                                )
                                if src
                                else None
                            )
                            dst_device = (
                                await session.scalar(
                                    select(Device.id).where(Device.addresses.contains([dst]))
                                )
                                if dst
                                else None
                            )
                            session.add(
                                Flow(
                                    fingerprint=fingerprint,
                                    reporting_node_id=message.get("nodeId"),
                                    source_device_id=src_device,
                                    destination_device_id=dst_device,
                                    source=src,
                                    destination=dst,
                                    protocol=count.get("proto"),
                                    source_port=src_port,
                                    destination_port=dst_port,
                                    category=category,
                                    tx_bytes=int(count.get("txBytes", 0)),
                                    rx_bytes=int(count.get("rxBytes", 0)),
                                    tx_packets=int(count.get("txPkts", 0)),
                                    rx_packets=int(count.get("rxPkts", 0)),
                                    start=parse_time(message.get("start")) or end,
                                    end=parse_time(message.get("end")) or end,
                                    logged=parse_time(message.get("logged")) or end,
                                    raw=redact(message),
                                )
                            )
                            processed += 1
            job.status = "success"
            job.processed = processed
        except TailscaleError as exc:
            job.status = "failed"
            job.error = f"Upstream returned HTTP {exc.status}"
        finally:
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await client.close()
            await unlock_job(session, key)


def create_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        sync_inventory,
        "interval",
        seconds=settings.inventory_interval_seconds,
        id="inventory",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    scheduler.add_job(
        sync_policy,
        "interval",
        seconds=settings.policy_interval_seconds,
        id="policy",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    scheduler.add_job(
        sync_logs,
        "interval",
        args=["flows"],
        seconds=settings.flow_interval_seconds,
        id="flows",
        max_instances=1,
        coalesce=True,
        jitter=5,
    )
    scheduler.add_job(
        sync_logs,
        "interval",
        args=["audit"],
        seconds=settings.audit_interval_seconds,
        id="audit",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    return scheduler
