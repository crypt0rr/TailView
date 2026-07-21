from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from .config import Settings, get_settings
from .db import SessionLocal, engine
from .models import (
    AuditEvent,
    Capability,
    Credential,
    Device,
    DnsConfiguration,
    Flow,
    PolicySnapshot,
    RawPayload,
    ServiceEndpoint,
    ServiceHost,
    SyncJob,
    TailnetService,
    TailnetUser,
    WebhookEndpoint,
)
from .policy import parse_policy
from .security import SecretBox
from .tailscale import TailscaleClient, TailscaleError, capability_status

log = structlog.get_logger()


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


async def lock_job(key: int) -> AsyncConnection | None:
    """Acquire a session advisory lock on a pinned database connection."""
    connection = await engine.connect()
    if connection.dialect.name != "postgresql":
        return connection
    acquired = bool(
        await connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key})
    )
    await connection.commit()
    if not acquired:
        await connection.close()
        return None
    return connection


async def unlock_job(connection: AsyncConnection, key: int) -> None:
    """Release an advisory lock using the same connection that acquired it."""
    try:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            await connection.commit()
    finally:
        await connection.close()


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


def preferred_device_id(device: dict[str, Any]) -> str:
    """Return the stable node ID preferred by the Tailscale API."""
    return str(device.get("nodeId") or device.get("id") or "")


def build_user_login_index(users: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Map normalized login names to their stable upstream user IDs."""
    return {login.casefold(): user_id for user_id, login in users if login}


async def sync_inventory() -> None:
    """Run every inventory source without sharing a transaction or failure boundary."""
    for synchronize in (
        sync_users,
        sync_devices,
        sync_routes,
        sync_services,
        sync_dns,
        sync_webhooks,
    ):
        try:
            await synchronize()
        except Exception:
            log.exception("inventory_source_orchestration_failed", source=synchronize.__name__)


SourceResult = tuple[int, int, int, dict[str, Any]]


class SourceAllFailed(TailscaleError):
    def __init__(self, status: int, attempted: int, details: dict[str, Any]) -> None:
        super().__init__(status, "Every item request failed")
        self.attempted = attempted
        self.details = details


async def _run_source(
    *,
    kind: str,
    lock_key: int,
    capability_name: str,
    capability_source: str,
    requirement: str,
    worker: Any,
) -> None:
    settings = get_settings()
    async with SessionLocal() as session:
        lock = await lock_job(lock_key)
        if lock is None:
            return
        job = SyncJob(kind=kind, status="running")
        session.add(job)
        await session.commit()
        job_id = job.id
        client = await client_for(session, settings)
        if client is None:
            job.status = "skipped"
            job.error = "No Tailscale credentials configured"
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await unlock_job(lock, lock_key)
            return
        try:
            attempted, succeeded, failed, details = await worker(session, client)
            job.attempted = attempted
            job.succeeded = succeeded
            job.failed = failed
            job.processed = succeeded
            job.details = details
            job.status = "partial_success" if failed and succeeded else "success"
            job.partial_success = bool(failed and succeeded)
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = "available"
            capability.requirement = requirement
            capability.detail = (
                "Some items failed; last-good values were retained." if failed else ""
            )
            capability.last_success = datetime.now(UTC)
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
            await session.commit()
        except TailscaleError as exc:
            await session.rollback()
            job = await session.get(SyncJob, job_id) or SyncJob(id=job_id, kind=kind)
            job.status = "failed"
            job.partial_success = False
            if isinstance(exc, SourceAllFailed):
                job.attempted = exc.attempted
                job.failed = exc.attempted
                job.details = exc.details
            else:
                job.failed = max(job.attempted, 1)
            job.error = f"Upstream returned HTTP {exc.status}"
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = capability_status(exc)
            capability.requirement = requirement
            capability.detail = job.error
            capability.checked_at = datetime.now(UTC)
            session.add_all([job, capability])
        except Exception as exc:
            await session.rollback()
            job = await session.get(SyncJob, job_id) or SyncJob(id=job_id, kind=kind)
            job.status = "failed"
            job.partial_success = False
            job.error = f"Ingestion failed ({type(exc).__name__})"
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = "upstream_error"
            capability.requirement = requirement
            capability.detail = job.error
            capability.checked_at = datetime.now(UTC)
            session.add_all([job, capability])
            log.exception("sync_ingestion_failed", kind=kind, error_type=type(exc).__name__)
        finally:
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await client.close()
            await unlock_job(lock, lock_key)


async def _users_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    items = await client.users()
    await record_payload(session, "users", items)
    await session.execute(update(TailnetUser).values(active=False))
    succeeded = 0
    for item in items:
        upstream_id = str(item.get("id") or item.get("userId") or item.get("loginName") or "")
        if not upstream_id:
            continue
        user = await session.get(TailnetUser, upstream_id) or TailnetUser(id=upstream_id)
        user.display_name = str(item.get("displayName") or item.get("name") or "")
        user.login_name = str(item.get("loginName") or item.get("email") or "")
        user.role = str(item.get("role") or "member")
        user.status = str(item.get("status") or "unknown")
        user.active = True
        user.raw = redact(item)
        user.synced_at = datetime.now(UTC)
        session.add(user)
        succeeded += 1
    return len(items), succeeded, 0, {"listed": len(items)}


async def sync_users() -> None:
    await _run_source(
        kind="users",
        lock_key=81101,
        capability_name="user_inventory",
        capability_source="Tailscale user API",
        requirement="users:read",
        worker=_users_worker,
    )


async def _devices_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    items = await client.devices()
    await record_payload(session, "devices", items)
    await session.execute(update(Device).values(active=False))
    rows = (await session.execute(select(TailnetUser.id, TailnetUser.login_name))).all()
    owner_ids = build_user_login_index((row[0], row[1]) for row in rows)
    succeeded = 0
    for item in items:
        upstream_id = preferred_device_id(item)
        if not upstream_id:
            continue
        device = await session.get(Device, upstream_id) or Device(id=upstream_id, name=upstream_id)
        device.name = str(item.get("name") or upstream_id)
        device.hostname = str(item.get("hostname") or device.name.split(".")[0])
        device.os = str(item.get("os") or "unknown")
        device.version = str(item.get("clientVersion") or "")
        device.owner_id = owner_ids.get(str(item.get("user") or "").casefold())
        device.online = item.get("connectedToControl", item.get("online"))
        device.authorized = item.get("authorized")
        device.active = True
        device.last_seen = parse_time(item.get("lastSeen"))
        device.created = parse_time(item.get("created"))
        device.key_expiry = parse_time(item.get("expires"))
        device.addresses = list(item.get("addresses") or [])
        device.tags = list(item.get("tags") or [])
        advertised = list(item.get("advertisedRoutes") or device.advertised_routes or [])
        device.roles, device.primary_role = classify(item, advertised)
        device.raw = redact(item)
        device.synced_at = datetime.now(UTC)
        session.add(device)
        succeeded += 1
    return len(items), succeeded, 0, {"listed": len(items)}


async def sync_devices() -> None:
    await _run_source(
        kind="devices",
        lock_key=81102,
        capability_name="device_inventory",
        capability_source="Tailscale device API",
        requirement="devices:core:read",
        worker=_devices_worker,
    )


async def _routes_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    devices = (await session.scalars(select(Device).where(Device.active.is_(True)))).all()
    semaphore = asyncio.Semaphore(8)

    async def fetch(device: Device) -> tuple[Device, dict[str, Any] | TailscaleError]:
        async with semaphore:
            try:
                return device, await client.routes(device.id)
            except TailscaleError as exc:
                return device, exc

    results = await asyncio.gather(*(fetch(device) for device in devices))
    errors: Counter[str] = Counter()
    succeeded = 0
    for device, result in results:
        if isinstance(result, TailscaleError):
            errors[capability_status(result)] += 1
            continue
        advertised = list(result.get("advertisedRoutes") or [])
        approved = list(result.get("enabledRoutes") or result.get("approvedRoutes") or [])
        device.advertised_routes = advertised
        device.approved_routes = approved
        device.roles, device.primary_role = classify(device.raw, advertised)
        device.synced_at = datetime.now(UTC)
        succeeded += 1
    failed = len(devices) - succeeded
    if devices and succeeded == 0:
        statuses = set(errors)
        status = next(iter(statuses)) if len(statuses) == 1 else "upstream_error"
        status_codes = {
            "permission_denied": 403,
            "unsupported": 404,
            "feature_disabled": 409,
        }
        synthetic = SourceAllFailed(
            status_codes.get(status, 500),
            len(devices),
            {"concurrency": 8, "failure_statuses": dict(errors)},
        )
        raise synthetic
    return len(devices), succeeded, failed, {"concurrency": 8, "failure_statuses": dict(errors)}


async def sync_routes() -> None:
    await _run_source(
        kind="routes",
        lock_key=81103,
        capability_name="routes",
        capability_source="Tailscale device routes API",
        requirement="devices:routes:read",
        worker=_routes_worker,
    )


def _service_identity(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("name") or item.get("serviceName") or "")


def _service_status(item: dict[str, Any]) -> str:
    value = item.get("status", item.get("state"))
    return str(value).casefold().replace(" ", "_") if value else "unknown"


def _endpoint_values(service_id: str, host_id: str | None, values: Any) -> list[ServiceEndpoint]:
    endpoints: list[ServiceEndpoint] = []
    known_fields = {"protocol", "proto", "port", "type"}
    if isinstance(values, dict) and not known_fields.intersection(values):
        values = [
            {
                "protocol": str(key).partition(":")[0],
                "port": str(key).partition(":")[2],
                "type": "configured_mapping",
                "target": target,
            }
            for key, target in values.items()
        ]
    elif isinstance(values, dict):
        values = [values]
    for value in values if isinstance(values, list) else []:
        if isinstance(value, str):
            protocol, _, port_text = value.partition(":")
            raw = {"value": value, "protocol": protocol or "unknown", "port": port_text}
        else:
            raw = value if isinstance(value, dict) else {"value": value}
        protocol = str(raw.get("protocol") or raw.get("proto") or "unknown")
        port_value = raw.get("port")
        port = int(str(port_value)) if str(port_value).isdigit() else None
        digest = hashlib.sha256(
            f"{service_id}:{host_id}:{json.dumps(raw, sort_keys=True)}".encode()
        ).hexdigest()
        endpoints.append(
            ServiceEndpoint(
                id=digest,
                service_id=service_id,
                host_id=host_id,
                protocol=protocol,
                port=port,
                endpoint_type=str(raw.get("type") or "unknown"),
                raw=redact(raw),
            )
        )
    return endpoints


async def _services_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    listed = await client.services()
    await record_payload(session, "services", listed)
    await session.execute(update(TailnetService).values(present=False))
    succeeded = 0
    failures: Counter[str] = Counter()
    for summary in listed:
        service_id = _service_identity(summary)
        if not service_id:
            failures["invalid_response"] += 1
            continue
        detail = summary
        try:
            detail = {**summary, **await client.service(service_id)}
        except TailscaleError as exc:
            failures[f"detail_{capability_status(exc)}"] += 1
        service = await session.get(TailnetService, service_id) or TailnetService(
            id=service_id, name=service_id
        )
        service.name = str(detail.get("name") or detail.get("serviceName") or service_id)
        service.comment = str(detail.get("comment") or detail.get("description") or "")
        service.addresses = list(detail.get("addrs") or detail.get("addresses") or [])
        service.tags = list(detail.get("tags") or [])
        service.ports = [str(value) for value in detail.get("ports", []) or []]
        service.status = _service_status(detail)
        service.present = True
        service.raw = redact(detail)
        service.synced_at = datetime.now(UTC)
        session.add(service)
        await session.flush()
        try:
            hosts = await client.service_hosts(service_id)
            await session.execute(
                delete(ServiceEndpoint).where(ServiceEndpoint.service_id == service_id)
            )
            await session.execute(delete(ServiceHost).where(ServiceHost.service_id == service_id))
            for index, host in enumerate(hosts):
                device_id = (
                    str(host.get("nodeId") or host.get("deviceId") or host.get("id") or "") or None
                )
                host_id = f"{service_id}:{device_id or index}"
                if device_id:
                    try:
                        approval = await client.service_host_approval(service_id, device_id)
                        host = {**host, **approval}
                    except TailscaleError as exc:
                        failures[f"approval_{capability_status(exc)}"] += 1
                row = ServiceHost(
                    id=host_id,
                    service_id=service_id,
                    device_id=device_id,
                    advertised=host.get("advertised"),
                    approved=host.get("approved"),
                    status=_service_status(host),
                    raw=redact(host),
                )
                session.add(row)
                for endpoint in _endpoint_values(service_id, host_id, host.get("endpoints", [])):
                    session.add(endpoint)
        except TailscaleError as exc:
            failures[f"hosts_{capability_status(exc)}"] += 1
        for endpoint in _endpoint_values(service_id, None, detail.get("endpoints", [])):
            session.add(endpoint)
        for endpoint in _endpoint_values(service_id, None, detail.get("ports", [])):
            session.add(endpoint)
        succeeded += 1
    return (
        len(listed),
        succeeded,
        sum(failures.values()),
        {"listed": len(listed), "failure_statuses": dict(failures)},
    )


async def sync_services() -> None:
    await _run_source(
        kind="services",
        lock_key=81104,
        capability_name="services",
        capability_source="Tailscale Services API",
        requirement="all:read (no granular Services scope is documented)",
        worker=_services_worker,
    )


async def _dns_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    item = await client.dns()
    await record_payload(session, "dns", item)
    preferences = item.get("preferences", {})
    row = await session.get(DnsConfiguration, "current") or DnsConfiguration(id="current")
    row.magic_dns = preferences.get("magicDNS", preferences.get("magicDns"))
    row.override_local_dns = preferences.get("overrideLocalDNS")
    nameservers = item.get("nameservers", {})
    if isinstance(nameservers, dict):
        nameserver_values = nameservers.get("dns", nameservers.get("nameservers", []))
    else:
        nameserver_values = nameservers if isinstance(nameservers, list) else []
    row.nameservers = list(nameserver_values or [])
    paths = item.get("searchPaths", {})
    if isinstance(paths, dict):
        path_values = paths.get("searchPaths", [])
    else:
        path_values = paths if isinstance(paths, list) else []
    row.search_paths = list(path_values or [])
    split = item.get("splitDNS", {})
    row.split_dns = dict(split if isinstance(split, dict) else {})
    row.raw = redact(item)
    row.synced_at = datetime.now(UTC)
    session.add(row)
    return 1, 1, 0, {}


async def sync_dns() -> None:
    await _run_source(
        kind="dns",
        lock_key=81105,
        capability_name="dns",
        capability_source="Tailscale DNS API",
        requirement="dns:read",
        worker=_dns_worker,
    )


def redact_webhook_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except ValueError:
        return "[invalid URL]"


async def _webhooks_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    items = await client.webhooks()
    await session.execute(update(WebhookEndpoint).values(present=False))
    safe_items: list[dict[str, Any]] = []
    succeeded = 0
    for item in items:
        endpoint_id = str(item.get("id") or item.get("endpointId") or "")
        if not endpoint_id:
            continue
        safe = redact(item)
        url = str(item.get("url") or item.get("endpoint") or "")
        display = redact_webhook_url(url)
        for key in ("url", "endpoint"):
            if key in safe:
                safe[key] = display
        row = await session.get(WebhookEndpoint, endpoint_id) or WebhookEndpoint(id=endpoint_id)
        row.url_display = display
        row.subscriptions = [
            str(value) for value in item.get("subscriptions", item.get("events", [])) or []
        ]
        row.enabled = item.get("enabled")
        row.present = True
        row.raw = safe
        row.synced_at = datetime.now(UTC)
        session.add(row)
        safe_items.append(safe)
        succeeded += 1
    await record_payload(session, "webhooks", safe_items)
    return len(items), succeeded, 0, {"listed": len(items)}


async def sync_webhooks() -> None:
    await _run_source(
        kind="webhooks",
        lock_key=81106,
        capability_name="webhooks",
        capability_source="Tailscale webhooks API",
        requirement="webhooks:read",
        worker=_webhooks_worker,
    )


async def sync_policy() -> None:
    settings = get_settings()
    async with SessionLocal() as session:
        lock = await lock_job(81002)
        if lock is None:
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
            await unlock_job(lock, 81002)
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
            await unlock_job(lock, 81002)


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


def build_address_index(rows: Iterable[tuple[str, list[str]]]) -> dict[str, str]:
    """Map unambiguous synchronized addresses to device IDs.

    Duplicate addresses are deliberately omitted rather than guessed.
    """
    index: dict[str, str] = {}
    ambiguous: set[str] = set()
    for device_id, addresses in rows:
        for address in addresses:
            if address in index and index[address] != device_id:
                ambiguous.add(address)
            else:
                index[address] = device_id
    for address in ambiguous:
        index.pop(address, None)
    return index


async def sync_logs(kind: str) -> None:
    settings = get_settings()
    key = 81003 if kind == "flows" else 81004
    async with SessionLocal() as session:
        lock = await lock_job(key)
        if lock is None:
            return
        job = SyncJob(kind=kind, status="running")
        session.add(job)
        await session.commit()
        job_id = job.id
        client = await client_for(session, settings)
        if not client:
            job.status = "skipped"
            job.error = "No Tailscale credentials configured"
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await unlock_job(lock, key)
            return
        end = datetime.now(UTC)
        start = end - timedelta(minutes=11)
        processed = 0
        capability_name = "network_flow_logs" if kind == "flows" else "configuration_audit_logs"
        capability_source = (
            "Tailscale network flow logs"
            if kind == "flows"
            else "Tailscale configuration audit logs"
        )
        capability_requirement = (
            "logs:network:read; eligible plan and logging enabled"
            if kind == "flows"
            else "logs:configuration:read"
        )
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
                device_rows = (await session.execute(select(Device.id, Device.addresses))).all()
                address_index = build_address_index(
                    (device_id, addresses) for device_id, addresses in device_rows
                )
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
                            src_device = address_index.get(src)
                            dst_device = address_index.get(dst)
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
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = "available"
            capability.requirement = capability_requirement
            capability.detail = ""
            capability.last_success = datetime.now(UTC)
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        except TailscaleError as exc:
            job.status = "failed"
            job.error = f"Upstream returned HTTP {exc.status}"
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = capability_status(exc)
            capability.requirement = capability_requirement
            capability.detail = f"Upstream returned HTTP {exc.status}"
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        except Exception as exc:
            await session.rollback()
            persisted_job = await session.get(SyncJob, job_id)
            if persisted_job is None:
                persisted_job = SyncJob(id=job_id, kind=kind, status="failed")
                session.add(persisted_job)
            job = persisted_job
            job.status = "failed"
            job.error = f"Ingestion failed ({type(exc).__name__})"
            capability = await session.get(Capability, capability_name) or Capability(
                name=capability_name, source=capability_source
            )
            capability.status = "upstream_error"
            capability.requirement = capability_requirement
            capability.detail = f"Ingestion failed ({type(exc).__name__})"
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
            log.exception("sync_ingestion_failed", kind=kind, error_type=type(exc).__name__)
        finally:
            job.finished_at = datetime.now(UTC)
            await session.commit()
            await client.close()
            await unlock_job(lock, key)


def create_scheduler() -> AsyncIOScheduler:
    settings = get_settings()
    scheduler = AsyncIOScheduler(timezone="UTC")
    for source in (sync_users, sync_devices, sync_routes, sync_services, sync_dns, sync_webhooks):
        scheduler.add_job(
            source,
            "interval",
            seconds=settings.inventory_interval_seconds,
            id=source.__name__.removeprefix("sync_"),
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
