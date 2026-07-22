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
from .findings import cleanup_findings_job, deliver_notifications_job, evaluate_findings_job
from .models import (
    AuditEvent,
    Capability,
    Credential,
    Device,
    DeviceConnectivity,
    DeviceInvite,
    DevicePostureAttribute,
    DevicePostureState,
    DnsConfiguration,
    Flow,
    LogStreamingConfiguration,
    PolicySnapshot,
    PostureIntegration,
    RawPayload,
    ServiceEndpoint,
    ServiceHost,
    SyncJob,
    TailnetContact,
    TailnetCredential,
    TailnetSecuritySettings,
    TailnetService,
    TailnetUser,
    WebhookEndpoint,
)
from .operations import cleanup_operations_job, instrument_job, scheduler_heartbeat
from .policy import parse_policy
from .reporting import aggregate_flows_job, reporting_cycle
from .security import SecretBox
from .tailscale import TailscaleClient, TailscaleError, capability_status

log = structlog.get_logger()

DEVICE_INVENTORY_DETAIL_FIELDS = {
    "blocksIncomingConnections",
    "isExternal",
    "machineKey",
    "nodeKey",
    "tailnetLockError",
    "tailnetLockKey",
    "updateAvailable",
}


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
        sync_posture,
        sync_routes,
        sync_services,
        sync_dns,
        sync_webhooks,
        sync_posture_integrations,
        sync_tailnet_settings,
        sync_credentials,
        sync_device_invites,
        sync_contacts,
        sync_log_streaming,
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
    semaphore = asyncio.Semaphore(8)

    async def enrich(item: dict[str, Any]) -> tuple[dict[str, Any], bool, str | None]:
        if isinstance(item.get("keyExpiryDisabled"), bool):
            return item, False, None
        upstream_id = preferred_device_id(item)
        if not upstream_id:
            return item, False, "missing_id"
        try:
            async with semaphore:
                details = await client.device(upstream_id)
            return {**item, **details}, True, None
        except TailscaleError as exc:
            return item, True, capability_status(exc)

    enriched = await asyncio.gather(*(enrich(item) for item in items))
    await session.execute(update(Device).values(active=False))
    rows = (await session.execute(select(TailnetUser.id, TailnetUser.login_name))).all()
    owner_ids = build_user_login_index((row[0], row[1]) for row in rows)
    succeeded = 0
    detail_succeeded = 0
    detail_failures: Counter[str] = Counter()
    detail_attempted = 0
    for item, detail_was_attempted, detail_error in enriched:
        detail_attempted += int(detail_was_attempted)
        if detail_error:
            detail_failures[detail_error] += 1
        elif detail_was_attempted:
            detail_succeeded += 1
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
        expiry_disabled = item.get("keyExpiryDisabled")
        if isinstance(expiry_disabled, bool):
            device.key_expiry_disabled = expiry_disabled
        elif detail_error is None:
            device.key_expiry_disabled = None
        device.addresses = list(item.get("addresses") or [])
        device.tags = list(item.get("tags") or [])
        advertised = list(item.get("advertisedRoutes") or device.advertised_routes or [])
        device.roles, device.primary_role = classify(item, advertised)
        device.inventory_details = {
            key: item[key] for key in DEVICE_INVENTORY_DETAIL_FIELDS if key in item
        }
        device.raw = redact(item)
        device.synced_at = datetime.now(UTC)
        session.add(device)
        connectivity = item.get("clientConnectivity")
        if isinstance(connectivity, dict):
            snapshot = await session.get(DeviceConnectivity, upstream_id) or DeviceConnectivity(
                device_id=upstream_id
            )
            snapshot.mapping_varies_by_dest_ip = connectivity.get("mappingVariesByDestIP")
            snapshot.derp = (
                str(connectivity["derp"]) if connectivity.get("derp") is not None else None
            )
            snapshot.endpoints = list(connectivity.get("endpoints") or [])
            latency = connectivity.get("latency")
            snapshot.latency = dict(latency) if isinstance(latency, dict) else {}
            supports = connectivity.get("clientSupports")
            snapshot.client_supports = (
                dict(supports)
                if isinstance(supports, dict)
                else {"features": list(supports)}
                if isinstance(supports, list)
                else {}
            )
            snapshot.retrieved_at = datetime.now(UTC)
            session.add(snapshot)
        else:
            existing_connectivity = await session.get(DeviceConnectivity, upstream_id)
            if existing_connectivity:
                await session.delete(existing_connectivity)
        succeeded += 1
    return (
        len(items),
        succeeded,
        0,
        {
            "listed": len(items),
            "detail_attempted": detail_attempted,
            "detail_succeeded": detail_succeeded,
            "detail_failed": sum(detail_failures.values()),
            "detail_failure_statuses": dict(detail_failures),
        },
    )


async def sync_devices() -> None:
    await _run_source(
        kind="devices",
        lock_key=81102,
        capability_name="device_inventory",
        capability_source="Tailscale device API",
        requirement="devices:core:read",
        worker=_devices_worker,
    )


def _posture_value_type(value: Any) -> str | None:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int | float) and not isinstance(value, bool):
        return "number"
    return None


async def _posture_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    devices = (await session.scalars(select(Device).where(Device.active.is_(True)))).all()
    semaphore = asyncio.Semaphore(8)

    async def fetch(device: Device) -> tuple[Device, dict[str, Any] | TailscaleError]:
        async with semaphore:
            try:
                return device, await client.posture_attributes(device.id)
            except TailscaleError as exc:
                return device, exc

    results = await asyncio.gather(*(fetch(device) for device in devices))
    failures: Counter[str] = Counter()
    unsupported_values = 0
    succeeded = 0
    now = datetime.now(UTC)
    for device, result in results:
        state = await session.get(DevicePostureState, device.id) or DevicePostureState(
            device_id=device.id
        )
        state.checked_at = now
        if isinstance(result, TailscaleError):
            failure_status = capability_status(result)
            failures[failure_status] += 1
            state.status = "stale" if state.last_success else "unknown"
            state.error_status = failure_status
            session.add(state)
            await session.commit()
            continue
        await record_payload(session, f"posture:{device.id}", result)
        attributes = result.get("attributes", {})
        expiries = result.get("expiries", {})
        if not isinstance(attributes, dict):
            attributes = {}
        if not isinstance(expiries, dict):
            expiries = {}
        await session.execute(
            update(DevicePostureAttribute)
            .where(DevicePostureAttribute.device_id == device.id)
            .values(present=False)
        )
        for key, value in attributes.items():
            value_type = _posture_value_type(value)
            if value_type is None:
                unsupported_values += 1
                continue
            attribute_key = str(key)
            row = await session.get(DevicePostureAttribute, (device.id, attribute_key))
            if row is None:
                row = DevicePostureAttribute(
                    device_id=device.id,
                    key=attribute_key,
                    namespace=attribute_key.partition(":")[0] or "unknown",
                    value=value,
                    value_type=value_type,
                )
            row.namespace = attribute_key.partition(":")[0] or "unknown"
            row.value = value
            row.value_type = value_type
            row.expiry = parse_time(expiries.get(attribute_key))
            row.present = True
            row.synced_at = now
            session.add(row)
        state.status = "available"
        state.error_status = None
        state.last_success = now
        session.add(state)
        await session.commit()
        succeeded += 1
    failed = len(devices) - succeeded
    details = {
        "concurrency": 8,
        "failure_statuses": dict(failures),
        "unsupported_attribute_values": unsupported_values,
    }
    if devices and succeeded == 0:
        statuses = set(failures)
        status_value = next(iter(statuses)) if len(statuses) == 1 else "upstream_error"
        status_codes = {"permission_denied": 403, "unsupported": 404, "feature_disabled": 409}
        raise SourceAllFailed(status_codes.get(status_value, 500), len(devices), details)
    return len(devices), succeeded, failed, details


async def sync_posture() -> None:
    await _run_source(
        kind="posture",
        lock_key=81107,
        capability_name="device_posture",
        capability_source="Tailscale device posture attributes API",
        requirement="devices:posture_attributes:read",
        worker=_posture_worker,
    )


SECURITY_SETTING_FIELDS = {
    "devicesApprovalOn",
    "devicesAutoUpdatesOn",
    "devicesKeyDurationDays",
    "usersApprovalOn",
    "usersRoleAllowedToJoinExternalTailnets",
    "networkFlowLoggingOn",
    "regionalRoutingOn",
    "postureIdentityCollectionOn",
}


async def _tailnet_settings_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    item = await client.tailnet_settings()
    await record_payload(session, "tailnet_settings", item)
    row = await session.get(TailnetSecuritySettings, "current") or TailnetSecuritySettings(
        id="current"
    )
    row.values = {key: item[key] for key in SECURITY_SETTING_FIELDS if key in item}
    row.synced_at = datetime.now(UTC)
    session.add(row)
    return 1, 1, 0, {"normalized_fields": len(row.values)}


async def sync_tailnet_settings() -> None:
    await _run_source(
        kind="tailnet_settings",
        lock_key=81108,
        capability_name="tailnet_settings",
        capability_source="Tailscale tailnet settings API",
        requirement="feature_settings:read; all:read recommended",
        worker=_tailnet_settings_worker,
    )


async def _posture_integrations_worker(
    session: AsyncSession, client: TailscaleClient
) -> SourceResult:
    items = await client.posture_integrations()
    await session.execute(update(PostureIntegration).values(present=False))
    failures: Counter[str] = Counter()
    succeeded = 0
    safe_items: list[dict[str, Any]] = []
    for summary in items:
        integration_id = str(summary.get("id") or summary.get("integrationId") or "")
        if not integration_id:
            failures["invalid_response"] += 1
            continue
        item = summary
        try:
            item = {**summary, **await client.posture_integration(integration_id)}
        except TailscaleError as exc:
            failures[f"detail_{capability_status(exc)}"] += 1
        row = await session.get(PostureIntegration, integration_id) or PostureIntegration(
            id=integration_id
        )
        row.name = str(item.get("name") or item.get("displayName") or integration_id)
        row.provider = str(item.get("provider") or item.get("type") or "unknown")
        row.status = str(item.get("status") or item.get("state") or "unknown")
        row.present = True
        row.synced_at = datetime.now(UTC)
        session.add(row)
        safe_items.append(redact(item))
        succeeded += 1
    await record_payload(session, "posture_integrations", safe_items)
    return len(items), succeeded, len(items) - succeeded, {"failure_statuses": dict(failures)}


async def sync_posture_integrations() -> None:
    await _run_source(
        kind="posture_integrations",
        lock_key=81109,
        capability_name="posture_integrations",
        capability_source="Tailscale posture integrations API",
        requirement="feature_settings:read",
        worker=_posture_integrations_worker,
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


def _masked_identifier(value: str) -> str:
    if len(value) <= 10:
        return value
    prefix = value.split("-", 2)[:2]
    label = "-".join(prefix) if len(prefix) == 2 else value[:6]
    return f"{label}-…{value[-6:]}"


def _credential_type(item: dict[str, Any], identifier: str) -> str:
    explicit = str(item.get("type") or item.get("keyType") or item.get("kind") or "")
    if explicit:
        return explicit.casefold().replace(" ", "_")
    prefixes = {
        "tskey-auth-": "auth_key",
        "tskey-api-": "api_access_token",
        "tskey-client-": "oauth_credential",
        "tskey-federated-": "federated_credential",
    }
    return next(
        (kind for prefix, kind in prefixes.items() if identifier.startswith(prefix)),
        "unknown",
    )


async def _credentials_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    items = await client.keys()
    await session.execute(update(TailnetCredential).values(present=False, stale=False))
    safe_items: list[dict[str, Any]] = []
    succeeded = 0
    now = datetime.now(UTC)
    for item in items:
        identifier = str(item.get("id") or item.get("keyId") or item.get("keyID") or "")
        if not identifier:
            continue
        row = await session.get(TailnetCredential, identifier) or TailnetCredential(
            id=identifier, credential_type="unknown"
        )
        row.display_id = _masked_identifier(identifier)
        row.credential_type = _credential_type(item, identifier)
        row.description = str(item.get("description") or item.get("name") or "")
        creator = item.get("creator", item.get("createdBy"))
        row.creator_id = (
            str(creator.get("id") or creator.get("loginName") or "")
            if isinstance(creator, dict)
            else str(creator)
            if creator
            else None
        )
        row.scopes = [str(value) for value in item.get("scopes", []) or []]
        capabilities = item.get("capabilities", {})
        device_caps = capabilities.get("devices", {}) if isinstance(capabilities, dict) else {}
        row.tags = [
            str(value)
            for value in item.get("tags", device_caps.get("create", {}).get("reusable", [])) or []
        ]
        row.reusable = item.get("reusable")
        row.ephemeral = item.get("ephemeral")
        row.preapproved = item.get("preauthorized", item.get("preApproved"))
        row.created_at = parse_time(item.get("created") or item.get("createdAt"))
        row.expires_at = parse_time(item.get("expires") or item.get("expiresAt"))
        row.revoked = item.get("revoked")
        row.present = True
        row.stale = False
        row.raw = redact(item)
        row.synced_at = now
        session.add(row)
        safe_items.append(redact(item))
        succeeded += 1
    await record_payload(session, "credentials", safe_items)
    return len(items), succeeded, 0, {"listed": len(items)}


async def sync_credentials() -> None:
    await _run_source(
        kind="credentials",
        lock_key=81110,
        capability_name="credential_inventory",
        capability_source="Tailscale keys API",
        requirement=(
            "all:read or applicable auth_keys/api_access_tokens/oauth_keys/federated_keys:read"
        ),
        worker=_credentials_worker,
    )


async def _device_invites_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    devices = (await session.scalars(select(Device).where(Device.active.is_(True)))).all()
    await session.execute(update(DeviceInvite).values(stale=True))
    await session.commit()
    semaphore = asyncio.Semaphore(8)

    async def fetch(device: Device) -> tuple[Device, list[dict[str, Any]] | TailscaleError]:
        async with semaphore:
            try:
                return device, await client.device_invites(device.id)
            except TailscaleError as exc:
                return device, exc

    results = await asyncio.gather(*(fetch(device) for device in devices))
    failures: Counter[str] = Counter()
    succeeded = 0
    invite_count = 0
    now = datetime.now(UTC)
    for device, result in results:
        if isinstance(result, TailscaleError):
            failures[capability_status(result)] += 1
            continue
        await session.execute(
            update(DeviceInvite).where(DeviceInvite.device_id == device.id).values(present=False)
        )
        for item in result:
            identifier = str(item.get("id") or item.get("inviteId") or item.get("inviteID") or "")
            if not identifier:
                continue
            row = await session.get(DeviceInvite, identifier) or DeviceInvite(
                id=identifier, device_id=device.id
            )
            inviter = item.get("inviter", item.get("createdBy"))
            recipient = item.get("recipient", item.get("invitee", item.get("email", "")))
            row.device_id = device.id
            row.inviter_id = (
                str(inviter.get("id") or inviter.get("loginName") or "")
                if isinstance(inviter, dict)
                else str(inviter)
                if inviter
                else None
            )
            row.recipient = (
                str(recipient.get("loginName") or recipient.get("email") or "")
                if isinstance(recipient, dict)
                else str(recipient or "")
            )
            row.status = str(item.get("status") or item.get("state") or "pending").casefold()
            row.created_at = parse_time(item.get("created") or item.get("createdAt"))
            row.expires_at = parse_time(item.get("expires") or item.get("expiresAt"))
            row.accepted_at = parse_time(item.get("accepted") or item.get("acceptedAt"))
            row.present = True
            row.stale = False
            row.raw = redact(item)
            row.synced_at = now
            session.add(row)
            invite_count += 1
        await session.commit()
        succeeded += 1
    failed = len(devices) - succeeded
    details = {"concurrency": 8, "invites": invite_count, "failure_statuses": dict(failures)}
    if devices and succeeded == 0:
        statuses = set(failures)
        value = next(iter(statuses)) if len(statuses) == 1 else "upstream_error"
        codes = {"permission_denied": 403, "unsupported": 404, "feature_disabled": 409}
        raise SourceAllFailed(codes.get(value, 500), len(devices), details)
    return len(devices), succeeded, failed, details


async def sync_device_invites() -> None:
    await _run_source(
        kind="device_invites",
        lock_key=81111,
        capability_name="device_invites",
        capability_source="Tailscale device invites API",
        requirement="devices_invites:read or all:read",
        worker=_device_invites_worker,
    )


async def _contacts_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    body = await client.contacts()
    await session.execute(update(TailnetContact).values(present=False, stale=False))
    contacts = body.get("contacts", body)
    if not isinstance(contacts, dict):
        raise TailscaleError(502, "Unexpected tailnet contacts response")
    succeeded = 0
    now = datetime.now(UTC)
    for contact_type, value in contacts.items():
        if contact_type in {"created", "updated"}:
            continue
        item = value if isinstance(value, dict) else {"value": value}
        row = await session.get(TailnetContact, str(contact_type)) or TailnetContact(
            contact_type=str(contact_type)
        )
        row.value = str(item.get("email") or item.get("value") or item.get("name") or "")
        verified = item.get("verified", item.get("isVerified"))
        row.verified = verified if isinstance(verified, bool) else None
        row.present = True
        row.stale = False
        row.raw = redact(item)
        row.synced_at = now
        session.add(row)
        succeeded += 1
    await record_payload(session, "contacts", body)
    return succeeded, succeeded, 0, {"listed": succeeded}


async def sync_contacts() -> None:
    await _run_source(
        kind="contacts",
        lock_key=81112,
        capability_name="tailnet_contacts",
        capability_source="Tailscale tailnet contacts API",
        requirement="account_settings:read or all:read",
        worker=_contacts_worker,
    )


async def _log_streaming_worker(session: AsyncSession, client: TailscaleClient) -> SourceResult:
    log_types = ("configuration", "network", "ssh")
    failures: Counter[str] = Counter()
    succeeded = 0
    now = datetime.now(UTC)
    for log_type in log_types:
        try:
            item = await client.log_streaming(log_type)
        except TailscaleError as exc:
            failures[capability_status(exc)] += 1
            existing = await session.get(LogStreamingConfiguration, log_type)
            if existing:
                existing.stale = True
                session.add(existing)
                await session.commit()
            continue
        configuration = item.get("configuration", {})
        status_body = item.get("status", {})
        destination = str(
            configuration.get("url")
            or configuration.get("endpoint")
            or configuration.get("bucket")
            or configuration.get("destination")
            or ""
        )
        safe_destination = redact_webhook_url(destination) if "://" in destination else destination
        safe_item = redact(item)
        for field in ("url", "endpoint", "destination"):
            if field in safe_item.get("configuration", {}):
                safe_item["configuration"][field] = safe_destination
        row = await session.get(LogStreamingConfiguration, log_type) or LogStreamingConfiguration(
            log_type=log_type
        )
        enabled = status_body.get("enabled", configuration.get("enabled"))
        row.enabled = enabled if isinstance(enabled, bool) else bool(configuration) or None
        row.destination_type = str(
            configuration.get("type") or configuration.get("provider") or "unknown"
        )
        row.destination_display = safe_destination
        row.status = str(status_body.get("status") or status_body.get("state") or "unknown")
        row.stale = False
        row.raw = safe_item
        row.synced_at = now
        session.add(row)
        await record_payload(session, f"log_streaming:{log_type}", safe_item)
        await session.commit()
        succeeded += 1
    failed = len(log_types) - succeeded
    details = {"log_types": list(log_types), "failure_statuses": dict(failures)}
    if succeeded == 0:
        statuses = set(failures)
        value = next(iter(statuses)) if len(statuses) == 1 else "upstream_error"
        codes = {"permission_denied": 403, "unsupported": 404, "feature_disabled": 409}
        raise SourceAllFailed(codes.get(value, 500), len(log_types), details)
    return len(log_types), succeeded, failed, details


async def sync_log_streaming() -> None:
    await _run_source(
        kind="log_streaming",
        lock_key=81113,
        capability_name="log_streaming",
        capability_source="Tailscale log streaming API",
        requirement="log_streaming:read or all:read",
        worker=_log_streaming_worker,
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
            capability = await session.get(Capability, "policy") or Capability(
                name="policy", source="Tailscale policy API"
            )
            capability.status = "available"
            capability.requirement = "policy_file:read"
            capability.detail = "Current policy retrieved successfully"
            capability.last_success = datetime.now(UTC)
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        except TailscaleError as exc:
            job.status = "failed"
            job.error = type(exc).__name__
            capability = await session.get(Capability, "policy") or Capability(
                name="policy", source="Tailscale policy API"
            )
            capability.status = capability_status(exc)
            capability.requirement = "policy_file:read"
            capability.detail = "Policy retrieval is unavailable"
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
        except ValueError as exc:
            job.status = "failed"
            job.error = type(exc).__name__
            capability = await session.get(Capability, "policy") or Capability(
                name="policy", source="Tailscale policy API"
            )
            capability.status = "available"
            capability.requirement = "policy_file:read"
            capability.detail = "Policy retrieved, but local parsing failed"
            capability.last_success = datetime.now(UTC)
            capability.checked_at = datetime.now(UTC)
            session.add(capability)
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
        name = source.__name__.removeprefix("sync_")
        scheduler.add_job(
            instrument_job(name, "synchronization", settings.inventory_interval_seconds, source),
            "interval",
            seconds=settings.inventory_interval_seconds,
            id=name,
            max_instances=1,
            coalesce=True,
            jitter=15,
        )
    scheduler.add_job(
        instrument_job(
            "posture", "synchronization", settings.posture_interval_seconds, sync_posture
        ),
        "interval",
        seconds=settings.posture_interval_seconds,
        id="posture",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    for source in (sync_posture_integrations, sync_tailnet_settings):
        name = source.__name__.removeprefix("sync_")
        scheduler.add_job(
            instrument_job(
                name, "synchronization", settings.security_settings_interval_seconds, source
            ),
            "interval",
            seconds=settings.security_settings_interval_seconds,
            id=name,
            max_instances=1,
            coalesce=True,
            jitter=30,
        )
    for source in (sync_credentials, sync_device_invites, sync_contacts, sync_log_streaming):
        name = source.__name__.removeprefix("sync_")
        scheduler.add_job(
            instrument_job(name, "synchronization", settings.governance_interval_seconds, source),
            "interval",
            seconds=settings.governance_interval_seconds,
            id=name,
            max_instances=1,
            coalesce=True,
            jitter=30,
        )
    scheduler.add_job(
        instrument_job("policy", "synchronization", settings.policy_interval_seconds, sync_policy),
        "interval",
        seconds=settings.policy_interval_seconds,
        id="policy",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    scheduler.add_job(
        instrument_job("flows", "synchronization", settings.flow_interval_seconds, sync_logs),
        "interval",
        args=["flows"],
        seconds=settings.flow_interval_seconds,
        id="flows",
        max_instances=1,
        coalesce=True,
        jitter=5,
    )
    scheduler.add_job(
        instrument_job("audit", "synchronization", settings.audit_interval_seconds, sync_logs),
        "interval",
        args=["audit"],
        seconds=settings.audit_interval_seconds,
        id="audit",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    scheduler.add_job(
        instrument_job(
            "findings", "security", settings.findings_interval_seconds, evaluate_findings_job
        ),
        "interval",
        seconds=settings.findings_interval_seconds,
        id="findings",
        max_instances=1,
        coalesce=True,
        jitter=15,
    )
    scheduler.add_job(
        instrument_job("notification-delivery", "delivery", 30, deliver_notifications_job),
        "interval",
        seconds=30,
        id="notification-delivery",
        max_instances=1,
        coalesce=True,
        jitter=5,
    )
    scheduler.add_job(
        instrument_job("findings-cleanup", "cleanup", 86400, cleanup_findings_job),
        "interval",
        hours=24,
        id="findings-cleanup",
        max_instances=1,
        coalesce=True,
        jitter=300,
    )
    scheduler.add_job(
        instrument_job("flow-aggregates", "aggregation", 300, aggregate_flows_job),
        "interval",
        minutes=5,
        id="flow-aggregates",
        max_instances=1,
        coalesce=True,
        jitter=20,
    )
    scheduler.add_job(
        instrument_job("network-reports", "reporting", 30, reporting_cycle),
        "interval",
        seconds=30,
        id="network-reports",
        max_instances=1,
        coalesce=True,
        jitter=5,
    )
    scheduler.add_job(
        instrument_job("operations-cleanup", "cleanup", 86400, cleanup_operations_job),
        "interval",
        hours=24,
        id="reporting-cleanup",
        max_instances=1,
        coalesce=True,
        jitter=300,
    )
    scheduler.add_job(
        scheduler_heartbeat,
        "interval",
        seconds=30,
        id="scheduler-heartbeat",
        max_instances=1,
        coalesce=True,
    )
    return scheduler
