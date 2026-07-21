from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import auth
from .addresses import (
    PhysicalEndpointObservation,
    aggregate_physical_endpoints,
    tailnet_address_items,
)
from .config import Settings, get_settings
from .db import get_db
from .demo import seed_demo
from .flow_data import (
    FlowFilters,
    apply_flow_filters,
    decode_cursor,
    encode_cursor,
    flow_keyset_condition,
    flow_summary_series,
    validate_flow_filters,
)
from .models import (
    AppUser,
    AuditEvent,
    Capability,
    Credential,
    Device,
    DnsConfiguration,
    Flow,
    LocalMetadata,
    PolicySnapshot,
    ServiceEndpoint,
    ServiceHost,
    SyncJob,
    TailnetService,
    TailnetUser,
    TelemetryObservation,
    WebhookEndpoint,
)
from .policy import evaluate_policy, review_policy, security_review_policy
from .schemas import CredentialRequest, LoginRequest, MetadataUpdate, SetupRequest, UserResponse
from .security import SecretBox
from .sync import (
    sync_devices,
    sync_dns,
    sync_inventory,
    sync_logs,
    sync_policy,
    sync_routes,
    sync_services,
    sync_users,
    sync_webhooks,
)

router = APIRouter(prefix="/api/v1")
Db = Annotated[AsyncSession, Depends(get_db)]
Authed = Annotated[AppUser, Depends(auth.current_user)]
Admin = Annotated[AppUser, Depends(auth.administrator)]
Csrf = Annotated[None, Depends(auth.enforce_csrf)]


def device_dict(
    device: Device,
    metadata: LocalMetadata | None = None,
    owner: TailnetUser | None = None,
) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": metadata.display_name if metadata and metadata.display_name else device.name,
        "source_name": device.name,
        "hostname": device.hostname,
        "os": device.os,
        "version": device.version,
        "owner_id": device.owner_id,
        "owner_display_name": owner.display_name if owner and owner.display_name else None,
        "owner_login_name": owner.login_name if owner and owner.login_name else None,
        "online": device.online,
        "authorized": device.authorized,
        "active": device.active,
        "stale": not device.active,
        "last_seen": device.last_seen,
        "created": device.created,
        "key_expiry": device.key_expiry,
        "key_expiry_disabled": device.key_expiry_disabled,
        "addresses": device.addresses,
        "tags": device.tags,
        "advertised_routes": device.advertised_routes,
        "approved_routes": device.approved_routes,
        "roles": device.roles,
        "primary_role": device.primary_role,
        "source": device.source,
        "metadata": {
            "description": metadata.description,
            "function": metadata.function,
            "environment": metadata.environment,
            "location": metadata.location,
            "criticality": metadata.criticality,
            "icon": metadata.icon,
            "hidden": metadata.hidden,
        }
        if metadata
        else None,
    }


async def device_label_map(db: AsyncSession) -> dict[str, str]:
    rows = (
        await db.execute(
            select(Device.id, Device.name, LocalMetadata.display_name).outerjoin(LocalMetadata)
        )
    ).all()
    return {device_id: display_name or name or device_id for device_id, name, display_name in rows}


async def service_address_map(db: AsyncSession) -> dict[str, tuple[str, str]]:
    """Map only unambiguous, exact official Service addresses."""
    rows = (
        await db.execute(
            select(TailnetService.id, TailnetService.name, TailnetService.addresses).where(
                TailnetService.present.is_(True)
            )
        )
    ).all()
    result: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for service_id, name, addresses in rows:
        for address in addresses:
            if address in result and result[address][0] != service_id:
                ambiguous.add(address)
            else:
                result[address] = (service_id, name)
    for address in ambiguous:
        result.pop(address, None)
    return result


def flow_identity(
    device_id: str | None,
    raw_value: str | None,
    labels: dict[str, str],
    unavailable: str,
) -> dict[str, str | None]:
    return {
        "id": device_id,
        "label": labels.get(device_id, device_id) if device_id else (raw_value or unavailable),
        "raw": raw_value,
    }


def preferred_device_label(
    device_id: str | None, raw_value: str | None, labels: dict[str, str]
) -> str:
    return (labels.get(device_id) if device_id else None) or device_id or raw_value or "Unavailable"


@router.get("/setup/status")
async def get_setup_status(db: Db) -> dict[str, bool]:
    return await auth.setup_status(db)


@router.post("/setup", response_model=UserResponse)
async def setup(
    payload: SetupRequest,
    response: Response,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
) -> UserResponse:
    return await auth.setup_admin(payload, response, db, settings)


@router.post("/auth/login", response_model=UserResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
) -> UserResponse:
    return await auth.login(payload, request, response, db, settings)


@router.get("/auth/me", response_model=UserResponse)
async def me(user: Authed) -> UserResponse:
    return UserResponse(id=user.id, username=user.username, role=user.role)


@router.post("/auth/logout")
async def logout(
    response: Response,
    db: Db,
    session: Annotated[Any, Depends(auth.current_session)],
    _: Csrf,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    await auth.logout(response, session, db, settings)


@router.get("/dashboard")
async def dashboard(
    _: Authed,
    db: Db,
    hours: int = Query(24),
) -> dict[str, Any]:
    filters = validate_flow_filters(FlowFilters(hours=hours))
    now = datetime.now(UTC)
    device_count = (await db.scalar(select(func.count()).select_from(Device))) or 0
    online = (
        await db.scalar(select(func.count()).select_from(Device).where(Device.online.is_(True)))
    ) or 0
    users = (await db.scalar(select(func.count()).select_from(TailnetUser))) or 0
    flows = (await db.scalar(select(func.count()).select_from(Flow))) or 0
    cutoff = now + timedelta(days=14)
    expiring = (
        await db.scalar(
            select(func.count())
            .select_from(Device)
            .where(
                Device.key_expiry_disabled.is_(False),
                Device.key_expiry.is_not(None),
                Device.key_expiry >= now,
                Device.key_expiry <= cutoff,
            )
        )
    ) or 0
    roles = (
        await db.execute(select(Device.primary_role, func.count()).group_by(Device.primary_role))
    ).all()
    os_rows = (await db.execute(select(Device.os, func.count()).group_by(Device.os))).all()
    top_pairs_query = select(
        Flow.source_device_id,
        Flow.destination_device_id,
        func.sum(Flow.tx_bytes + Flow.rx_bytes).label("bytes"),
    ).group_by(Flow.source_device_id, Flow.destination_device_id)
    top_pairs_query = apply_flow_filters(top_pairs_query, filters, now)
    top_pairs = (await db.execute(top_pairs_query.order_by(desc("bytes")).limit(5))).all()
    traffic_series = await flow_summary_series(db, filters, now=now)
    labels = await device_label_map(db)
    return {
        "devices": device_count,
        "online": online,
        "offline": device_count - online,
        "users": users,
        "flow_records": flows,
        "expiring_keys": expiring,
        "roles": [{"name": n, "value": c} for n, c in roles],
        "operating_systems": [{"name": n, "value": c} for n, c in os_rows],
        "top_pairs": [
            {
                "source": labels.get(s, s or "Unresolved source"),
                "source_device_id": s,
                "destination": labels.get(d, d or "Unresolved destination"),
                "destination_device_id": d,
                "reported_bytes": b or 0,
            }
            for s, d, b in top_pairs
        ],
        "traffic_series": traffic_series,
        "range_hours": hours,
        "generated_at": now,
        "traffic_label": "Reported bytes; peer reports may overlap",
    }


def _device_query(
    search: str,
    role: str,
    status_filter: str,
    owner: str,
    key_expiry: str = "",
) -> tuple[Any, Any]:
    sort_key = func.lower(func.coalesce(LocalMetadata.display_name, Device.name, Device.id))
    query = (
        select(Device, LocalMetadata, TailnetUser, sort_key.label("sort_key"))
        .outerjoin(LocalMetadata)
        .outerjoin(TailnetUser, Device.owner_id == TailnetUser.id)
        .order_by(sort_key, Device.id)
    )
    if search:
        query = query.where(
            or_(
                Device.name.ilike(f"%{search}%"),
                Device.hostname.ilike(f"%{search}%"),
                Device.os.ilike(f"%{search}%"),
                TailnetUser.display_name.ilike(f"%{search}%"),
                TailnetUser.login_name.ilike(f"%{search}%"),
            )
        )
    if role:
        query = query.where(Device.primary_role == role)
    if status_filter:
        if status_filter not in {"online", "offline", "unknown"}:
            raise HTTPException(422, "status must be online, offline, or unknown")
        if status_filter == "unknown":
            query = query.where(Device.online.is_(None))
        else:
            query = query.where(Device.online.is_(status_filter == "online"))
    if owner:
        owner_pattern = f"%{owner}%"
        query = query.where(
            or_(
                Device.owner_id == owner,
                TailnetUser.display_name.ilike(owner_pattern),
                TailnetUser.login_name.ilike(owner_pattern),
            )
        )
    if key_expiry:
        allowed_key_expiry = {
            "within_14_days",
            "expired",
            "valid",
            "disabled",
            "not_reported",
        }
        if key_expiry not in allowed_key_expiry:
            raise HTTPException(
                422,
                "key_expiry must be within_14_days, expired, valid, disabled, or not_reported",
            )
        now = datetime.now(UTC)
        cutoff = now + timedelta(days=14)
        if key_expiry == "within_14_days":
            query = query.where(
                Device.key_expiry_disabled.is_(False),
                Device.key_expiry.is_not(None),
                Device.key_expiry >= now,
                Device.key_expiry <= cutoff,
            )
        elif key_expiry == "expired":
            query = query.where(
                Device.key_expiry_disabled.is_(False),
                Device.key_expiry.is_not(None),
                Device.key_expiry < now,
            )
        elif key_expiry == "valid":
            query = query.where(
                Device.key_expiry_disabled.is_(False),
                Device.key_expiry.is_not(None),
                Device.key_expiry > cutoff,
            )
        elif key_expiry == "disabled":
            query = query.where(Device.key_expiry_disabled.is_(True))
        else:
            query = query.where(
                or_(Device.key_expiry_disabled.is_(None), Device.key_expiry.is_(None))
            )
    return query, sort_key


@router.get("/devices")
async def devices(
    _: Authed,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    search: str = "",
    role: str = "",
    status_filter: str = Query("", alias="status"),
    owner: str = "",
    key_expiry: str = "",
) -> dict[str, Any]:
    cursor_data = decode_cursor(cursor, "devices")
    query, sort_key = _device_query(search, role, status_filter, owner, key_expiry)
    if cursor_data:
        try:
            cursor_name = str(cursor_data["name"])
            cursor_id = str(cursor_data["id"])
        except KeyError as exc:
            raise HTTPException(400, "Invalid cursor") from exc
        query = query.where(
            or_(sort_key > cursor_name, and_(sort_key == cursor_name, Device.id > cursor_id))
        )
    rows = (await db.execute(query.limit(limit + 1))).all()
    page_rows = rows[:limit]
    next_cursor = None
    if len(rows) > limit and page_rows:
        last_device, _, _, last_sort_key = page_rows[-1]
        next_cursor = encode_cursor("devices", {"name": str(last_sort_key), "id": last_device.id})
    return {
        "items": [device_dict(d, m, item_owner) for d, m, item_owner, _ in page_rows],
        "next_cursor": next_cursor,
    }


@router.get("/devices/export.csv")
async def export_devices(
    _: Authed,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
    search: str = "",
    role: str = "",
    status_filter: str = Query("", alias="status"),
    owner: str = "",
    key_expiry: str = "",
) -> StreamingResponse:
    query, _ = _device_query(search, role, status_filter, owner, key_expiry)
    probe_query = query.with_only_columns(Device.id).limit(settings.export_row_limit + 1)
    probe = (await db.execute(probe_query)).all()
    truncated = len(probe) > settings.export_row_limit

    async def rows() -> AsyncIterator[str]:
        columns = [
            "name",
            "source_name",
            "hostname",
            "status",
            "primary_role",
            "owner",
            "owner_id",
            "os",
            "version",
            "addresses",
            "key_expiry",
            "key_expiry_disabled",
            "last_seen",
            "source",
        ]
        yield _csv_line(columns)
        stream = await db.stream(
            query.limit(settings.export_row_limit).execution_options(yield_per=500)
        )
        async for device_row, metadata, item_owner, _ in stream:
            item = device_dict(device_row, metadata, item_owner)
            values = {
                **item,
                "status": (
                    "online"
                    if item["online"] is True
                    else "offline"
                    if item["online"] is False
                    else "unknown"
                ),
                "owner": item["owner_display_name"] or item["owner_login_name"] or "",
                "addresses": ";".join(item["addresses"]),
                "key_expiry": item["key_expiry"].isoformat() if item["key_expiry"] else "",
                "key_expiry_disabled": (
                    item["key_expiry_disabled"]
                    if item["key_expiry_disabled"] is not None
                    else "not_reported"
                ),
                "last_seen": item["last_seen"].isoformat() if item["last_seen"] else "",
            }
            yield _csv_line([values.get(column, "") for column in columns])

    return StreamingResponse(
        rows(),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=tailview-devices.csv",
            "X-TailView-Export-Limit": str(settings.export_row_limit),
            "X-TailView-Export-Truncated": str(truncated).lower(),
        },
    )


@router.get("/devices/{device_id}")
async def device(
    device_id: str,
    _: Authed,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
    address_hours: int = Query(168),
) -> dict[str, Any]:
    if address_hours not in {24, 168, 720}:
        raise HTTPException(422, "address_hours must be one of 24, 168, or 720")
    row = (
        await db.execute(
            select(Device, LocalMetadata, TailnetUser)
            .outerjoin(LocalMetadata)
            .outerjoin(TailnetUser, Device.owner_id == TailnetUser.id)
            .where(Device.id == device_id)
        )
    ).first()
    if not row:
        raise HTTPException(404, "Device not found")
    item = device_dict(row[0], row[1], row[2])
    flows = (
        (
            await db.execute(
                select(Flow)
                .where(
                    or_(Flow.source_device_id == device_id, Flow.destination_device_id == device_id)
                )
                .order_by(Flow.start.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    labels = await device_label_map(db)
    item["flows"] = []
    for f in flows:
        source = flow_identity(f.source_device_id, f.source, labels, "Unresolved source")
        destination = flow_identity(
            f.destination_device_id, f.destination, labels, "Destination not logged"
        )
        item["flows"].append(
            {
                "id": f.id,
                "source": source["label"],
                "source_device_id": source["id"],
                "source_raw": source["raw"],
                "destination": destination["label"],
                "destination_device_id": destination["id"],
                "destination_raw": destination["raw"],
                "category": f.category,
                "protocol": f.protocol,
                "destination_port": f.destination_port,
                "reported_bytes": f.tx_bytes + f.rx_bytes,
                "start": f.start,
                "end": f.end,
                "provenance": "demo" if f.raw.get("demo") else "network_flow_logs",
            }
        )
    endpoint_rows = (
        await db.execute(
            select(
                Flow.destination,
                Flow.destination_port,
                Flow.start,
                Flow.end,
                Flow.reporting_node_id,
                (Flow.tx_bytes + Flow.rx_bytes).label("reported_bytes"),
            )
            .where(
                Flow.source_device_id == device_id,
                Flow.category == "physical",
                Flow.end >= datetime.now(UTC) - timedelta(hours=address_hours),
                Flow.destination != "",
            )
            .order_by(Flow.end.desc())
            .limit(20001)
        )
    ).all()
    truncated = len(endpoint_rows) > 20000
    observations = [
        PhysicalEndpointObservation(
            address=address,
            port=port,
            start=start,
            end=end,
            reporting_node_id=reporter,
            reported_bytes=reported_bytes or 0,
        )
        for address, port, start, end, reporter, reported_bytes in endpoint_rows[:20000]
    ]
    observed = aggregate_physical_endpoints(observations, labels)
    capability = await db.get(Capability, "network_flow_logs")
    latest_flow_job = await db.scalar(
        select(SyncJob).where(SyncJob.kind == "flows").order_by(SyncJob.started_at.desc()).limit(1)
    )
    capability_status_value = (
        capability.status
        if capability
        else "available"
        if observed or (latest_flow_job and latest_flow_job.status == "success")
        else "unknown"
    )
    retention_limited = address_hours > settings.flow_retention_days * 24
    if observed:
        address_status = "available"
    elif capability_status_value not in {"available", "unknown"}:
        address_status = "capability_unavailable"
    elif retention_limited:
        address_status = "retention_limited"
    else:
        address_status = "no_observations"
    item["address_inventory"] = {
        "tailnet": tailnet_address_items(item["addresses"]),
        "observed": observed,
        "status": address_status,
        "capability_status": capability_status_value,
        "requested_hours": address_hours,
        "retention_days": settings.flow_retention_days,
        "truncated": truncated,
        "notice": (
            "Observed physical endpoints are client-reported candidates from historical flow "
            "windows. They can represent NAT mappings, relays, or spoofed values and are not "
            "authoritative device interface addresses."
        ),
    }
    return item


@router.put("/devices/{device_id}/metadata")
async def update_metadata(
    device_id: str, payload: MetadataUpdate, _: Admin, __: Csrf, db: Db
) -> dict[str, str]:
    if not await db.get(Device, device_id):
        raise HTTPException(404, "Device not found")
    metadata = await db.get(LocalMetadata, device_id) or LocalMetadata(device_id=device_id)
    for key, value in payload.model_dump().items():
        setattr(metadata, key, value)
    db.add(metadata)
    await db.commit()
    return {"status": "updated"}


@router.get("/users")
async def users(_: Authed, db: Db) -> dict[str, Any]:
    rows = (
        (await db.execute(select(TailnetUser).order_by(TailnetUser.display_name))).scalars().all()
    )
    count_rows = (
        await db.execute(select(Device.owner_id, func.count()).group_by(Device.owner_id))
    ).all()
    counts: dict[str | None, int] = {owner_id: count for owner_id, count in count_rows}
    return {
        "items": [
            {
                "id": u.id,
                "display_name": u.display_name,
                "login_name": u.login_name,
                "role": u.role,
                "status": u.status,
                "active": u.active,
                "stale": not u.active,
                "device_count": counts.get(u.id, 0),
                "source": u.source,
            }
            for u in rows
        ],
        "next_cursor": None,
    }


@router.get("/groups")
async def groups(_: Authed, db: Db) -> dict[str, Any]:
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    values = snapshot.normalized.get("groups", {}) if snapshot else {}
    return {
        "items": [
            {
                "name": name,
                "members": members,
                "member_count": len(members),
                "source": "tailnet_policy",
            }
            for name, members in values.items()
        ],
        "next_cursor": None,
    }


@router.get("/routes")
async def routes(_: Authed, db: Db) -> dict[str, Any]:
    rows = (await db.execute(select(Device))).scalars().all()
    items = [
        {
            "id": f"{device.id}:{route}",
            "route": route,
            "device_id": device.id,
            "device": device.name,
            "advertised": True,
            "approved": route in device.approved_routes,
            "route_type": "exit" if route in {"0.0.0.0/0", "::/0"} else "subnet",
            "source": device.source,
        }
        for device in rows
        for route in device.advertised_routes
    ]
    return {"items": items, "next_cursor": None}


@router.get("/tags")
async def tags(_: Authed, db: Db) -> dict[str, Any]:
    rows = (await db.execute(select(Device))).scalars().all()
    counts: dict[str, int] = {}
    for device in rows:
        for tag in device.tags:
            counts[str(tag)] = counts.get(str(tag), 0) + 1
    return {
        "items": [
            {"name": tag, "device_count": count, "source": "tailscale_device_api_or_demo"}
            for tag, count in sorted(counts.items())
        ],
        "next_cursor": None,
    }


@router.get("/services")
async def services(
    _: Authed,
    db: Db,
    search: str = "",
    status_filter: str = Query("", alias="status"),
    host: str = "",
    cursor: str | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    query = select(TailnetService).where(TailnetService.present.is_(True))
    if search:
        query = query.where(
            or_(TailnetService.name.ilike(f"%{search}%"), TailnetService.id.ilike(f"%{search}%"))
        )
    if status_filter:
        query = query.where(TailnetService.status == status_filter)
    if host:
        host_pattern = f"%{host}%"
        matching_hosts = (
            select(ServiceHost.service_id)
            .outerjoin(Device, ServiceHost.device_id == Device.id)
            .where(
                or_(
                    ServiceHost.device_id == host,
                    Device.name.ilike(host_pattern),
                    Device.hostname.ilike(host_pattern),
                )
            )
        )
        query = query.where(TailnetService.id.in_(matching_hosts))
    decoded = decode_cursor(cursor, "services")
    if decoded:
        name, service_id = str(decoded.get("name", "")), str(decoded.get("id", ""))
        query = query.where(
            or_(
                func.lower(TailnetService.name) > name,
                and_(func.lower(TailnetService.name) == name, TailnetService.id > service_id),
            )
        )
    rows = (
        await db.scalars(
            query.order_by(func.lower(TailnetService.name), TailnetService.id).limit(limit + 1)
        )
    ).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    host_count_rows = (
        await db.execute(
            select(ServiceHost.service_id, func.count()).group_by(ServiceHost.service_id)
        )
    ).all()
    host_counts: dict[str, int] = {row[0]: row[1] for row in host_count_rows}
    service_capability = await db.get(Capability, "services")
    snapshot_stale = bool(service_capability and service_capability.status != "available")
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    policy_names: set[str] = set()
    if snapshot:
        for rule in snapshot.normalized.get("grants", []):
            policy_names.update(
                str(value) for value in rule.get("dst", []) if str(value).startswith("svc:")
            )
    real_names = {row.id for row in rows} | {row.name for row in rows}
    items = [
        {
            "id": row.id,
            "name": row.name,
            "comment": row.comment,
            "status": row.status,
            "addresses": row.addresses,
            "tags": row.tags,
            "ports": row.ports,
            "host_count": host_counts.get(row.id, 0),
            "source": row.source,
            "synced_at": row.synced_at,
            "stale": snapshot_stale,
        }
        for row in rows
    ]
    if not cursor and not search and not status_filter and not host:
        items.extend(
            {
                "id": name,
                "name": name,
                "status": "policy_reference_only",
                "addresses": [],
                "tags": [],
                "ports": [],
                "host_count": 0,
                "source": "tailnet_policy",
                "stale": True,
            }
            for name in sorted(policy_names - real_names)
        )
    next_cursor = (
        encode_cursor("services", {"name": rows[-1].name.casefold(), "id": rows[-1].id})
        if has_more and rows
        else None
    )
    return {"items": items, "next_cursor": next_cursor}


@router.get("/services/{service_id}")
async def service_detail(service_id: str, _: Authed, db: Db) -> dict[str, Any]:
    service = await db.get(TailnetService, service_id)
    capability = await db.get(Capability, "services")
    if service is None:
        raise HTTPException(404, "Service not found")
    hosts = (
        await db.scalars(select(ServiceHost).where(ServiceHost.service_id == service_id))
    ).all()
    endpoints = (
        await db.scalars(select(ServiceEndpoint).where(ServiceEndpoint.service_id == service_id))
    ).all()
    device_names = await device_label_map(db)
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    references = []
    if snapshot:
        for index, rule in enumerate(snapshot.normalized.get("grants", [])):
            if service.id in rule.get("dst", []) or service.name in rule.get("dst", []):
                references.append({"section": "grants", "rule_index": index})
    return {
        "id": service.id,
        "name": service.name,
        "comment": service.comment,
        "status": service.status,
        "addresses": service.addresses,
        "tags": service.tags,
        "ports": service.ports,
        "source": service.source,
        "synced_at": service.synced_at,
        "stale": not service.present or bool(capability and capability.status != "available"),
        "availability": capability.status if capability else "unknown",
        "hosts": [
            {
                "id": h.id,
                "device_id": h.device_id,
                "device_name": device_names.get(h.device_id or "", h.device_id),
                "advertised": h.advertised,
                "approved": h.approved,
                "status": h.status,
            }
            for h in hosts
        ],
        "endpoints": [
            {
                "id": e.id,
                "host_id": e.host_id,
                "protocol": e.protocol,
                "port": e.port,
                "type": e.endpoint_type,
            }
            for e in endpoints
        ],
        "policy_references": references,
        "provenance": "tailscale_services_api",
    }


def _flow_filters(
    *,
    hours: int,
    source: str,
    destination: str,
    category: str,
    protocol: int | None,
    port: int | None,
    resolution: Literal["all", "resolved", "unresolved"],
) -> FlowFilters:
    return validate_flow_filters(
        FlowFilters(
            hours=hours,
            source=source.strip(),
            destination=destination.strip(),
            category=category,
            protocol=protocol,
            port=port,
            resolution=resolution,
        )
    )


def _flow_dict(
    flow: Flow,
    labels: dict[str, str],
    service_addresses: dict[str, tuple[str, str]] | None = None,
) -> dict[str, Any]:
    service_addresses = service_addresses or {}
    source_identity = flow_identity(flow.source_device_id, flow.source, labels, "Unresolved source")
    destination_identity = flow_identity(
        flow.destination_device_id, flow.destination, labels, "Destination not logged"
    )
    reporter_identity = flow_identity(
        flow.reporting_node_id, flow.reporting_node_id, labels, "Reporter not reported"
    )
    source_service = service_addresses.get(flow.source) if not flow.source_device_id else None
    destination_service = (
        service_addresses.get(flow.destination) if not flow.destination_device_id else None
    )
    return {
        "id": flow.id,
        "source": source_service[1] if source_service else source_identity["label"],
        "source_device_id": source_identity["id"],
        "source_raw": source_identity["raw"],
        "source_service_id": source_service[0] if source_service else None,
        "destination": destination_service[1]
        if destination_service
        else destination_identity["label"],
        "destination_device_id": destination_identity["id"],
        "destination_raw": destination_identity["raw"],
        "destination_service_id": destination_service[0] if destination_service else None,
        "protocol": flow.protocol,
        "source_port": flow.source_port,
        "destination_port": flow.destination_port,
        "category": flow.category,
        "reported_bytes": flow.tx_bytes + flow.rx_bytes,
        "reported_packets": flow.tx_packets + flow.rx_packets,
        "start": flow.start,
        "end": flow.end,
        "reporting_node": reporter_identity["label"],
        "reporting_node_id": reporter_identity["id"],
        "provenance": "demo" if flow.raw.get("demo") else "network_flow_logs",
    }


@router.get("/flows")
async def flows(
    _: Authed,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    source: str = "",
    destination: str = "",
    category: str = "",
    protocol: int | None = None,
    port: int | None = None,
    resolution: Literal["all", "resolved", "unresolved"] = "all",
    hours: int = Query(24),
) -> dict[str, Any]:
    filters = _flow_filters(
        hours=hours,
        source=source,
        destination=destination,
        category=category,
        protocol=protocol,
        port=port,
        resolution=resolution,
    )
    now = datetime.now(UTC)
    query = apply_flow_filters(select(Flow), filters, now)
    cursor_data = decode_cursor(cursor, "flows")
    if cursor_data:
        query = query.where(flow_keyset_condition(cursor_data))
    rows = (
        (await db.execute(query.order_by(Flow.start.desc(), Flow.id.desc()).limit(limit + 1)))
        .scalars()
        .all()
    )
    page_rows = rows[:limit]
    labels = await device_label_map(db)
    service_addresses = await service_address_map(db)
    next_cursor = None
    if len(rows) > limit and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor("flows", {"start": last.start.isoformat(), "id": last.id})
    return {
        "items": [_flow_dict(flow, labels, service_addresses) for flow in page_rows],
        "next_cursor": next_cursor,
        "notice": (
            "Historical client-reported windows, not active sessions. Peer reports can overlap."
        ),
    }


@router.get("/flows/summary")
async def flows_summary(
    _: Authed,
    db: Db,
    source: str = "",
    destination: str = "",
    category: str = "",
    protocol: int | None = None,
    port: int | None = None,
    resolution: Literal["all", "resolved", "unresolved"] = "all",
    hours: int = Query(24),
) -> dict[str, Any]:
    filters = _flow_filters(
        hours=hours,
        source=source,
        destination=destination,
        category=category,
        protocol=protocol,
        port=port,
        resolution=resolution,
    )
    series = await flow_summary_series(db, filters, now=datetime.now(UTC))
    return {
        "series": series,
        "reported_bytes": sum(point["reported_bytes"] for point in series),
        "reported_packets": sum(point["reported_packets"] for point in series),
        "record_count": sum(point["record_count"] for point in series),
        "range_hours": hours,
        "notice": "Reported volumes can overlap because both peers may report a connection.",
    }


def _csv_line(values: list[Any]) -> str:
    output = io.StringIO()
    csv.writer(output).writerow(values)
    return output.getvalue()


def _export_flow(
    flow: Flow, labels: dict[str, str], service_addresses: dict[str, tuple[str, str]]
) -> dict[str, Any]:
    item = _flow_dict(flow, labels, service_addresses)
    item["start"] = flow.start.isoformat()
    item["end"] = flow.end.isoformat()
    return item


@router.get("/flows/export.{format}")
async def export_flows(
    format: str,
    _: Authed,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
    source: str = "",
    destination: str = "",
    category: str = "",
    protocol: int | None = None,
    port: int | None = None,
    resolution: Literal["all", "resolved", "unresolved"] = "all",
    hours: int = Query(24),
) -> StreamingResponse:
    if format not in {"csv", "json"}:
        raise HTTPException(404, "Unsupported export format")
    filters = _flow_filters(
        hours=hours,
        source=source,
        destination=destination,
        category=category,
        protocol=protocol,
        port=port,
        resolution=resolution,
    )
    now = datetime.now(UTC)
    base_query = apply_flow_filters(select(Flow), filters, now).order_by(
        Flow.start.desc(), Flow.id.desc()
    )
    probe = (
        (
            await db.execute(
                apply_flow_filters(select(Flow.id), filters, now)
                .order_by(Flow.start.desc(), Flow.id.desc())
                .limit(settings.export_row_limit + 1)
            )
        )
        .scalars()
        .all()
    )
    truncated = len(probe) > settings.export_row_limit
    labels = await device_label_map(db)
    service_addresses = await service_address_map(db)

    async def json_rows() -> AsyncIterator[str]:
        yield "["
        first = True
        stream = await db.stream_scalars(
            base_query.limit(settings.export_row_limit).execution_options(yield_per=500)
        )
        async for flow in stream:
            if not first:
                yield ","
            yield json.dumps(_export_flow(flow, labels, service_addresses), separators=(",", ":"))
            first = False
        yield "]"

    async def csv_rows() -> AsyncIterator[str]:
        columns = [
            "source",
            "source_device_id",
            "source_service_id",
            "source_raw",
            "destination",
            "destination_device_id",
            "destination_service_id",
            "destination_raw",
            "category",
            "protocol",
            "source_port",
            "destination_port",
            "reported_bytes",
            "reported_packets",
            "start",
            "end",
            "reporting_node",
            "reporting_node_id",
            "provenance",
        ]
        yield _csv_line(columns)
        stream = await db.stream_scalars(
            base_query.limit(settings.export_row_limit).execution_options(yield_per=500)
        )
        async for flow in stream:
            item = _export_flow(flow, labels, service_addresses)
            yield _csv_line([item.get(column, "") for column in columns])

    headers = {
        "Content-Disposition": f"attachment; filename=tailview-flows.{format}",
        "X-TailView-Export-Limit": str(settings.export_row_limit),
        "X-TailView-Export-Truncated": str(truncated).lower(),
    }
    return StreamingResponse(
        json_rows() if format == "json" else csv_rows(),
        media_type="application/json" if format == "json" else "text/csv",
        headers=headers,
    )


@router.get("/topology")
async def topology(
    _: Authed, db: Db, hours: int = Query(24, ge=1, le=720), hide_inactive: bool = False
) -> dict[str, Any]:
    query = (
        select(Device, LocalMetadata, TailnetUser)
        .outerjoin(LocalMetadata)
        .outerjoin(TailnetUser, Device.owner_id == TailnetUser.id)
    )
    if hide_inactive:
        query = query.where(Device.online.is_(True))
    rows = (await db.execute(query)).all()
    nodes = [device_dict(d, m, owner) for d, m, owner in rows if not (m and m.hidden)]
    node_ids = {n["id"] for n in nodes}
    service_rows = (
        await db.scalars(select(TailnetService).where(TailnetService.present.is_(True)))
    ).all()
    service_nodes = [
        {
            "id": f"service:{service.id}",
            "service_id": service.id,
            "name": service.name,
            "source_name": service.name,
            "hostname": "",
            "os": "service",
            "online": None,
            "addresses": service.addresses,
            "tags": service.tags,
            "roles": ["service"],
            "primary_role": "service",
            "kind": "service",
            "status": service.status,
            "source": service.source,
        }
        for service in service_rows
    ]
    nodes.extend(service_nodes)
    flow_rows = (
        await db.execute(
            select(
                Flow.source_device_id,
                Flow.destination_device_id,
                func.sum(Flow.tx_bytes + Flow.rx_bytes),
                func.min(Flow.start),
                func.max(Flow.end),
            )
            .where(Flow.start >= datetime.now(UTC) - timedelta(hours=hours))
            .group_by(Flow.source_device_id, Flow.destination_device_id)
        )
    ).all()
    edges = [
        {
            "id": f"flow:{s}:{d}",
            "source": s,
            "target": d,
            "kind": "observed",
            "reported_bytes": b or 0,
            "first_seen": first,
            "last_seen": last,
            "provenance": "network_flow_logs_or_demo",
        }
        for s, d, b, first, last in flow_rows
        if s in node_ids and d in node_ids
    ]
    service_host_rows = (await db.scalars(select(ServiceHost))).all()
    edges.extend(
        {
            "id": f"hosting:{host.id}",
            "source": host.device_id,
            "target": f"service:{host.service_id}",
            "kind": "hosting",
            "status": host.status,
            "provenance": "tailscale_services_api",
        }
        for host in service_host_rows
        if host.device_id in node_ids
    )
    for service in service_rows:
        if not service.addresses:
            continue
        observed = (
            await db.execute(
                select(Flow.source_device_id, func.sum(Flow.tx_bytes + Flow.rx_bytes))
                .where(
                    Flow.start >= datetime.now(UTC) - timedelta(hours=hours),
                    Flow.source_device_id.is_not(None),
                    Flow.destination.in_(service.addresses),
                )
                .group_by(Flow.source_device_id)
            )
        ).all()
        edges.extend(
            {
                "id": f"service-flow:{source_id}:{service.id}",
                "source": source_id,
                "target": f"service:{service.id}",
                "kind": "observed",
                "reported_bytes": reported_bytes or 0,
                "provenance": "exact_service_address_match",
            }
            for source_id, reported_bytes in observed
            if source_id in node_ids
        )
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    tail_users = (await db.execute(select(TailnetUser))).scalars().all()
    if snapshot:
        policy_edges = evaluate_policy(
            snapshot.normalized,
            nodes,
            [
                {"id": u.id, "login_name": u.login_name, "display_name": u.display_name}
                for u in tail_users
            ],
        )
        edges += [
            {
                "id": f"policy:{e['id']}",
                "source": e["source"],
                "target": e["destination"],
                "kind": "permitted",
                "ports": e["ports"],
                "status": e["status"],
                "rule_index": e["rule_index"],
                "provenance": "tailnet_policy",
            }
            for e in policy_edges
            if e["source"] in node_ids and e["destination"] in node_ids
        ]
        device_by_selector: dict[str, set[str]] = {}
        for node in nodes:
            if node.get("kind") == "service":
                continue
            selectors = {
                node["id"],
                node.get("name", ""),
                node.get("hostname", ""),
                *node.get("addresses", []),
                *node.get("tags", []),
            }
            for selector in selectors:
                if selector:
                    device_by_selector.setdefault(str(selector), set()).add(node["id"])
        for rule_index, grant in enumerate(snapshot.normalized.get("grants", [])):
            destinations = [str(value) for value in grant.get("dst", [])]
            for destination in destinations:
                matching_service = next(
                    (
                        service
                        for service in service_rows
                        if destination in {service.id, service.name}
                    ),
                    None,
                )
                if matching_service is None:
                    continue
                source_ids: set[str] = set()
                for selector in grant.get("src", []):
                    source_ids.update(device_by_selector.get(str(selector), set()))
                edges.extend(
                    {
                        "id": f"service-policy:{rule_index}:{source_id}:{matching_service.id}",
                        "source": source_id,
                        "target": f"service:{matching_service.id}",
                        "kind": "permitted",
                        "ports": grant.get("ip", []),
                        "status": "fully_evaluated",
                        "rule_index": rule_index,
                        "provenance": "tailnet_policy_exact_selector",
                    }
                    for source_id in source_ids
                )
    return {
        "nodes": nodes,
        "edges": edges,
        "generated_at": datetime.now(UTC),
        "notice": "Permitted and observed are distinct. Observations are historical windows.",
    }


@router.get("/policy")
async def policy(_: Authed, db: Db) -> dict[str, Any]:
    snapshot = await db.scalar(
        select(PolicySnapshot).order_by(PolicySnapshot.retrieved_at.desc()).limit(1)
    )
    if not snapshot:
        return {"available": False, "status": "No policy snapshot is available"}
    return {
        "available": True,
        "id": snapshot.id,
        "hujson": snapshot.hujson,
        "normalized": snapshot.normalized,
        "valid": snapshot.valid,
        "parse_error": snapshot.parse_error,
        "unsupported": snapshot.unsupported,
        "retrieved_at": snapshot.retrieved_at,
        "notice": "Read-only current policy; absence of a rule means no matching allow rule.",
    }


@router.get("/policy/review")
async def policy_review(_: Authed, db: Db) -> dict[str, Any]:
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    if not snapshot:
        return {"available": False, "status": "No valid policy snapshot is available"}
    result = review_policy(snapshot.normalized)
    return {
        "available": True,
        "source_snapshot_id": snapshot.id,
        "retrieved_at": snapshot.retrieved_at,
        **result,
    }


@router.get("/policy/security-review")
async def policy_security_review(_: Authed, db: Db) -> dict[str, Any]:
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    if not snapshot:
        return {"available": False, "status": "No valid policy snapshot is available"}
    devices = (await db.execute(select(Device))).scalars().all()
    tail_users = (await db.execute(select(TailnetUser))).scalars().all()
    result = security_review_policy(
        snapshot.normalized,
        [device_dict(device) for device in devices],
        [
            {"id": user.id, "login_name": user.login_name, "display_name": user.display_name}
            for user in tail_users
        ],
    )
    return {
        "available": True,
        "source_snapshot_id": snapshot.id,
        "retrieved_at": snapshot.retrieved_at,
        **result,
    }


@router.get("/audit")
async def audit(_: Authed, db: Db, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    rows = (
        (await db.execute(select(AuditEvent).order_by(AuditEvent.event_time.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": e.id,
                "event_time": e.event_time,
                "action": e.action,
                "actor": e.actor,
                "target": e.target,
                "old": e.old,
                "new": e.new,
                "provenance": "demo" if e.raw.get("demo") else "configuration_audit_log",
            }
            for e in rows
        ],
        "notice": "Configuration events are not network flow records.",
    }


@router.get("/capabilities")
async def capabilities(_: Authed, db: Db) -> dict[str, Any]:
    rows = (await db.execute(select(Capability).order_by(Capability.name))).scalars().all()
    return {
        "items": [
            {
                "name": c.name,
                "status": c.status,
                "source": c.source,
                "requirement": c.requirement,
                "detail": c.detail,
                "last_success": c.last_success,
                "checked_at": c.checked_at,
            }
            for c in rows
        ]
    }


@router.get("/sync")
async def sync_jobs(_: Authed, db: Db) -> dict[str, Any]:
    rows = (
        (await db.execute(select(SyncJob).order_by(SyncJob.started_at.desc()).limit(100)))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": j.id,
                "kind": j.kind,
                "status": j.status,
                "started_at": j.started_at,
                "finished_at": j.finished_at,
                "processed": j.processed,
                "attempted": j.attempted,
                "succeeded": j.succeeded,
                "failed": j.failed,
                "partial_success": j.partial_success,
                "details": j.details,
                "error": j.error,
            }
            for j in rows
        ]
    }


@router.post("/sync/{kind}")
async def run_sync(
    kind: str,
    _: Admin,
    __: Csrf,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str]:
    """Run one read-only source synchronization under its distributed job lock."""
    if settings.demo_mode:
        raise HTTPException(409, "Real synchronization is disabled in demo mode")
    synchronizers = {
        "inventory": sync_inventory,
        "users": sync_users,
        "devices": sync_devices,
        "routes": sync_routes,
        "services": sync_services,
        "dns": sync_dns,
        "webhooks": sync_webhooks,
        "policy": sync_policy,
    }
    if kind in {"flows", "audit"}:
        await sync_logs(kind)
        return {"status": "completed", "kind": kind}
    synchronize = synchronizers.get(kind)
    if synchronize is None:
        raise HTTPException(404, "Unknown synchronization source")
    await synchronize()
    return {"status": "completed", "kind": kind}


@router.get("/settings/dns")
async def dns_settings(_: Admin, db: Db) -> dict[str, Any]:
    row = await db.get(DnsConfiguration, "current")
    capability = await db.get(Capability, "dns")
    if row is None:
        return {"available": False, "status": capability.status if capability else "unknown"}
    return {
        "available": True,
        "status": capability.status if capability else "unknown",
        "stale": bool(capability and capability.status != "available"),
        "magic_dns": row.magic_dns,
        "override_local_dns": row.override_local_dns,
        "nameservers": row.nameservers,
        "search_paths": row.search_paths,
        "split_dns": row.split_dns,
        "synced_at": row.synced_at,
    }


@router.get("/settings/webhooks")
async def webhook_settings(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(
            select(WebhookEndpoint)
            .where(WebhookEndpoint.present.is_(True))
            .order_by(WebhookEndpoint.id)
        )
    ).all()
    capability = await db.get(Capability, "webhooks")
    return {
        "available": capability.status == "available" if capability else False,
        "status": capability.status if capability else "unknown",
        "stale": bool(capability and capability.status != "available"),
        "items": [
            {
                "id": row.id,
                "url": row.url_display,
                "subscriptions": row.subscriptions,
                "enabled": row.enabled,
                "synced_at": row.synced_at,
            }
            for row in rows
        ],
    }


@router.post("/settings/credentials")
async def credentials(
    payload: CredentialRequest,
    _: Admin,
    __: Csrf,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    if payload.kind == "oauth" and not payload.client_id:
        raise HTTPException(422, "client_id is required for OAuth")
    box = SecretBox(settings.encryption_key)
    db.add(
        Credential(
            kind=payload.kind,
            client_id=payload.client_id,
            encrypted_secret=box.encrypt(payload.secret),
        )
    )
    await db.commit()


@router.post("/demo/seed")
async def demo_seed(
    _: Admin, __: Csrf, db: Db, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, str]:
    if not settings.demo_mode:
        raise HTTPException(409, "Demo mode is disabled")
    await seed_demo(db)
    return {"status": "seeded"}


@router.post("/telemetry", status_code=202)
async def telemetry(
    request: Request, db: Db, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, str]:
    if not settings.telemetry_secret:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Local telemetry is disabled")
    body = await request.body()
    expected = hmac.new(settings.telemetry_secret.encode(), body, hashlib.sha256).hexdigest()
    supplied = request.headers.get("x-tailview-signature", "")
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid telemetry signature")
    if len(body) > 5_000_000:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Telemetry payload is too large"
        )
    payload = json.loads(body)
    observed = datetime.fromtimestamp(float(payload.get("observedAt", 0)), UTC)
    collector = payload.get("status", {}).get("Self", {}).get("ID")
    fingerprint = hashlib.sha256(body).hexdigest()
    if not await db.get(TelemetryObservation, fingerprint):
        db.add(
            TelemetryObservation(
                id=fingerprint,
                collector_node_id=collector,
                observed_at=observed,
                scope="single_collector_node",
                payload=payload,
            )
        )
        await db.commit()
    return {"status": "accepted", "provenance": "local_telemetry"}
