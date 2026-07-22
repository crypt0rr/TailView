from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import String, and_, cast, desc, func, or_, select
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
from .findings import (
    SEVERITY_ORDER,
    evaluate_findings_job,
    validate_webhook_url,
)
from .flow_data import (
    FlowFilters,
    apply_flow_filters,
    decode_cursor,
    encode_cursor,
    flow_device_ranking,
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
    DeviceConnectivity,
    DeviceInvite,
    DevicePostureAttribute,
    DevicePostureState,
    DnsConfiguration,
    Finding,
    FindingOccurrence,
    FindingTransition,
    Flow,
    LocalMetadata,
    LogStreamingConfiguration,
    NotificationDelivery,
    NotificationEndpoint,
    PolicySnapshot,
    PostureIntegration,
    ServiceEndpoint,
    ServiceHost,
    SyncJob,
    TailnetContact,
    TailnetCredential,
    TailnetSecuritySettings,
    TailnetService,
    TailnetUser,
    TelemetryObservation,
    WebhookEndpoint,
)
from .policy import (
    evaluate_device_postures,
    evaluate_policy,
    required_postures_for_rule,
    review_policy,
    security_review_policy,
    source_line,
)
from .schemas import (
    CredentialRequest,
    FindingActionRequest,
    FindingAssignRequest,
    FindingSuppressRequest,
    LoginRequest,
    MetadataUpdate,
    NotificationEndpointRequest,
    SetupRequest,
    UserResponse,
)
from .security import SecretBox, new_token
from .sync import (
    sync_contacts,
    sync_credentials,
    sync_device_invites,
    sync_devices,
    sync_dns,
    sync_inventory,
    sync_log_streaming,
    sync_logs,
    sync_policy,
    sync_posture,
    sync_posture_integrations,
    sync_routes,
    sync_services,
    sync_tailnet_settings,
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
        "inventory_details": device.inventory_details,
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


def _posture_applicable(device: Device) -> bool:
    """Avoid posture claims for sources whose device applicability is ambiguous."""
    raw = device.raw or {}
    if "subnet_router" in (device.roles or []):
        return False
    return not any(
        raw.get(key) for key in ("isExternal", "isShared", "shared", "sharedTo", "sharedWith")
    )


def _posture_overall(results: list[dict[str, Any]], state: DevicePostureState | None) -> str:
    if state is None or state.status not in {"available", "stale"}:
        return "incomplete_data"
    if not results:
        return "not_applicable"
    statuses = {str(result["status"]) for result in results}
    if "fail" in statuses:
        return "fail"
    if statuses & {"incomplete_data", "unsupported_condition"}:
        return "incomplete_data"
    if statuses == {"not_applicable"}:
        return "not_applicable"
    return "pass"


async def _posture_payload(
    db: AsyncSession,
    device: Device,
    snapshot: PolicySnapshot | None = None,
    *,
    preloaded_state: DevicePostureState | None = None,
    preloaded_attributes: list[DevicePostureAttribute] | None = None,
    preloaded: bool = False,
) -> dict[str, Any]:
    state = preloaded_state if preloaded else await db.get(DevicePostureState, device.id)
    if preloaded:
        attributes = preloaded_attributes or []
    else:
        attributes = list(
            (
                await db.scalars(
                    select(DevicePostureAttribute)
                    .where(
                        DevicePostureAttribute.device_id == device.id,
                        DevicePostureAttribute.present.is_(True),
                    )
                    .order_by(DevicePostureAttribute.key)
                )
            ).all()
        )
    now = datetime.now(UTC)
    values = {attribute.key: attribute.value for attribute in attributes}
    expiries = {attribute.key: attribute.expiry for attribute in attributes}
    data_available = bool(state and state.status == "available")
    results = evaluate_device_postures(
        snapshot.normalized if snapshot else {},
        values,
        expiries,
        data_available=data_available,
        applicable=_posture_applicable(device),
        now=now,
    )
    for result in results:
        for assertion in result["assertions"]:
            lines = (
                source_line(snapshot.hujson, assertion["condition"]) if snapshot else (None, None)
            )
            assertion["source_lines"] = {"start": lines[0], "end": lines[1]}
    usage: dict[str, list[dict[str, Any]]] = {}
    if snapshot:
        for section in ("grants", "acls"):
            rules = snapshot.normalized.get(section, [])
            if not isinstance(rules, list):
                continue
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue
                required = required_postures_for_rule(snapshot.normalized, rule)
                destinations = rule.get("dst", rule.get("ports", []))
                for posture_name in required:
                    usage.setdefault(posture_name, []).append(
                        {
                            "policy_path": f'$["{section}"][{index}]',
                            "source_lines": {
                                "start": source_line(snapshot.hujson, posture_name)[0],
                                "end": source_line(snapshot.hujson, posture_name)[1],
                            },
                            "affected_destinations": destinations
                            if isinstance(destinations, list)
                            else [],
                        }
                    )
    for result in results:
        result["policy_uses"] = usage.get(result["name"], [])

    rule_impacts: list[dict[str, Any]] = []
    result_by_name = {result["name"]: result["status"] for result in results}
    if snapshot:
        for section in ("grants", "acls"):
            rules = snapshot.normalized.get(section, [])
            if not isinstance(rules, list):
                continue
            for index, rule in enumerate(rules):
                if not isinstance(rule, dict):
                    continue
                required = required_postures_for_rule(snapshot.normalized, rule)
                if not required:
                    continue
                statuses = [result_by_name.get(name, "unsupported_condition") for name in required]
                if not _posture_applicable(device):
                    status_value = "not_applicable"
                elif "pass" in statuses:
                    status_value = "pass"
                elif any(
                    status in {"incomplete_data", "unsupported_condition"} for status in statuses
                ):
                    status_value = "incomplete_data"
                else:
                    status_value = "fail"
                destinations = rule.get("dst", rule.get("ports", []))
                rule_impacts.append(
                    {
                        "policy_path": f'$["{section}"][{index}]',
                        "status": status_value,
                        "required_postures": required,
                        "semantics": "any_required_posture_may_pass",
                        "affected_destinations": destinations
                        if isinstance(destinations, list)
                        else [],
                    }
                )

    attribute_items = []
    for attribute in attributes:
        expiry = attribute.expiry
        if expiry and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        if expiry and expiry <= now:
            expiry_state = "expired"
        elif expiry and expiry <= now + timedelta(days=7):
            expiry_state = "expiring"
        else:
            expiry_state = "active"
        attribute_items.append(
            {
                "key": attribute.key,
                "namespace": attribute.namespace,
                "value": attribute.value,
                "value_type": attribute.value_type,
                "expiry": expiry,
                "expiry_state": expiry_state,
                "synced_at": attribute.synced_at,
                "provenance": "tailscale_device_posture_attributes_api",
            }
        )
    return {
        "status": _posture_overall(results, state),
        "evidence_status": state.status if state else "unknown",
        "stale": bool(state and state.status == "stale"),
        "checked_at": state.checked_at if state else None,
        "last_success": state.last_success if state else None,
        "attributes": attribute_items,
        "evaluations": results,
        "rule_impacts": rule_impacts,
        "notice": (
            "Posture is evaluated against the current policy and current device evidence. "
            "It does not describe posture at the time of historical flows."
        ),
    }


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
    user: Authed,
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
    finding_query = select(Finding.severity, func.count()).where(
        Finding.status.in_(["open", "acknowledged"])
    )
    if user.role != "administrator":
        finding_query = finding_query.where(Finding.visibility == "viewer")
    finding_counts = {
        severity: int(count)
        for severity, count in (await db.execute(finding_query.group_by(Finding.severity))).all()
    }
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
        "findings": {
            "open": sum(finding_counts.values()),
            "critical": finding_counts.get("critical", 0),
            "high": finding_counts.get("high", 0),
        },
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
        .where(Device.active.is_(True))
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
        query = query.where(
            or_(
                Device.primary_role == role,
                cast(Device.roles, String).like(f'%"{role}"%'),
            )
        )
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
    posture_result: str = "",
) -> dict[str, Any]:
    if posture_result:
        if posture_result not in {"pass", "fail", "incomplete_data", "not_applicable"}:
            raise HTTPException(422, "Unsupported posture result filter")
        items = [
            item
            for item in await _security_device_rows(db)
            if item["posture"]["status"] == posture_result
        ]
        cursor_data = decode_cursor(cursor, "devices")
        if cursor_data:
            key = (str(cursor_data.get("name", "")), str(cursor_data.get("id", "")))
            items = [
                item for item in items if (str(item["name"]).casefold(), str(item["id"])) > key
            ]
        page = items[:limit]
        next_cursor = None
        if len(items) > limit and page:
            last = page[-1]
            next_cursor = encode_cursor(
                "devices", {"name": str(last["name"]).casefold(), "id": last["id"]}
            )
        return {"items": page, "next_cursor": next_cursor}
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
    items = []
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    for current_device, metadata, item_owner, _ in page_rows:
        item = device_dict(current_device, metadata, item_owner)
        item["posture"] = await _posture_payload(db, current_device, snapshot)
        items.append(item)
    return {"items": items, "next_cursor": next_cursor}


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
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    item["posture"] = await _posture_payload(db, row[0], snapshot)
    connectivity = await db.get(DeviceConnectivity, device_id)
    item["connectivity"] = (
        {
            "status": "available",
            "mapping_varies_by_dest_ip": connectivity.mapping_varies_by_dest_ip,
            "derp": connectivity.derp,
            "endpoints": connectivity.endpoints,
            "latency": connectivity.latency,
            "client_supports": connectivity.client_supports,
            "retrieved_at": connectivity.retrieved_at,
            "provenance": "tailscale_device_api_client_connectivity",
            "notice": (
                "Device-reported API snapshot. Endpoints, DERP selection, and latency are "
                "delayed point-in-time reports, not live or tailnet-wide measurements."
            ),
        }
        if connectivity
        else {
            "status": "not_reported",
            "retrieved_at": None,
            "provenance": "tailscale_device_api_client_connectivity",
            "notice": "Client connectivity was not supplied by the device API.",
        }
    )
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
    now = datetime.now(UTC)
    series = await flow_summary_series(db, filters, now=now)
    top_devices = await flow_device_ranking(db, filters, now=now)
    labels = await device_label_map(db)
    return {
        "series": series,
        "reported_bytes": sum(point["reported_bytes"] for point in series),
        "reported_packets": sum(point["reported_packets"] for point in series),
        "record_count": sum(point["record_count"] for point in series),
        "top_devices": [
            {**item, "name": labels.get(item["device_id"], item["device_id"])}
            for item in top_devices
        ],
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
    capability_by_name = {row.name: row for row in rows}
    active_devices = (await db.scalars(select(Device).where(Device.active.is_(True)))).all()
    service_count = (
        await db.scalar(
            select(func.count()).select_from(TailnetService).where(TailnetService.present.is_(True))
        )
    ) or 0
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    groups_value = snapshot.normalized.get("groups", {}) if snapshot else {}
    group_count = len(groups_value) if isinstance(groups_value, dict) else 0
    tag_count = len({str(tag) for device in active_devices for tag in device.tags})
    inventory_counts = {
        "/services": (int(service_count), "services", "Tailscale Services"),
        "/routes": (
            sum(len(device.advertised_routes) for device in active_devices),
            "routes",
            "advertised routes",
        ),
        "/exit-nodes": (
            sum("exit_node" in device.roles for device in active_devices),
            "routes",
            "exit nodes",
        ),
        "/subnet-routers": (
            sum("subnet_router" in device.roles for device in active_devices),
            "routes",
            "subnet routers",
        ),
        "/groups": (group_count, "policy", "policy groups"),
        "/tags": (tag_count, "device_inventory", "device tags"),
    }
    governance_names = {
        "credential_inventory",
        "device_invites",
        "tailnet_contacts",
        "log_streaming",
    }
    governance_rows = [
        capability_by_name[name] for name in governance_names if name in capability_by_name
    ]
    governance_count = (
        int(
            await db.scalar(
                select(func.count())
                .select_from(TailnetCredential)
                .where(TailnetCredential.present.is_(True))
            )
            or 0
        )
        + int(
            await db.scalar(
                select(func.count()).select_from(DeviceInvite).where(DeviceInvite.present.is_(True))
            )
            or 0
        )
        + int(
            await db.scalar(
                select(func.count())
                .select_from(TailnetContact)
                .where(TailnetContact.present.is_(True))
            )
            or 0
        )
        + int(
            await db.scalar(
                select(func.count())
                .select_from(LogStreamingConfiguration)
                .where(LogStreamingConfiguration.enabled.is_(True))
            )
            or 0
        )
    )
    determinate_states = {
        "available",
        "permission_denied",
        "feature_disabled",
        "plan_unavailable",
        "unsupported",
    }
    governance_evaluated = len(governance_rows) == len(governance_names) and all(
        row.status in determinate_states for row in governance_rows
    )
    inventory_counts["/security/governance"] = (
        governance_count,
        "access_governance",
        "governance records or enabled streams",
    )
    navigation = {}
    for path, (count, capability_name, label) in inventory_counts.items():
        capability = capability_by_name.get(capability_name)
        evaluated = (
            governance_evaluated
            if path == "/security/governance"
            else bool(capability and capability.status == "available")
        )
        navigation[path] = {
            "count": count,
            "evaluated": evaluated,
            "in_use": not evaluated or count > 0,
            "status": "active" if not evaluated or count > 0 else "not_configured",
            "detail": (
                f"Successfully synchronized; no {label} are currently configured."
                if evaluated and count == 0
                else f"{count} synchronized {label}."
            ),
            "checked_at": capability.checked_at if capability else None,
        }
    items = [
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
    if governance_rows:
        unavailable = {"permission_denied", "feature_disabled", "plan_unavailable", "unsupported"}
        aggregate_status = (
            "available"
            if any(row.status == "available" for row in governance_rows)
            else "unsupported"
            if governance_evaluated and all(row.status in unavailable for row in governance_rows)
            else "unknown"
        )
        items.append(
            {
                "name": "access_governance",
                "status": aggregate_status,
                "source": "Aggregate governance sources",
                "requirement": "all:read or applicable granular read scopes",
                "detail": "Credential, invite, contact, and log-stream inventory.",
                "last_success": max(
                    (row.last_success for row in governance_rows if row.last_success), default=None
                ),
                "checked_at": max(row.checked_at for row in governance_rows),
            }
        )
    return {
        "items": items,
        "navigation": navigation,
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


def _finding_visible(user: AppUser, finding: Finding) -> bool:
    return user.role == "administrator" or finding.visibility == "viewer"


def _finding_dict(finding: Finding, assignee: AppUser | None = None) -> dict[str, Any]:
    return {
        "id": finding.id,
        "source": finding.source,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "summary": finding.summary,
        "remediation": finding.remediation,
        "subject_type": finding.subject_type,
        "subject_id": finding.subject_id,
        "subject_display": finding.subject_display,
        "evidence": finding.evidence,
        "link_path": finding.link_path,
        "status": finding.status,
        "stale": finding.stale,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "last_evaluated": finding.last_evaluated,
        "resolved_at": finding.resolved_at,
        "acknowledged_at": finding.acknowledged_at,
        "suppressed_until": finding.suppressed_until,
        "suppression_reason": finding.suppression_reason,
        "assigned_to": finding.assigned_to,
        "assignee": assignee.username if assignee else None,
        "occurrence_count": finding.occurrence_count,
    }


@router.get("/findings/summary")
async def findings_summary(user: Authed, db: Db) -> dict[str, Any]:
    visibility = [] if user.role == "administrator" else [Finding.visibility == "viewer"]
    rows = (
        await db.execute(
            select(Finding.status, Finding.severity, Finding.source, func.count())
            .where(*visibility)
            .group_by(Finding.status, Finding.severity, Finding.source)
        )
    ).all()
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    open_by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for status_value, severity, source, count in rows:
        by_status[status_value] = by_status.get(status_value, 0) + int(count)
        if status_value != "resolved":
            by_severity[severity] = by_severity.get(severity, 0) + int(count)
            by_source[source] = by_source.get(source, 0) + int(count)
        if status_value == "open":
            open_by_severity[severity] = open_by_severity.get(severity, 0) + int(count)
    return {
        "total": sum(by_status.values()),
        "open": sum(
            count for status_value, count in by_status.items() if status_value != "resolved"
        ),
        "by_status": by_status,
        "by_severity": by_severity,
        "open_by_severity": open_by_severity,
        "by_source": by_source,
        "generated_at": datetime.now(UTC),
    }


@router.get("/findings")
async def findings_list(
    user: Authed,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    status_filter: str = Query("", alias="status"),
    severity: str = "",
    source: str = "",
    category: str = "",
    subject: str = "",
    assigned_to: str = "",
    search: str = "",
) -> dict[str, Any]:
    query = select(Finding, AppUser).outerjoin(AppUser, Finding.assigned_to == AppUser.id)
    if user.role != "administrator":
        query = query.where(Finding.visibility == "viewer")
    if status_filter:
        allowed = {"open", "acknowledged", "suppressed", "resolved"}
        if status_filter not in allowed:
            raise HTTPException(422, "Invalid finding status")
        query = query.where(Finding.status == status_filter)
    if severity:
        if severity not in SEVERITY_ORDER:
            raise HTTPException(422, "Invalid finding severity")
        query = query.where(Finding.severity == severity)
    if source:
        query = query.where(Finding.source == source)
    if category:
        query = query.where(Finding.category == category)
    if subject:
        pattern = f"%{subject}%"
        query = query.where(
            or_(Finding.subject_type.ilike(pattern), Finding.subject_display.ilike(pattern))
        )
    if assigned_to:
        query = query.where(
            Finding.assigned_to.is_(None)
            if assigned_to == "unassigned"
            else Finding.assigned_to == assigned_to
        )
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.summary.ilike(pattern),
                Finding.subject_display.ilike(pattern),
            )
        )
    cursor_data = decode_cursor(cursor, "findings")
    if cursor_data:
        try:
            cursor_time = datetime.fromisoformat(str(cursor_data["last_seen"]))
            cursor_id = str(cursor_data["id"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, "Invalid cursor") from exc
        query = query.where(
            or_(
                Finding.last_seen < cursor_time,
                and_(Finding.last_seen == cursor_time, Finding.id > cursor_id),
            )
        )
    rows = (
        await db.execute(query.order_by(Finding.last_seen.desc(), Finding.id).limit(limit + 1))
    ).all()
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit and page:
        last = page[-1][0]
        next_cursor = encode_cursor(
            "findings", {"last_seen": last.last_seen.isoformat(), "id": last.id}
        )
    return {
        "items": [_finding_dict(finding, assignee) for finding, assignee in page],
        "next_cursor": next_cursor,
    }


@router.get("/findings/notification-endpoints")
async def notification_endpoints(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(select(NotificationEndpoint).order_by(NotificationEndpoint.name))
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "name": row.name,
                "url": row.url_display,
                "minimum_severity": row.minimum_severity,
                "sources": row.sources,
                "include_resolved": row.include_resolved,
                "enabled": row.enabled,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]
    }


@router.post("/findings/notification-endpoints")
async def create_notification_endpoint(
    payload: NotificationEndpointRequest,
    _: Admin,
    __: Csrf,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    try:
        display = await validate_webhook_url(payload.url, settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    secret = new_token()
    box = SecretBox(settings.encryption_key)
    row = NotificationEndpoint(
        name=payload.name,
        url_display=display,
        encrypted_url=box.encrypt(payload.url),
        encrypted_secret=box.encrypt(secret),
        minimum_severity=payload.minimum_severity,
        sources=payload.sources,
        include_resolved=payload.include_resolved,
        enabled=payload.enabled,
    )
    db.add(row)
    await db.commit()
    return {"id": row.id, "name": row.name, "url": row.url_display, "signing_secret": secret}


@router.put("/findings/notification-endpoints/{endpoint_id}")
async def update_notification_endpoint(
    endpoint_id: str,
    payload: NotificationEndpointRequest,
    _: Admin,
    __: Csrf,
    db: Db,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    row = await db.get(NotificationEndpoint, endpoint_id)
    if row is None:
        raise HTTPException(404, "Notification endpoint not found")
    try:
        row.url_display = await validate_webhook_url(payload.url, settings)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    row.name = payload.name
    row.encrypted_url = SecretBox(settings.encryption_key).encrypt(payload.url)
    row.minimum_severity = payload.minimum_severity
    row.sources = payload.sources
    row.include_resolved = payload.include_resolved
    row.enabled = payload.enabled
    await db.commit()
    return {"id": row.id, "name": row.name, "url": row.url_display, "enabled": row.enabled}


@router.delete("/findings/notification-endpoints/{endpoint_id}")
async def delete_notification_endpoint(endpoint_id: str, _: Admin, __: Csrf, db: Db) -> None:
    row = await db.get(NotificationEndpoint, endpoint_id)
    if row is None:
        raise HTTPException(404, "Notification endpoint not found")
    row.enabled = False
    await db.commit()


@router.post("/findings/notification-endpoints/{endpoint_id}/test")
async def test_notification_endpoint(
    endpoint_id: str,
    _: Admin,
    __: Csrf,
    db: Db,
) -> dict[str, Any]:
    endpoint = await db.get(NotificationEndpoint, endpoint_id)
    if endpoint is None:
        raise HTTPException(404, "Notification endpoint not found")
    event_id = str(uuid.uuid4())
    delivery = NotificationDelivery(
        endpoint_id=endpoint.id,
        finding_id=None,
        event_type="test",
        idempotency_key=f"{endpoint.id}:{event_id}",
        payload={
            "schemaVersion": "1",
            "eventId": event_id,
            "eventType": "test",
            "occurredAt": datetime.now(UTC).isoformat(),
            "message": "TailView notification endpoint test",
        },
    )
    db.add(delivery)
    await db.commit()
    return {"delivery_id": delivery.id, "status": delivery.status}


@router.get("/findings/notification-deliveries")
async def notification_deliveries(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(
            select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(200)
        )
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "endpoint_id": row.endpoint_id,
                "finding_id": row.finding_id,
                "event_type": row.event_type,
                "status": row.status,
                "attempt_count": row.attempt_count,
                "next_attempt": row.next_attempt,
                "last_attempt": row.last_attempt,
                "delivered_at": row.delivered_at,
                "http_status": row.http_status,
                "error_class": row.error_class,
                "created_at": row.created_at,
            }
            for row in rows
        ]
    }


@router.get("/findings/assignees")
async def finding_assignees(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(select(AppUser).where(AppUser.active.is_(True)).order_by(AppUser.username))
    ).all()
    return {"items": [{"id": row.id, "username": row.username, "role": row.role} for row in rows]}


@router.get("/findings/{finding_id}")
async def finding_detail(finding_id: str, user: Authed, db: Db) -> dict[str, Any]:
    finding = await db.get(Finding, finding_id)
    if finding is None or not _finding_visible(user, finding):
        raise HTTPException(404, "Finding not found")
    assignee = await db.get(AppUser, finding.assigned_to) if finding.assigned_to else None
    occurrences = (
        await db.scalars(
            select(FindingOccurrence)
            .where(FindingOccurrence.finding_id == finding.id)
            .order_by(FindingOccurrence.occurred_at.desc())
            .limit(200)
        )
    ).all()
    transitions = (
        await db.scalars(
            select(FindingTransition)
            .where(FindingTransition.finding_id == finding.id)
            .order_by(FindingTransition.occurred_at.desc())
            .limit(200)
        )
    ).all()
    return {
        **_finding_dict(finding, assignee),
        "occurrences": [
            {
                "id": row.id,
                "event_type": row.event_type,
                "severity": row.severity,
                "evidence": row.evidence,
                "occurred_at": row.occurred_at,
            }
            for row in occurrences
        ],
        "transitions": [
            {
                "id": row.id,
                "from_status": row.from_status,
                "to_status": row.to_status,
                "actor_id": row.actor_id,
                "reason": row.reason,
                "occurred_at": row.occurred_at,
            }
            for row in transitions
        ],
    }


async def _finding_for_action(finding_id: str, db: AsyncSession) -> Finding:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    return finding


def _record_finding_transition(
    db: AsyncSession,
    finding: Finding,
    status_value: str,
    actor: AppUser,
    reason: str,
) -> None:
    db.add(
        FindingTransition(
            finding_id=finding.id,
            from_status=finding.status,
            to_status=status_value,
            actor_id=actor.id,
            reason=reason,
        )
    )
    finding.status = status_value


@router.post("/findings/{finding_id}/acknowledge")
async def acknowledge_finding(
    finding_id: str, payload: FindingActionRequest, user: Admin, _: Csrf, db: Db
) -> dict[str, Any]:
    finding = await _finding_for_action(finding_id, db)
    if finding.status == "resolved":
        raise HTTPException(409, "Resolved findings cannot be acknowledged")
    _record_finding_transition(db, finding, "acknowledged", user, payload.reason)
    finding.acknowledged_at = datetime.now(UTC)
    finding.acknowledged_by = user.id
    await db.commit()
    return _finding_dict(finding)


@router.post("/findings/{finding_id}/reopen")
async def reopen_finding(
    finding_id: str, payload: FindingActionRequest, user: Admin, _: Csrf, db: Db
) -> dict[str, Any]:
    finding = await _finding_for_action(finding_id, db)
    _record_finding_transition(db, finding, "open", user, payload.reason)
    finding.resolved_at = None
    finding.suppressed_until = None
    finding.suppression_reason = ""
    await db.commit()
    return _finding_dict(finding)


@router.post("/findings/{finding_id}/suppress")
async def suppress_finding(
    finding_id: str, payload: FindingSuppressRequest, user: Admin, _: Csrf, db: Db
) -> dict[str, Any]:
    finding = await _finding_for_action(finding_id, db)
    if finding.status == "resolved":
        raise HTTPException(409, "Resolved findings cannot be suppressed")
    durations = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    finding.suppressed_until = (
        datetime.now(UTC) + durations[payload.duration]
        if payload.duration != "indefinite"
        else None
    )
    finding.suppression_reason = payload.reason
    _record_finding_transition(db, finding, "suppressed", user, payload.reason)
    await db.commit()
    return _finding_dict(finding)


@router.post("/findings/{finding_id}/unsuppress")
async def unsuppress_finding(
    finding_id: str, payload: FindingActionRequest, user: Admin, _: Csrf, db: Db
) -> dict[str, Any]:
    finding = await _finding_for_action(finding_id, db)
    if finding.status != "suppressed":
        raise HTTPException(409, "Finding is not suppressed")
    _record_finding_transition(db, finding, "open", user, payload.reason)
    finding.suppressed_until = None
    finding.suppression_reason = ""
    await db.commit()
    return _finding_dict(finding)


@router.post("/findings/{finding_id}/assign")
async def assign_finding(
    finding_id: str, payload: FindingAssignRequest, user: Admin, _: Csrf, db: Db
) -> dict[str, Any]:
    finding = await _finding_for_action(finding_id, db)
    assignee = None
    if payload.user_id:
        assignee = await db.get(AppUser, payload.user_id)
        if assignee is None or not assignee.active:
            raise HTTPException(422, "Assignee must be an active TailView user")
    finding.assigned_to = payload.user_id
    db.add(
        FindingTransition(
            finding_id=finding.id,
            from_status=finding.status,
            to_status=finding.status,
            actor_id=user.id,
            reason=f"Assigned to {assignee.username}" if assignee else "Assignment cleared",
        )
    )
    await db.commit()
    return _finding_dict(finding, assignee)


def _governance_credential_status(row: TailnetCredential, now: datetime) -> str:
    if row.stale:
        return "stale"
    if row.revoked is True:
        return "revoked"
    expires_at = (
        row.expires_at.replace(tzinfo=UTC)
        if row.expires_at and row.expires_at.tzinfo is None
        else row.expires_at
    )
    if expires_at and expires_at <= now:
        return "expired"
    if not row.present:
        return "inactive"
    return "active"


def _public_credential_id(identifier: str) -> str:
    return hashlib.sha256(f"tailview-credential:{identifier}".encode()).hexdigest()


def _governance_capability(row: Capability | None, scope: str) -> dict[str, Any]:
    return {
        "status": row.status if row else "unknown",
        "detail": row.detail if row else "Not synchronized yet",
        "last_success": row.last_success if row else None,
        "checked_at": row.checked_at if row else None,
        "required_scope": scope,
    }


async def _governance_findings(db: AsyncSession) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    credentials = (await db.scalars(select(TailnetCredential))).all()
    invites = (await db.scalars(select(DeviceInvite).where(DeviceInvite.present.is_(True)))).all()
    contacts = (
        await db.scalars(select(TailnetContact).where(TailnetContact.present.is_(True)))
    ).all()
    findings: list[dict[str, Any]] = []
    for credential_row in credentials:
        status_value = _governance_credential_status(credential_row, now)
        if status_value != "active":
            continue
        if credential_row.credential_type == "auth_key" and credential_row.reusable is True:
            findings.append(
                {
                    "id": f"reusable:{_public_credential_id(credential_row.id)}",
                    "severity": "high",
                    "kind": "reusable_auth_key",
                    "record_type": "credential",
                    "record_id": _public_credential_id(credential_row.id),
                    "label": credential_row.description or credential_row.display_id,
                    "message": "An active reusable authentication key was reported.",
                    "remediation": (
                        "Confirm continued need and protect it in a dedicated secrets manager."
                    ),
                    "evidence": {"reusable": True, "type": credential_row.credential_type},
                }
            )
        if credential_row.expires_at:
            expires_at = (
                credential_row.expires_at.replace(tzinfo=UTC)
                if credential_row.expires_at.tzinfo is None
                else credential_row.expires_at
            )
            remaining = expires_at - now
            if timedelta(0) < remaining <= timedelta(days=30):
                days = max(0, remaining.days)
                findings.append(
                    {
                        "id": f"expiry:{_public_credential_id(credential_row.id)}",
                        "severity": "high" if days <= 7 else "medium",
                        "kind": "credential_expiring",
                        "record_type": "credential",
                        "record_id": _public_credential_id(credential_row.id),
                        "label": credential_row.description or credential_row.display_id,
                        "message": f"A credential expires in {days} day{'s' if days != 1 else ''}.",
                        "remediation": (
                            "Rotate or remove the credential before its reported expiry."
                        ),
                        "evidence": {
                            "expires_at": credential_row.expires_at,
                            "days_remaining": days,
                        },
                    }
                )
        write_scopes = [
            scope
            for scope in credential_row.scopes
            if scope == "all" or not scope.endswith(":read")
        ]
        if write_scopes:
            findings.append(
                {
                    "id": f"write-scope:{_public_credential_id(credential_row.id)}",
                    "severity": "high" if "all" in write_scopes else "medium",
                    "kind": "write_capable_scope",
                    "record_type": "credential",
                    "record_id": _public_credential_id(credential_row.id),
                    "label": credential_row.description or credential_row.display_id,
                    "message": "The API explicitly reported one or more write-capable scopes.",
                    "remediation": (
                        "Prefer equivalent read-only scopes when mutation is unnecessary."
                    ),
                    "evidence": {"scopes": write_scopes},
                }
            )
    for invite_row in invites:
        if invite_row.status not in {"pending", "created", "unknown"}:
            continue
        created_at = (
            invite_row.created_at.replace(tzinfo=UTC)
            if invite_row.created_at and invite_row.created_at.tzinfo is None
            else invite_row.created_at
        )
        invite_expires_at = (
            invite_row.expires_at.replace(tzinfo=UTC)
            if invite_row.expires_at and invite_row.expires_at.tzinfo is None
            else invite_row.expires_at
        )
        age = (now - created_at).days if created_at else None
        expiring = bool(
            invite_expires_at and timedelta(0) < invite_expires_at - now <= timedelta(days=7)
        )
        if (age is not None and age >= 14) or expiring:
            findings.append(
                {
                    "id": f"invite:{invite_row.id}",
                    "severity": "medium",
                    "kind": "pending_device_invite",
                    "record_type": "invite",
                    "record_id": invite_row.id,
                    "label": invite_row.recipient or invite_row.id,
                    "message": "A device invitation remains pending or is nearing expiry.",
                    "remediation": (
                        "Confirm the invitation is still expected in the Tailscale admin console."
                    ),
                    "evidence": {"age_days": age, "expires_at": invite_expires_at},
                }
            )
    for contact_row in contacts:
        if contact_row.verified is False:
            findings.append(
                {
                    "id": f"contact:{contact_row.contact_type}",
                    "severity": "medium",
                    "kind": "unverified_contact",
                    "record_type": "contact",
                    "record_id": contact_row.contact_type,
                    "label": contact_row.contact_type,
                    "message": "The API explicitly reports this tailnet contact as unverified.",
                    "remediation": "Complete verification in the Tailscale admin console.",
                    "evidence": {"verified": False},
                }
            )
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (order.get(str(item["severity"]), 9), item["id"]))


@router.get("/security/governance")
async def security_governance(_: Admin, db: Db) -> dict[str, Any]:
    now = datetime.now(UTC)
    credentials = (await db.scalars(select(TailnetCredential))).all()
    invites = (await db.scalars(select(DeviceInvite).where(DeviceInvite.present.is_(True)))).all()
    contacts = (
        await db.scalars(select(TailnetContact).where(TailnetContact.present.is_(True)))
    ).all()
    streams = (await db.scalars(select(LogStreamingConfiguration))).all()
    capability_specs = {
        "credentials": ("credential_inventory", "all:read or granular key read scopes"),
        "invites": ("device_invites", "devices_invites:read or all:read"),
        "contacts": ("tailnet_contacts", "account_settings:read or all:read"),
        "log_streaming": ("log_streaming", "log_streaming:read or all:read"),
    }
    capabilities_value = {
        label: _governance_capability(await db.get(Capability, name), scope)
        for label, (name, scope) in capability_specs.items()
    }
    return {
        "counts": {
            "credentials": sum(row.present for row in credentials),
            "active_credentials": sum(
                _governance_credential_status(row, now) == "active" for row in credentials
            ),
            "expiring_credentials": sum(
                bool(
                    row.present
                    and row.expires_at
                    and timedelta(0)
                    < (
                        row.expires_at.replace(tzinfo=UTC)
                        if row.expires_at.tzinfo is None
                        else row.expires_at
                    )
                    - now
                    <= timedelta(days=30)
                )
                for row in credentials
            ),
            "pending_invites": sum(
                row.status in {"pending", "created", "unknown"} for row in invites
            ),
            "verified_contacts": sum(row.verified is True for row in contacts),
            "enabled_streams": sum(row.enabled is True for row in streams),
        },
        "findings": await _governance_findings(db),
        "capabilities": capabilities_value,
        "freshness": {
            "stale_credentials": sum(row.stale for row in credentials),
            "stale_invites": sum(row.stale for row in invites),
            "stale_contacts": sum(row.stale for row in contacts),
            "stale_streams": sum(row.stale for row in streams),
        },
        "limitations": [
            "TailView receives metadata only; usable credential secrets are never requested.",
            (
                "Credential-to-device use is not inferred unless the upstream API explicitly "
                "reports it."
            ),
            (
                "Disabled log streaming is configuration visibility, not automatically a "
                "vulnerability."
            ),
        ],
    }


@router.get("/security/governance/credentials")
async def governance_credentials(
    _: Admin,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    credential_type: str = "",
    status_filter: str = Query("", alias="status"),
    scope: str = "",
    expiry_days: int | None = Query(None, ge=1, le=365),
    search: str = "",
) -> dict[str, Any]:
    now = datetime.now(UTC)
    rows = (await db.scalars(select(TailnetCredential))).all()
    items: list[dict[str, Any]] = []
    for row in rows:
        status_value = _governance_credential_status(row, now)
        if credential_type and row.credential_type != credential_type:
            continue
        if status_filter and status_value != status_filter:
            continue
        if scope and not any(scope.casefold() in value.casefold() for value in row.scopes):
            continue
        expires_at = (
            row.expires_at.replace(tzinfo=UTC)
            if row.expires_at and row.expires_at.tzinfo is None
            else row.expires_at
        )
        if expiry_days is not None and not (
            expires_at and timedelta(0) < expires_at - now <= timedelta(days=expiry_days)
        ):
            continue
        haystack = " ".join([row.display_id, row.description, row.creator_id or "", *row.scopes])
        if search and search.casefold() not in haystack.casefold():
            continue
        items.append(
            {
                "id": _public_credential_id(row.id),
                "display_id": row.display_id,
                "type": row.credential_type,
                "description": row.description,
                "creator_id": row.creator_id,
                "scopes": row.scopes,
                "tags": row.tags,
                "reusable": row.reusable,
                "ephemeral": row.ephemeral,
                "preapproved": row.preapproved,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "status": status_value,
                "present": row.present,
                "stale": row.stale,
                "synced_at": row.synced_at,
                "provenance": row.source,
            }
        )
    items.sort(
        key=lambda item: (
            (item["description"] or item["display_id"]).casefold(),
            item["id"],
        )
    )
    cursor_data = decode_cursor(cursor, "governance_credentials")
    if cursor_data:
        key = (str(cursor_data.get("name", "")), str(cursor_data.get("id", "")))
        items = [
            item
            for item in items
            if ((item["description"] or item["display_id"]).casefold(), item["id"]) > key
        ]
    page = items[:limit]
    next_cursor = None
    if len(items) > limit and page:
        last = page[-1]
        next_cursor = encode_cursor(
            "governance_credentials",
            {"name": (last["description"] or last["display_id"]).casefold(), "id": last["id"]},
        )
    return {"items": page, "next_cursor": next_cursor, "total": len(items)}


@router.get("/security/governance/invites")
async def governance_invites(
    _: Admin,
    db: Db,
    status_filter: str = Query("", alias="status"),
) -> dict[str, Any]:
    rows = (
        await db.execute(
            select(DeviceInvite, Device, TailnetUser)
            .outerjoin(Device, DeviceInvite.device_id == Device.id)
            .outerjoin(TailnetUser, DeviceInvite.inviter_id == TailnetUser.id)
            .where(DeviceInvite.present.is_(True))
            .order_by(DeviceInvite.created_at.desc(), DeviceInvite.id)
        )
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "device_id": row.device_id,
                "device_name": device.name if device else row.device_id,
                "inviter_id": row.inviter_id,
                "inviter_name": (
                    inviter.display_name or inviter.login_name if inviter else row.inviter_id
                ),
                "recipient": row.recipient,
                "status": row.status,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "accepted_at": row.accepted_at,
                "stale": row.stale,
                "synced_at": row.synced_at,
                "provenance": "tailscale_device_invites_api",
            }
            for row, device, inviter in rows
            if not status_filter or row.status == status_filter
        ]
    }


@router.get("/security/governance/contacts")
async def governance_contacts(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(
            select(TailnetContact)
            .where(TailnetContact.present.is_(True))
            .order_by(TailnetContact.contact_type)
        )
    ).all()
    return {
        "items": [
            {
                "type": row.contact_type,
                "value": row.value,
                "verified": row.verified,
                "stale": row.stale,
                "synced_at": row.synced_at,
                "provenance": "tailscale_contacts_api",
            }
            for row in rows
        ]
    }


@router.get("/security/governance/log-streaming")
async def governance_log_streaming(_: Admin, db: Db) -> dict[str, Any]:
    rows = (
        await db.scalars(
            select(LogStreamingConfiguration).order_by(LogStreamingConfiguration.log_type)
        )
    ).all()
    return {
        "items": [
            {
                "log_type": row.log_type,
                "enabled": row.enabled,
                "destination_type": row.destination_type,
                "destination": row.destination_display,
                "status": row.status,
                "stale": row.stale,
                "synced_at": row.synced_at,
                "provenance": "tailscale_log_streaming_api",
            }
            for row in rows
        ]
    }


async def _security_device_rows(db: AsyncSession) -> list[dict[str, Any]]:
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    rows = (
        await db.execute(
            select(Device, LocalMetadata, TailnetUser)
            .outerjoin(LocalMetadata)
            .outerjoin(TailnetUser, Device.owner_id == TailnetUser.id)
            .where(Device.active.is_(True))
            .order_by(func.lower(func.coalesce(LocalMetadata.display_name, Device.name)), Device.id)
        )
    ).all()
    states = {
        state.device_id: state for state in (await db.scalars(select(DevicePostureState))).all()
    }
    attribute_rows = (
        await db.scalars(
            select(DevicePostureAttribute)
            .where(DevicePostureAttribute.present.is_(True))
            .order_by(DevicePostureAttribute.device_id, DevicePostureAttribute.key)
        )
    ).all()
    attributes_by_device: dict[str, list[DevicePostureAttribute]] = {}
    for attribute_row in attribute_rows:
        attributes_by_device.setdefault(attribute_row.device_id, []).append(attribute_row)
    result = []
    for current_device, metadata, owner in rows:
        item = device_dict(current_device, metadata, owner)
        item["posture"] = await _posture_payload(
            db,
            current_device,
            snapshot,
            preloaded_state=states.get(current_device.id),
            preloaded_attributes=attributes_by_device.get(current_device.id, []),
            preloaded=True,
        )
        result.append(item)
    return result


@router.get("/security/posture")
async def security_posture(_: Authed, db: Db) -> dict[str, Any]:
    devices = await _security_device_rows(db)
    capability = await db.get(Capability, "device_posture")
    counts = {
        "pass": 0,
        "fail": 0,
        "incomplete": 0,
        "stale": 0,
        "pending_approval": 0,
        "expiring_attributes": 0,
    }
    namespace_counts: dict[str, int] = {}
    attribute_counts: dict[str, int] = {}
    auto_update: dict[str, int] = {}
    release_tracks: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    for item in devices:
        posture = item["posture"]
        status_value = posture["status"]
        if status_value in {"pass", "fail"}:
            counts[status_value] += 1
        elif status_value == "incomplete_data":
            counts["incomplete"] += 1
        if posture["stale"]:
            counts["stale"] += 1
            findings.append(
                {
                    "severity": "medium",
                    "kind": "stale_evidence",
                    "device_id": item["id"],
                    "device": item["name"],
                    "message": (
                        "Last-good posture evidence is stale; no pass/fail conclusion is made."
                    ),
                }
            )
        if item["authorized"] is False:
            counts["pending_approval"] += 1
            findings.append(
                {
                    "severity": "high",
                    "kind": "unauthorized_device",
                    "device_id": item["id"],
                    "device": item["name"],
                    "message": "The device API reports this device as not authorized.",
                }
            )
        for attribute in posture["attributes"]:
            key = str(attribute["key"])
            namespace = str(attribute["namespace"])
            attribute_counts[key] = attribute_counts.get(key, 0) + 1
            namespace_counts[namespace] = namespace_counts.get(namespace, 0) + 1
            if attribute["expiry_state"] == "expiring":
                counts["expiring_attributes"] += 1
                findings.append(
                    {
                        "severity": "medium",
                        "kind": "expiring_attribute",
                        "device_id": item["id"],
                        "device": item["name"],
                        "attribute": key,
                        "expiry": attribute["expiry"],
                        "message": "A temporary posture attribute expires within seven days.",
                    }
                )
            if key == "node:tsAutoUpdate":
                label = str(attribute["value"])
                auto_update[label] = auto_update.get(label, 0) + 1
            if key == "node:tsReleaseTrack":
                label = str(attribute["value"])
                release_tracks[label] = release_tracks.get(label, 0) + 1
        if status_value == "fail":
            findings.append(
                {
                    "severity": "high",
                    "kind": "posture_failure",
                    "device_id": item["id"],
                    "device": item["name"],
                    "message": "One or more current policy postures fail for this device.",
                }
            )
    device_total = len(devices)
    return {
        "counts": {"devices": device_total, **counts},
        "coverage": {
            "devices_with_fresh_evidence": sum(
                1 for item in devices if item["posture"]["evidence_status"] == "available"
            ),
            "percent": round(
                100
                * sum(1 for item in devices if item["posture"]["evidence_status"] == "available")
                / device_total,
                1,
            )
            if device_total
            else 0,
        },
        "attribute_coverage": [
            {"key": key, "device_count": count, "percent": round(count * 100 / device_total, 1)}
            for key, count in sorted(attribute_counts.items(), key=lambda pair: (-pair[1], pair[0]))
        ]
        if device_total
        else [],
        "namespaces": namespace_counts,
        "auto_update": auto_update,
        "release_tracks": release_tracks,
        "findings": findings[:500],
        "capability": {
            "status": capability.status if capability else "unknown",
            "detail": capability.detail if capability else "Not synchronized yet",
            "last_success": capability.last_success if capability else None,
            "required_scope": "devices:posture_attributes:read or all:read",
        },
        "limitations": [
            "Posture conclusions use current policy and current device evidence only.",
            "Shared-node and subnet-routed source applicability may be incomplete.",
            (
                "Fleet-relative versions are displayed without claiming they are vulnerable "
                "or outdated."
            ),
        ],
    }


@router.get("/security/posture/devices")
async def security_posture_devices(
    _: Authed,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    result: str = "",
    posture: str = "",
    attribute: str = "",
    owner: str = "",
    os: str = "",
    expiry: str = "",
    stale: bool | None = None,
) -> dict[str, Any]:
    items = await _security_device_rows(db)
    filtered = []
    for item in items:
        details = item["posture"]
        attributes = details["attributes"]
        evaluations = details["evaluations"]
        if result and details["status"] != result:
            continue
        if posture and not any(evaluation["name"] == posture for evaluation in evaluations):
            continue
        if attribute and not any(
            attribute.casefold() in value["key"].casefold() for value in attributes
        ):
            continue
        owner_text = " ".join(
            filter(None, [item["owner_display_name"], item["owner_login_name"], item["owner_id"]])
        )
        if owner and owner.casefold() not in owner_text.casefold():
            continue
        if os and os.casefold() not in str(item["os"]).casefold():
            continue
        if expiry and not any(value["expiry_state"] == expiry for value in attributes):
            continue
        if stale is not None and details["stale"] is not stale:
            continue
        filtered.append(item)
    start = 0
    cursor_data = decode_cursor(cursor, "posture_devices")
    if cursor_data:
        cursor_key = (str(cursor_data.get("name", "")), str(cursor_data.get("id", "")))
        start = next(
            (
                index
                for index, item in enumerate(filtered)
                if (str(item["name"]).casefold(), str(item["id"])) > cursor_key
            ),
            len(filtered),
        )
    page = filtered[start : start + limit]
    next_cursor = None
    if start + limit < len(filtered) and page:
        last = page[-1]
        next_cursor = encode_cursor(
            "posture_devices", {"name": str(last["name"]).casefold(), "id": last["id"]}
        )
    return {"items": page, "next_cursor": next_cursor, "total": len(filtered)}


@router.get("/security/posture/integrations")
async def security_posture_integrations(_: Authed, db: Db) -> dict[str, Any]:
    capability = await db.get(Capability, "posture_integrations")
    rows = (
        await db.scalars(
            select(PostureIntegration)
            .where(PostureIntegration.present.is_(True))
            .order_by(PostureIntegration.name, PostureIntegration.id)
        )
    ).all()
    return {
        "items": [
            {
                "id": row.id,
                "name": row.name,
                "provider": row.provider,
                "status": row.status,
                "synced_at": row.synced_at,
                "provenance": "tailscale_posture_integrations_api",
            }
            for row in rows
        ],
        "capability_status": capability.status if capability else "unknown",
    }


@router.get("/security/settings")
async def security_settings(_: Authed, db: Db) -> dict[str, Any]:
    row = await db.get(TailnetSecuritySettings, "current")
    capability = await db.get(Capability, "tailnet_settings")
    return {
        "available": row is not None,
        "values": row.values if row else {},
        "synced_at": row.synced_at if row else None,
        "capability_status": capability.status if capability else "unknown",
        "provenance": "tailscale_tailnet_feature_settings_api",
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
        "posture": sync_posture,
        "posture_integrations": sync_posture_integrations,
        "tailnet_settings": sync_tailnet_settings,
        "credentials": sync_credentials,
        "device_invites": sync_device_invites,
        "contacts": sync_contacts,
        "log_streaming": sync_log_streaming,
    }
    if kind in {"flows", "audit"}:
        await sync_logs(kind)
        await evaluate_findings_job()
        return {"status": "completed", "kind": kind}
    synchronize = synchronizers.get(kind)
    if synchronize is None:
        raise HTTPException(404, "Unknown synchronization source")
    await synchronize()
    await evaluate_findings_job()
    return {"status": "completed", "kind": kind}


@router.get("/settings/dns")
async def dns_settings(_: Admin, db: Db) -> dict[str, Any]:
    row = await db.get(DnsConfiguration, "current")
    capability = await db.get(Capability, "dns")
    capability_fields = {
        "status": capability.status if capability else "unknown",
        "source": capability.source if capability else "Tailscale DNS API",
        "required_scope": capability.requirement if capability else "dns:read",
        "detail": capability.detail if capability else "",
        "checked_at": capability.checked_at if capability else None,
        "last_success": capability.last_success if capability else None,
    }
    if row is None:
        return {"available": False, "stale": False, **capability_fields}
    return {
        "available": True,
        "stale": bool(capability and capability.status != "available"),
        "magic_dns": row.magic_dns,
        "override_local_dns": row.override_local_dns,
        "nameservers": row.nameservers,
        "search_paths": row.search_paths,
        "split_dns": row.split_dns,
        "synced_at": row.synced_at,
        **capability_fields,
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
