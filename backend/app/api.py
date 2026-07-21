from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import auth
from .config import Settings, get_settings
from .db import get_db
from .demo import seed_demo
from .models import (
    AppUser,
    AuditEvent,
    Capability,
    Credential,
    Device,
    Flow,
    LocalMetadata,
    PolicySnapshot,
    SyncJob,
    TailnetUser,
    TelemetryObservation,
)
from .policy import evaluate_policy, review_policy
from .schemas import CredentialRequest, LoginRequest, MetadataUpdate, SetupRequest, UserResponse
from .security import SecretBox
from .sync import sync_inventory, sync_logs, sync_policy

router = APIRouter(prefix="/api/v1")
Db = Annotated[AsyncSession, Depends(get_db)]
Authed = Annotated[AppUser, Depends(auth.current_user)]
Admin = Annotated[AppUser, Depends(auth.administrator)]
Csrf = Annotated[None, Depends(auth.enforce_csrf)]


def encode_cursor(value: int) -> str:
    return base64.urlsafe_b64encode(str(value).encode()).decode()


def decode_cursor(value: str | None) -> int:
    if not value:
        return 0
    try:
        return max(0, int(base64.urlsafe_b64decode(value).decode()))
    except Exception as exc:
        raise HTTPException(400, "Invalid cursor") from exc


def device_dict(device: Device, metadata: LocalMetadata | None = None) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": metadata.display_name if metadata and metadata.display_name else device.name,
        "source_name": device.name,
        "hostname": device.hostname,
        "os": device.os,
        "version": device.version,
        "owner_id": device.owner_id,
        "online": device.online,
        "authorized": device.authorized,
        "last_seen": device.last_seen,
        "created": device.created,
        "key_expiry": device.key_expiry,
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
async def dashboard(_: Authed, db: Db) -> dict[str, Any]:
    device_count = (await db.scalar(select(func.count()).select_from(Device))) or 0
    online = (
        await db.scalar(select(func.count()).select_from(Device).where(Device.online.is_(True)))
    ) or 0
    users = (await db.scalar(select(func.count()).select_from(TailnetUser))) or 0
    flows = (await db.scalar(select(func.count()).select_from(Flow))) or 0
    cutoff = datetime.now(UTC) + timedelta(days=14)
    expiring = (
        await db.scalar(
            select(func.count())
            .select_from(Device)
            .where(Device.key_expiry.is_not(None), Device.key_expiry < cutoff)
        )
    ) or 0
    roles = (
        await db.execute(select(Device.primary_role, func.count()).group_by(Device.primary_role))
    ).all()
    os_rows = (await db.execute(select(Device.os, func.count()).group_by(Device.os))).all()
    top_pairs = (
        await db.execute(
            select(
                Flow.source_device_id,
                Flow.destination_device_id,
                func.sum(Flow.tx_bytes + Flow.rx_bytes).label("bytes"),
            )
            .group_by(Flow.source_device_id, Flow.destination_device_id)
            .order_by(desc("bytes"))
            .limit(5)
        )
    ).all()
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
            {"source": s, "destination": d, "reported_bytes": b or 0} for s, d, b in top_pairs
        ],
        "generated_at": datetime.now(UTC),
        "traffic_label": "Reported bytes; peer reports may overlap",
    }


@router.get("/devices")
async def devices(
    _: Authed,
    db: Db,
    cursor: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    search: str = "",
    role: str = "",
) -> dict[str, Any]:
    offset = decode_cursor(cursor)
    query = select(Device, LocalMetadata).outerjoin(LocalMetadata).order_by(Device.name)
    if search:
        query = query.where(
            or_(
                Device.name.ilike(f"%{search}%"),
                Device.hostname.ilike(f"%{search}%"),
                Device.os.ilike(f"%{search}%"),
            )
        )
    if role:
        query = query.where(Device.primary_role == role)
    rows = (await db.execute(query.offset(offset).limit(limit + 1))).all()
    return {
        "items": [device_dict(d, m) for d, m in rows[:limit]],
        "next_cursor": encode_cursor(offset + limit) if len(rows) > limit else None,
    }


@router.get("/devices/{device_id}")
async def device(device_id: str, _: Authed, db: Db) -> dict[str, Any]:
    row = (
        await db.execute(
            select(Device, LocalMetadata).outerjoin(LocalMetadata).where(Device.id == device_id)
        )
    ).first()
    if not row:
        raise HTTPException(404, "Device not found")
    item = device_dict(row[0], row[1])
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
    item["flows"] = [
        {
            "id": f.id,
            "source": f.source_device_id,
            "destination": f.destination_device_id,
            "category": f.category,
            "protocol": f.protocol,
            "destination_port": f.destination_port,
            "reported_bytes": f.tx_bytes + f.rx_bytes,
            "start": f.start,
            "end": f.end,
            "provenance": "demo" if f.raw.get("demo") else "network_flow_logs",
        }
        for f in flows
    ]
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
async def services(_: Authed, db: Db) -> dict[str, Any]:
    # Service objects are retained in policy snapshots until the official service
    # inventory adapter has synchronized a dedicated response for this tailnet.
    snapshot = await db.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    services: set[str] = set()
    if snapshot:
        for rule in snapshot.normalized.get("grants", []):
            services.update(
                str(value) for value in rule.get("dst", []) if str(value).startswith("svc:")
            )
    return {
        "items": [
            {
                "name": name,
                "status": "policy_reference_only",
                "source": "tailnet_policy",
                "detail": "Host inventory is not yet synchronized or unavailable",
            }
            for name in sorted(services)
        ],
        "next_cursor": None,
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
    hours: int = Query(24, ge=1, le=24 * 30),
) -> dict[str, Any]:
    offset = decode_cursor(cursor)
    query = (
        select(Flow)
        .where(Flow.start >= datetime.now(UTC) - timedelta(hours=hours))
        .order_by(Flow.start.desc())
    )
    if source:
        query = query.where(or_(Flow.source_device_id == source, Flow.source.ilike(f"%{source}%")))
    if destination:
        query = query.where(
            or_(
                Flow.destination_device_id == destination,
                Flow.destination.ilike(f"%{destination}%"),
            )
        )
    if category:
        query = query.where(Flow.category == category)
    rows = (await db.execute(query.offset(offset).limit(limit + 1))).scalars().all()
    items = [
        {
            "id": f.id,
            "source": f.source_device_id or f.source,
            "destination": f.destination_device_id or f.destination or "Destination not logged",
            "protocol": f.protocol,
            "source_port": f.source_port,
            "destination_port": f.destination_port,
            "category": f.category,
            "reported_bytes": f.tx_bytes + f.rx_bytes,
            "reported_packets": f.tx_packets + f.rx_packets,
            "start": f.start,
            "end": f.end,
            "reporting_node": f.reporting_node_id,
            "provenance": "demo" if f.raw.get("demo") else "network_flow_logs",
        }
        for f in rows[:limit]
    ]
    return {
        "items": items,
        "next_cursor": encode_cursor(offset + limit) if len(rows) > limit else None,
        "notice": (
            "Historical client-reported windows, not active sessions. Peer reports can overlap."
        ),
    }


@router.get("/flows/export.{format}")
async def export_flows(format: str, _: Authed, db: Db) -> StreamingResponse:
    if format not in {"csv", "json"}:
        raise HTTPException(404, "Unsupported export format")
    rows = (await db.execute(select(Flow).order_by(Flow.start.desc()).limit(10000))).scalars().all()
    if format == "json":
        body = json.dumps(
            [
                {
                    "source": f.source_device_id or f.source,
                    "destination": f.destination_device_id or f.destination,
                    "category": f.category,
                    "protocol": f.protocol,
                    "reported_bytes": f.tx_bytes + f.rx_bytes,
                    "start": f.start.isoformat(),
                }
                for f in rows
            ]
        )
        return StreamingResponse(
            iter([body]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=tailview-flows.json"},
        )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["source", "destination", "category", "protocol", "reported_bytes", "start"])
    for flow in rows:
        writer.writerow(
            [
                flow.source_device_id or flow.source,
                flow.destination_device_id or flow.destination,
                flow.category,
                flow.protocol or "",
                flow.tx_bytes + flow.rx_bytes,
                flow.start.isoformat(),
            ]
        )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tailview-flows.csv"},
    )


@router.get("/topology")
async def topology(
    _: Authed, db: Db, hours: int = Query(24, ge=1, le=720), hide_inactive: bool = False
) -> dict[str, Any]:
    query = select(Device, LocalMetadata).outerjoin(LocalMetadata)
    if hide_inactive:
        query = query.where(Device.online.is_(True))
    rows = (await db.execute(query)).all()
    nodes = [device_dict(d, m) for d, m in rows if not (m and m.hidden)]
    node_ids = {n["id"] for n in nodes}
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
    if kind == "inventory":
        await sync_inventory()
    elif kind == "policy":
        await sync_policy()
    elif kind in {"flows", "audit"}:
        await sync_logs(kind)
    else:
        raise HTTPException(404, "Unknown synchronization source")
    return {"status": "completed", "kind": kind}


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
