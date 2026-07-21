from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import HTTPException
from sqlalchemy import and_, func, or_, select, text, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Device, Flow, LocalMetadata

ALLOWED_HOURS = {1, 24, 168, 720}
ALLOWED_CATEGORIES = {"virtual", "subnet", "exit", "physical"}
Resolution = Literal["all", "resolved", "unresolved"]


@dataclass(frozen=True)
class FlowFilters:
    hours: int = 24
    source: str = ""
    destination: str = ""
    category: str = ""
    protocol: int | None = None
    port: int | None = None
    resolution: Resolution = "all"


def validate_flow_filters(filters: FlowFilters) -> FlowFilters:
    if filters.hours not in ALLOWED_HOURS:
        raise HTTPException(422, "hours must be one of 1, 24, 168, or 720")
    if filters.category and filters.category not in ALLOWED_CATEGORIES:
        raise HTTPException(422, "Unsupported flow category")
    if filters.protocol is not None and not 0 <= filters.protocol <= 255:
        raise HTTPException(422, "protocol must be between 0 and 255")
    if filters.port is not None and not 1 <= filters.port <= 65535:
        raise HTTPException(422, "port must be between 1 and 65535")
    if filters.resolution not in {"all", "resolved", "unresolved"}:
        raise HTTPException(422, "resolution must be all, resolved, or unresolved")
    if len(filters.source) > 255 or len(filters.destination) > 255:
        raise HTTPException(422, "source and destination filters must not exceed 255 characters")
    return filters


def encode_cursor(kind: str, payload: dict[str, Any]) -> str:
    data = {"v": 1, "kind": kind, **payload}
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str | None, kind: str) -> dict[str, Any] | None:
    if not value:
        return None
    if len(value) > 2048:
        raise HTTPException(400, "Invalid cursor")
    try:
        padded = value + "=" * (-len(value) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        if not isinstance(data, dict) or data.get("v") != 1 or data.get("kind") != kind:
            raise ValueError("wrong cursor kind or version")
        return data
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, "Invalid cursor") from exc


def flow_cutoff(now: datetime, hours: int) -> datetime:
    return now - timedelta(hours=hours)


def apply_flow_filters(statement: Any, filters: FlowFilters, now: datetime) -> Any:
    filters = validate_flow_filters(filters)
    statement = statement.where(Flow.start >= flow_cutoff(now, filters.hours))
    if filters.source:
        pattern = f"%{filters.source}%"
        matching_devices = (
            select(Device.id)
            .outerjoin(LocalMetadata)
            .where(
                or_(
                    Device.id == filters.source,
                    Device.name.ilike(pattern),
                    Device.hostname.ilike(pattern),
                    LocalMetadata.display_name.ilike(pattern),
                )
            )
        )
        statement = statement.where(
            or_(
                Flow.source_device_id == filters.source,
                Flow.source.ilike(pattern),
                Flow.source_device_id.in_(matching_devices),
            )
        )
    if filters.destination:
        pattern = f"%{filters.destination}%"
        matching_devices = (
            select(Device.id)
            .outerjoin(LocalMetadata)
            .where(
                or_(
                    Device.id == filters.destination,
                    Device.name.ilike(pattern),
                    Device.hostname.ilike(pattern),
                    LocalMetadata.display_name.ilike(pattern),
                )
            )
        )
        statement = statement.where(
            or_(
                Flow.destination_device_id == filters.destination,
                Flow.destination.ilike(pattern),
                Flow.destination_device_id.in_(matching_devices),
            )
        )
    if filters.category:
        statement = statement.where(Flow.category == filters.category)
    if filters.protocol is not None:
        statement = statement.where(Flow.protocol == filters.protocol)
    if filters.port is not None:
        statement = statement.where(
            or_(Flow.source_port == filters.port, Flow.destination_port == filters.port)
        )
    if filters.resolution == "resolved":
        statement = statement.where(
            Flow.source_device_id.is_not(None), Flow.destination_device_id.is_not(None)
        )
    elif filters.resolution == "unresolved":
        statement = statement.where(
            or_(Flow.source_device_id.is_(None), Flow.destination_device_id.is_(None))
        )
    return statement


def bucket_seconds(hours: int) -> int:
    return {1: 300, 24: 3600, 168: 21600, 720: 86400}[hours]


def _aligned_bucket(value: datetime, seconds: int) -> datetime:
    timestamp = int(value.timestamp())
    return datetime.fromtimestamp(timestamp - timestamp % seconds, tz=UTC)


def fill_series(
    rows: list[tuple[datetime, int, int, int]],
    *,
    now: datetime,
    hours: int,
) -> list[dict[str, Any]]:
    seconds = bucket_seconds(hours)
    values = {
        _aligned_bucket(bucket, seconds): (reported_bytes, reported_packets, record_count)
        for bucket, reported_bytes, reported_packets, record_count in rows
    }
    current = _aligned_bucket(flow_cutoff(now, hours), seconds)
    final = _aligned_bucket(now, seconds)
    result: list[dict[str, Any]] = []
    while current <= final:
        reported_bytes, reported_packets, record_count = values.get(current, (0, 0, 0))
        result.append(
            {
                "bucket_start": current,
                "reported_bytes": reported_bytes,
                "reported_packets": reported_packets,
                "record_count": record_count,
            }
        )
        current += timedelta(seconds=seconds)
    return result


async def flow_summary_series(
    db: AsyncSession,
    filters: FlowFilters,
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    filters = validate_flow_filters(filters)
    seconds = bucket_seconds(filters.hours)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        bucket = func.date_bin(
            text(f"INTERVAL '{seconds} seconds'"),
            Flow.start,
            datetime(1970, 1, 1, tzinfo=UTC),
        ).label("bucket_start")
        statement = (
            select(
                bucket,
                func.sum(Flow.tx_bytes + Flow.rx_bytes),
                func.sum(Flow.tx_packets + Flow.rx_packets),
                func.count(Flow.id),
            )
            .group_by(bucket)
            .order_by(bucket)
        )
        statement = apply_flow_filters(statement, filters, now)
        raw_rows = (await db.execute(statement)).all()
        rows = [
            (bucket_start, int(byte_count or 0), int(packet_count or 0), int(record_count or 0))
            for bucket_start, byte_count, packet_count, record_count in raw_rows
        ]
    else:
        statement = apply_flow_filters(
            select(
                Flow.start,
                Flow.tx_bytes + Flow.rx_bytes,
                Flow.tx_packets + Flow.rx_packets,
            ),
            filters,
            now,
        )
        raw_rows = (await db.execute(statement)).all()
        aggregated: dict[datetime, tuple[int, int, int]] = {}
        for started_at, byte_count, packet_count in raw_rows:
            bucket_start = _aligned_bucket(started_at, seconds)
            old_bytes, old_packets, old_count = aggregated.get(bucket_start, (0, 0, 0))
            aggregated[bucket_start] = (
                old_bytes + int(byte_count or 0),
                old_packets + int(packet_count or 0),
                old_count + 1,
            )
        rows = [(key, *value) for key, value in sorted(aggregated.items())]
    return fill_series(rows, now=now, hours=filters.hours)


async def flow_device_ranking(
    db: AsyncSession,
    filters: FlowFilters,
    *,
    now: datetime,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Rank resolved endpoint devices by reported volume across matching flow windows."""
    volume = (Flow.tx_bytes + Flow.rx_bytes).label("reported_bytes")
    packets = (Flow.tx_packets + Flow.rx_packets).label("reported_packets")
    source = apply_flow_filters(
        select(
            Flow.source_device_id.label("device_id"),
            volume,
            packets,
        ).where(Flow.source_device_id.is_not(None)),
        filters,
        now,
    )
    destination = apply_flow_filters(
        select(
            Flow.destination_device_id.label("device_id"),
            volume,
            packets,
        ).where(
            Flow.destination_device_id.is_not(None),
            or_(
                Flow.source_device_id.is_(None),
                Flow.destination_device_id != Flow.source_device_id,
            ),
        ),
        filters,
        now,
    )
    endpoints = union_all(source, destination).subquery()
    statement = (
        select(
            endpoints.c.device_id,
            func.sum(endpoints.c.reported_bytes).label("reported_bytes"),
            func.sum(endpoints.c.reported_packets).label("reported_packets"),
            func.count().label("record_count"),
        )
        .group_by(endpoints.c.device_id)
        .order_by(func.sum(endpoints.c.reported_bytes).desc(), endpoints.c.device_id)
        .limit(limit)
    )
    rows = (await db.execute(statement)).all()
    return [
        {
            "device_id": device_id,
            "reported_bytes": int(reported_bytes or 0),
            "reported_packets": int(reported_packets or 0),
            "record_count": int(record_count or 0),
        }
        for device_id, reported_bytes, reported_packets, record_count in rows
    ]


def flow_keyset_condition(cursor: dict[str, Any]) -> Any:
    try:
        started_at = datetime.fromisoformat(str(cursor["start"]))
        flow_id = int(cursor["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    return or_(Flow.start < started_at, and_(Flow.start == started_at, Flow.id < flow_id))
