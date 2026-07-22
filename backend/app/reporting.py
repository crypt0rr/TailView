from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import uuid
import zipfile
from collections import defaultdict
from datetime import UTC, datetime, time, timedelta
from typing import Any
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import structlog
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db import SessionLocal, engine
from .models import (
    Device,
    Flow,
    FlowAggregate,
    FlowAggregateState,
    LocalMetadata,
    ReportArtifact,
    ReportRun,
    ReportSchedule,
    SavedView,
    SyncJob,
    TailnetService,
    TailnetUser,
)
from .saved_views import compatible_state

log = structlog.get_logger()
RANGE_HOURS = {"24h": 24, "7d": 168, "30d": 720, "90d": 2160, "13mo": 9600}
REPORT_SCHEMA_VERSION = "2"
REPORT_SECTIONS = (
    "trends",
    "devices",
    "pairs",
    "services",
    "protocols",
    "ports",
    "categories",
    "resolution",
    "fleet_context",
)
DEFAULT_REPORT_OPTIONS: dict[str, Any] = {
    "description": "",
    "ranking_limit": 10,
    "include_previous_period": True,
    "sections": list(REPORT_SECTIONS),
}


def normalize_report_options(value: dict[str, Any] | None) -> dict[str, Any]:
    value = value or {}
    try:
        ranking_limit = int(value.get("ranking_limit", 10))
    except (TypeError, ValueError):
        ranking_limit = 10
    sections = [
        section for section in value.get("sections", REPORT_SECTIONS) if section in REPORT_SECTIONS
    ]
    return {
        "description": str(value.get("description", ""))[:500],
        "ranking_limit": ranking_limit if ranking_limit in {5, 10, 20} else 10,
        "include_previous_period": bool(value.get("include_previous_period", True)),
        "sections": list(dict.fromkeys(sections)) or list(REPORT_SECTIONS),
    }


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def iso_aware(value: datetime | None) -> str | None:
    normalized = aware(value)
    return normalized.isoformat() if normalized else None


def floor_bucket(value: datetime, granularity: str) -> datetime:
    value = value.astimezone(UTC)
    if granularity == "daily":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    return value.replace(minute=0, second=0, microsecond=0)


def bucket_step(granularity: str) -> timedelta:
    return timedelta(days=1) if granularity == "daily" else timedelta(hours=1)


async def _service_addresses(session: AsyncSession) -> dict[str, str]:
    services = (
        await session.scalars(select(TailnetService).where(TailnetService.present.is_(True)))
    ).all()
    return {address: service.id for service in services for address in service.addresses}


async def rebuild_aggregate_range(
    session: AsyncSession,
    granularity: str,
    start: datetime,
    end: datetime,
) -> int:
    """Replace complete buckets in a bounded range so late records remain correct."""
    start, end = floor_bucket(start, granularity), floor_bucket(end, granularity)
    if end <= start:
        return 0
    await session.execute(
        delete(FlowAggregate)
        .where(
            FlowAggregate.granularity == granularity,
            FlowAggregate.bucket_start >= start,
            FlowAggregate.bucket_start < end,
        )
        .execution_options(synchronize_session=False)
    )
    rows = (
        await session.execute(
            select(
                Flow.start,
                Flow.source_device_id,
                Flow.destination_device_id,
                Flow.source,
                Flow.destination,
                Flow.category,
                Flow.protocol,
                Flow.source_port,
                Flow.destination_port,
                Flow.tx_bytes + Flow.rx_bytes,
                Flow.tx_packets + Flow.rx_packets,
            ).where(Flow.start >= start, Flow.start < end)
        )
    ).all()
    service_addresses = await _service_addresses(session)
    grouped: dict[tuple[Any, ...], list[int]] = {}
    for row in rows:
        (
            started,
            source_id,
            destination_id,
            source_raw,
            destination_raw,
            category,
            protocol,
            source_port,
            destination_port,
            byte_count,
            packet_count,
        ) = row
        key = (
            floor_bucket(started, granularity),
            source_id or "",
            destination_id or "",
            source_raw or "",
            destination_raw or "",
            service_addresses.get(source_raw or "", "") if not source_id else "",
            service_addresses.get(destination_raw or "", "") if not destination_id else "",
            category or "unknown",
            int(protocol) if protocol is not None else -1,
            int(source_port) if source_port is not None else -1,
            int(destination_port) if destination_port is not None else -1,
            bool(source_id and destination_id),
        )
        totals = grouped.setdefault(key, [0, 0, 0])
        totals[0] += int(byte_count or 0)
        totals[1] += int(packet_count or 0)
        totals[2] += 1
    now = datetime.now(UTC)
    session.add_all(
        [
            FlowAggregate(
                granularity=granularity,
                bucket_start=key[0],
                source_device_id=key[1],
                destination_device_id=key[2],
                source_raw=key[3],
                destination_raw=key[4],
                source_service_id=key[5],
                destination_service_id=key[6],
                category=key[7],
                protocol=key[8],
                source_port=key[9],
                destination_port=key[10],
                resolved=key[11],
                reported_bytes=totals[0],
                reported_packets=totals[1],
                record_count=totals[2],
                updated_at=now,
            )
            for key, totals in grouped.items()
        ]
    )
    await session.flush()
    return len(grouped)


async def update_flow_aggregates(
    session: AsyncSession, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(UTC)
    earliest = await session.scalar(select(func.min(Flow.start)))
    if earliest is None:
        return {"hourly": 0, "daily": 0}
    counts: dict[str, int] = {}
    for granularity, overlap in (("hourly", timedelta(hours=3)), ("daily", timedelta(days=2))):
        state = await session.get(FlowAggregateState, granularity)
        if state is None:
            state = FlowAggregateState(granularity=granularity)
            session.add(state)
        rebuild_start = max(earliest, now - overlap) if state.last_success else earliest
        processed_start = floor_bucket(rebuild_start, granularity)
        current = processed_start
        final = floor_bucket(now, granularity) + bucket_step(granularity)
        count = 0
        chunk = timedelta(days=1 if granularity == "hourly" else 7)
        try:
            while current < final:
                chunk_end = min(current + chunk, final)
                count += await rebuild_aggregate_range(session, granularity, current, chunk_end)
                current = chunk_end
            previous_start = aware(state.coverage_start)
            previous_end = aware(state.coverage_end)
            state.coverage_start = (
                min(previous_start, processed_start) if previous_start else processed_start
            )
            state.coverage_end = max(previous_end, final) if previous_end else final
            state.last_success = now
            state.last_error = ""
            counts[granularity] = count
        except Exception as exc:
            state.last_error = f"Aggregation failed ({type(exc).__name__})"
            raise
    await session.commit()
    return counts


async def cleanup_flow_data(session: AsyncSession, settings: Settings, now: datetime) -> None:
    hourly_cutoff = floor_bucket(
        now - timedelta(days=settings.flow_hourly_aggregate_retention_days), "hourly"
    )
    daily_cutoff = floor_bucket(
        now - timedelta(days=settings.flow_daily_aggregate_retention_days), "daily"
    )
    await session.execute(
        delete(FlowAggregate).where(
            or_(
                (FlowAggregate.granularity == "hourly")
                & (FlowAggregate.bucket_start < hourly_cutoff),
                (FlowAggregate.granularity == "daily")
                & (FlowAggregate.bucket_start < daily_cutoff),
            )
        )
    )
    raw_cutoff = now - timedelta(days=settings.flow_retention_days)
    states = {
        state.granularity: state
        for state in (await session.scalars(select(FlowAggregateState))).all()
    }

    def covers_cutoff(state: FlowAggregateState | None) -> bool:
        if state is None or state.last_success is None:
            return False
        start, end = aware(state.coverage_start), aware(state.coverage_end)
        return bool(start and end and start <= raw_cutoff <= end)

    if all(covers_cutoff(states.get(name)) for name in ("hourly", "daily")):
        await session.execute(delete(Flow).where(Flow.start < raw_cutoff))
    await session.commit()


def validate_timezone(value: str) -> ZoneInfo:
    try:
        return ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise ValueError("Unknown IANA timezone") from exc


def next_schedule_time(schedule: ReportSchedule, after: datetime) -> datetime:
    zone = validate_timezone(schedule.timezone)
    hour, minute = (int(part) for part in schedule.local_time.split(":"))
    local_after = after.astimezone(zone)
    for offset in range(0, 401):
        candidate_date = local_after.date() + timedelta(days=offset)
        allowed = schedule.frequency == "daily"
        if schedule.frequency == "weekly":
            allowed = candidate_date.weekday() == (schedule.weekday or 0)
        elif schedule.frequency == "monthly":
            allowed = candidate_date.day == (schedule.month_day or 1)
        if not allowed:
            continue
        candidate = datetime.combine(candidate_date, time(hour, minute), zone)
        # A nonexistent DST wall time is shifted to the first valid minute.
        for _ in range(121):
            roundtrip = candidate.astimezone(UTC).astimezone(zone)
            if (roundtrip.hour, roundtrip.minute) == (candidate.hour, candidate.minute):
                break
            candidate += timedelta(minutes=1)
        value = candidate.astimezone(UTC)
        if value > after:
            return value
    raise ValueError("Unable to calculate next report execution")


def report_period(frequency: str, end: datetime) -> tuple[datetime, datetime]:
    duration = {
        "daily": timedelta(days=1),
        "weekly": timedelta(days=7),
        "monthly": timedelta(days=30),
    }[frequency]
    return end - duration, end


async def _label_maps(session: AsyncSession) -> tuple[dict[str, str], dict[str, str]]:
    device_rows = (
        await session.execute(
            select(Device.id, Device.name, LocalMetadata.display_name).outerjoin(LocalMetadata)
        )
    ).all()
    devices = {
        device_id: local_name or name or device_id for device_id, name, local_name in device_rows
    }
    services = {
        service_id: name
        for service_id, name in (
            await session.execute(select(TailnetService.id, TailnetService.name))
        ).all()
    }
    return devices, services


def _aggregate_matches(
    row: FlowAggregate, filters: dict[str, Any], device_labels: dict[str, str]
) -> bool:
    if filters.get("category") and row.category != filters["category"]:
        return False
    if filters.get("protocol") not in (None, "") and row.protocol != int(filters["protocol"]):
        return False
    if filters.get("port") not in (None, "") and int(filters["port"]) not in {
        row.source_port,
        row.destination_port,
    }:
        return False
    resolution = filters.get("resolution", "all")
    if resolution == "resolved" and not row.resolved:
        return False
    if resolution == "unresolved" and row.resolved:
        return False
    for side in ("source", "destination"):
        term = str(filters.get(side, "")).casefold()
        if not term:
            continue
        device_id = getattr(row, f"{side}_device_id")
        raw = getattr(row, f"{side}_raw")
        if term not in " ".join((device_id, raw, device_labels.get(device_id, ""))).casefold():
            return False
    return True


def _rank(
    values: dict[str, list[int]], labels: dict[str, str], limit: int = 20
) -> list[dict[str, Any]]:
    return [
        {
            "id": key,
            "name": labels.get(key, key or "Unresolved"),
            "reported_bytes": totals[0],
            "reported_packets": totals[1],
            "record_count": totals[2],
        }
        for key, totals in sorted(values.items(), key=lambda item: (-item[1][0], item[0]))[:limit]
    ]


async def aggregate_report_data(
    session: AsyncSession,
    start: datetime,
    end: datetime,
    filters: dict[str, Any],
    ranking_limit: int = 20,
) -> dict[str, Any]:
    granularity = "daily" if end - start > timedelta(days=90) else "hourly"
    rows = (
        await session.scalars(
            select(FlowAggregate).where(
                FlowAggregate.granularity == granularity,
                FlowAggregate.bucket_start >= floor_bucket(start, granularity),
                FlowAggregate.bucket_start < end,
            )
        )
    ).all()
    devices, services = await _label_maps(session)
    rows = [row for row in rows if _aggregate_matches(row, filters, devices)]
    series: dict[datetime, list[int]] = defaultdict(lambda: [0, 0, 0])
    top_devices: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    top_pairs: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    top_services: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    distributions: dict[str, dict[str, list[int]]] = {
        name: defaultdict(lambda: [0, 0, 0])
        for name in ("categories", "protocols", "ports", "resolution")
    }
    totals = [0, 0, 0]
    for row in rows:
        values = [row.reported_bytes, row.reported_packets, row.record_count]
        for index, value in enumerate(values):
            totals[index] += value
            series[row.bucket_start][index] += value
        endpoint_ids = [row.source_device_id, row.destination_device_id]
        for device_id in {value for value in endpoint_ids if value}:
            for index, value in enumerate(values):
                top_devices[device_id][index] += value
        source_label = (
            devices.get(row.source_device_id, row.source_device_id)
            if row.source_device_id
            else row.source_raw or "unresolved"
        )
        destination_label = (
            devices.get(row.destination_device_id, row.destination_device_id)
            if row.destination_device_id
            else row.destination_raw or "unresolved"
        )
        pair_key = f"{source_label} → {destination_label}"
        for index, value in enumerate(values):
            top_pairs[pair_key][index] += value
        for service_id in {row.source_service_id, row.destination_service_id} - {""}:
            for index, value in enumerate(values):
                top_services[service_id][index] += value
        keys = {
            "categories": row.category,
            "protocols": str(row.protocol) if row.protocol >= 0 else "not reported",
            "ports": str(row.destination_port) if row.destination_port >= 0 else "not reported",
            "resolution": "resolved" if row.resolved else "unresolved",
        }
        for dimension, key in keys.items():
            for index, value in enumerate(values):
                distributions[dimension][key][index] += value
    bucket = floor_bucket(start, granularity)
    series_end = floor_bucket(end, granularity)
    filled_series: list[dict[str, Any]] = []
    while bucket < series_end:
        values = series.get(bucket, [0, 0, 0])
        filled_series.append(
            {
                "bucket_start": bucket.isoformat(),
                "reported_bytes": values[0],
                "reported_packets": values[1],
                "record_count": values[2],
            }
        )
        bucket += bucket_step(granularity)
    return {
        "granularity": granularity,
        "totals": {
            "reported_bytes": totals[0],
            "reported_packets": totals[1],
            "record_count": totals[2],
        },
        "series": filled_series,
        "top_devices": _rank(top_devices, devices, ranking_limit),
        "top_pairs": _rank(top_pairs, {}, ranking_limit),
        "top_services": _rank(top_services, services, ranking_limit),
        "distributions": {
            dimension: _rank(values, {}, ranking_limit)
            for dimension, values in distributions.items()
        },
    }


async def _fleet_snapshot(session: AsyncSession) -> dict[str, Any]:
    devices = (await session.scalars(select(Device).where(Device.active.is_(True)))).all()
    sync_time = await session.scalar(select(func.max(SyncJob.finished_at)))
    source_freshness = {
        kind: finished.isoformat() if finished else None
        for kind, finished in (
            await session.execute(
                select(SyncJob.kind, func.max(SyncJob.finished_at))
                .where(SyncJob.status.in_(["success", "partial_success"]))
                .group_by(SyncJob.kind)
            )
        ).all()
    }
    return {
        "devices": len(devices),
        "online": sum(device.online is True for device in devices),
        "users": int(await session.scalar(select(func.count()).select_from(TailnetUser)) or 0),
        "routes": sum(len(device.approved_routes) for device in devices),
        "services": int(
            await session.scalar(
                select(func.count())
                .select_from(TailnetService)
                .where(TailnetService.present.is_(True))
            )
            or 0
        ),
        "last_synchronization": sync_time.isoformat() if sync_time else None,
        "basis": "current inventory at report generation time",
        "source_freshness": source_freshness,
    }


async def build_report_snapshot(session: AsyncSession, run: ReportRun) -> dict[str, Any]:
    range_start, range_end = aware(run.range_start), aware(run.range_end)
    if range_start is None or range_end is None:
        raise ValueError("Report range is unavailable")
    options = normalize_report_options(run.report_options)
    ranking_limit = int(options["ranking_limit"])
    current = await aggregate_report_data(
        session, range_start, range_end, run.filters, ranking_limit
    )
    duration = range_end - range_start
    previous = (
        await aggregate_report_data(
            session, range_start - duration, range_start, run.filters, ranking_limit
        )
        if options["include_previous_period"]
        else None
    )
    state = await session.get(FlowAggregateState, current["granularity"])
    coverage_start = aware(state.coverage_start) if state else None
    coverage_end = aware(state.coverage_end) if state else None
    complete = bool(
        coverage_start
        and coverage_end
        and coverage_start <= range_start
        and coverage_end >= range_end
    )
    run.coverage = {
        "complete": complete,
        "coverage_start": coverage_start.isoformat() if coverage_start else None,
        "coverage_end": coverage_end.isoformat() if coverage_end else None,
        "granularity": current["granularity"],
    }
    comparison = (
        {
            key: {
                "current": current["totals"][key],
                "previous": previous["totals"][key],
                "change_percent": (
                    round(
                        (current["totals"][key] - previous["totals"][key])
                        / previous["totals"][key]
                        * 100,
                        2,
                    )
                    if previous["totals"][key]
                    else None
                ),
            }
            for key in ("reported_bytes", "reported_packets", "record_count")
        }
        if previous
        else None
    )
    aggregate_states = {
        item.granularity: {
            "coverage_start": iso_aware(item.coverage_start),
            "coverage_end": iso_aware(item.coverage_end),
            "last_success": iso_aware(item.last_success),
            "last_error": item.last_error,
        }
        for item in (await session.scalars(select(FlowAggregateState))).all()
    }
    settings = get_settings()
    snapshot = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_id": run.id,
        "title": run.title,
        "description": options["description"],
        "generated_at": datetime.now(UTC).isoformat(),
        "saved_view": {
            "id": run.saved_view_id,
            "revision": run.saved_view_revision,
        },
        "report_options": options,
        "range": {"start": range_start.isoformat(), "end": range_end.isoformat()},
        "filters": run.filters,
        "coverage": run.coverage,
        "notice": (
            "Client-reported successful traffic windows; peer reports may overlap. "
            "Volumes are reported bytes and packets, not unique transferred volume."
        ),
        "traffic": current,
        "previous_period": previous["totals"] if previous else None,
        "comparison": comparison,
        "fleet": await _fleet_snapshot(session),
        "aggregate_coverage": aggregate_states,
        "retention": {
            "hourly_days": settings.flow_hourly_aggregate_retention_days,
            "daily_days": settings.flow_daily_aggregate_retention_days,
            "raw_flow_days": settings.flow_retention_days,
        },
    }
    evidence = json.dumps(
        {"filters": run.filters, "range": snapshot["range"], "traffic": current},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    snapshot["evidence_sha256"] = hashlib.sha256(evidence).hexdigest()
    return snapshot


def _csv_bytes(rows: list[list[Any]]) -> bytes:
    output = io.StringIO(newline="")
    csv.writer(output).writerows(rows)
    return output.getvalue().encode()


def render_csv_bundle(snapshot: dict[str, Any]) -> bytes:
    output = io.BytesIO()
    traffic = snapshot["traffic"]
    options = normalize_report_options(snapshot.get("report_options"))
    sections = set(options["sections"])
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.csv",
            _csv_bytes(
                [
                    ["field", "value"],
                    ["schema_version", snapshot["schema_version"]],
                    ["report_id", snapshot["report_id"]],
                    ["generated_at", snapshot["generated_at"]],
                    ["range_start", snapshot["range"]["start"]],
                    ["range_end", snapshot["range"]["end"]],
                    ["coverage_complete", snapshot["coverage"]["complete"]],
                    ["coverage_start", snapshot["coverage"].get("coverage_start")],
                    ["coverage_end", snapshot["coverage"].get("coverage_end")],
                    ["saved_view_id", snapshot.get("saved_view", {}).get("id")],
                    ["saved_view_revision", snapshot.get("saved_view", {}).get("revision")],
                    ["ranking_limit", options["ranking_limit"]],
                    ["include_previous_period", options["include_previous_period"]],
                    ["sections", ",".join(options["sections"])],
                    ["filters", json.dumps(snapshot.get("filters", {}), sort_keys=True)],
                    ["evidence_sha256", snapshot.get("evidence_sha256", "")],
                    ["notice", snapshot["notice"]],
                ]
            ),
        )
        archive.writestr(
            "summary.csv",
            _csv_bytes(
                [
                    ["period", "reported_bytes", "reported_packets", "record_count"],
                    [
                        "current",
                        traffic["totals"]["reported_bytes"],
                        traffic["totals"]["reported_packets"],
                        traffic["totals"]["record_count"],
                    ],
                    *(
                        [
                            [
                                "previous",
                                snapshot["previous_period"]["reported_bytes"],
                                snapshot["previous_period"]["reported_packets"],
                                snapshot["previous_period"]["record_count"],
                            ]
                        ]
                        if snapshot.get("previous_period")
                        else []
                    ),
                ]
            ),
        )
        if "trends" in sections:
            archive.writestr(
                "timeseries.csv",
                _csv_bytes(
                    [
                        ["bucket_start", "reported_bytes", "reported_packets", "record_count"],
                        *[
                            [
                                row["bucket_start"],
                                row["reported_bytes"],
                                row["reported_packets"],
                                row["record_count"],
                            ]
                            for row in traffic["series"]
                        ],
                    ]
                ),
            )
        entity_sections = {
            "top_devices": "devices",
            "top_pairs": "pairs",
            "top_services": "services",
        }
        for name, section in entity_sections.items():
            if section not in sections:
                continue
            archive.writestr(
                f"{name}.csv",
                _csv_bytes(
                    [
                        ["id", "name", "reported_bytes", "reported_packets", "record_count"],
                        *[
                            [
                                row["id"],
                                row["name"],
                                row["reported_bytes"],
                                row["reported_packets"],
                                row["record_count"],
                            ]
                            for row in traffic[name]
                        ],
                    ]
                ),
            )
        distribution_sections = {
            "protocols": "protocols",
            "ports": "ports",
            "categories": "categories",
            "resolution": "resolution",
        }
        for name, rows in traffic["distributions"].items():
            if distribution_sections[name] not in sections:
                continue
            archive.writestr(
                f"distribution_{name}.csv",
                _csv_bytes(
                    [
                        ["value", "reported_bytes", "reported_packets", "record_count"],
                        *[
                            [
                                row["name"],
                                row["reported_bytes"],
                                row["reported_packets"],
                                row["record_count"],
                            ]
                            for row in rows
                        ],
                    ]
                ),
            )
    return output.getvalue()


def _human_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    for unit in units:
        if amount < 1000 or unit == units[-1]:
            return f"{amount:.1f} {unit}"
        amount /= 1000
    return f"{value} B"


def _change_label(comparison: dict[str, Any] | None, key: str) -> str:
    if not comparison or comparison[key]["change_percent"] is None:
        return "Previous period unavailable"
    change = float(comparison[key]["change_percent"])
    direction = "increase" if change > 0 else "decrease" if change < 0 else "no change"
    return f"{abs(change):.1f}% {direction}"


def _page_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#526b68"))
    canvas.drawString(16 * mm, 9 * mm, "TailView · Client-reported network usage")
    canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def _distribution_drawing(rows: list[dict[str, Any]]) -> Drawing:
    drawing = Drawing(172 * mm, 42 * mm)
    chart = HorizontalBarChart()
    chart.x, chart.y, chart.width, chart.height = 42 * mm, 5 * mm, 122 * mm, 32 * mm
    visible = rows[:8]
    chart.data = [[row["reported_bytes"] for row in reversed(visible)]]
    chart.categoryAxis.categoryNames = [row["name"][:24] for row in reversed(visible)]
    chart.bars[0].fillColor = colors.HexColor("#32c9a5")
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 6
    chart.categoryAxis.labels.fontSize = 6
    drawing.add(chart)
    return drawing


def render_pdf(snapshot: dict[str, Any]) -> bytes:
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=snapshot["title"],
        author="TailView",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="TailViewTitle",
            parent=styles["Title"],
            textColor=colors.HexColor("#143b3a"),
            alignment=TA_LEFT,
        )
    )
    options = normalize_report_options(snapshot.get("report_options"))
    sections = set(options["sections"])
    story: list[Any] = [
        Paragraph("TAILVIEW · NETWORK USAGE", styles["Heading4"]),
        Paragraph(escape(snapshot["title"]), styles["TailViewTitle"]),
        *(
            [Paragraph(escape(options["description"]), styles["BodyText"]), Spacer(1, 2 * mm)]
            if options["description"]
            else []
        ),
        Paragraph(f"{snapshot['range']['start']} — {snapshot['range']['end']}", styles["Normal"]),
        Paragraph(f"Generated {snapshot['generated_at']}", styles["Normal"]),
        Spacer(1, 8 * mm),
    ]
    totals = snapshot["traffic"]["totals"]
    comparison = snapshot.get("comparison")
    metrics = Table(
        [
            ["Reported volume", "Reported packets", "Flow records", "Coverage"],
            [
                _human_bytes(totals["reported_bytes"]),
                f"{totals['reported_packets']:,}",
                f"{totals['record_count']:,}",
                "Complete" if snapshot["coverage"]["complete"] else "Partial",
            ],
            [
                _change_label(comparison, "reported_bytes"),
                _change_label(comparison, "reported_packets"),
                _change_label(comparison, "record_count"),
                f"{snapshot['coverage'].get('granularity', 'unknown')} aggregates",
            ],
        ],
        colWidths=[43 * mm] * 4,
    )
    metrics.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#143b3a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#edf8f5")),
                ("TEXTCOLOR", (0, 2), (-1, 2), colors.HexColor("#526b68")),
                ("FONTSIZE", (0, 2), (-1, 2), 7),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8d5d0")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend([metrics, Spacer(1, 8 * mm)])
    series = snapshot["traffic"]["series"]
    if series and "trends" in sections:
        drawing = Drawing(175 * mm, 55 * mm)
        chart = HorizontalLineChart()
        chart.x, chart.y, chart.width, chart.height = 12 * mm, 8 * mm, 155 * mm, 38 * mm
        chart.data = [[row["reported_bytes"] for row in series]]
        chart.lines[0].strokeColor = colors.HexColor("#32c9a5")
        chart.lines[0].strokeWidth = 2
        chart.valueAxis.valueMin = 0
        label_step = max(1, len(series) // 8)
        chart.categoryAxis.categoryNames = [
            row["bucket_start"][:10] if index % label_step == 0 else ""
            for index, row in enumerate(series)
        ]
        chart.categoryAxis.labels.angle = 30
        chart.categoryAxis.labels.fontSize = 6
        drawing.add(chart)
        story.extend([Paragraph("Reported traffic trend", styles["Heading2"]), drawing])
    for heading, key, section in (
        ("Top devices", "top_devices", "devices"),
        ("Top pairs", "top_pairs", "pairs"),
        ("Top Services", "top_services", "services"),
    ):
        rows = snapshot["traffic"][key][: int(options["ranking_limit"])]
        if not rows or section not in sections:
            continue
        table = Table(
            [
                [heading, "Reported volume", "Packets"],
                *[
                    [
                        row["name"],
                        _human_bytes(row["reported_bytes"]),
                        f"{row['reported_packets']:,}",
                    ]
                    for row in rows
                ],
            ],
            colWidths=[95 * mm, 42 * mm, 35 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dff5ef")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b8d5d0")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.extend([Spacer(1, 5 * mm), KeepTogether(table)])
    distribution_labels = {
        "protocols": "Protocols",
        "ports": "Destination ports",
        "categories": "Traffic categories",
        "resolution": "Resolution coverage",
    }
    for key, heading in distribution_labels.items():
        rows = snapshot["traffic"]["distributions"][key]
        if key not in sections or not rows:
            continue
        table = Table(
            [
                [heading, "Reported volume", "Records"],
                *[
                    [
                        row["name"],
                        _human_bytes(row["reported_bytes"]),
                        f"{row['record_count']:,}",
                    ]
                    for row in rows[: int(options["ranking_limit"])]
                ],
            ],
            colWidths=[95 * mm, 42 * mm, 35 * mm],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dff5ef")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b8d5d0")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.extend(
            [
                Spacer(1, 5 * mm),
                Paragraph(heading, styles["Heading2"]),
                _distribution_drawing(rows),
                table,
            ]
        )
    story.extend(
        [
            Spacer(1, 7 * mm),
            Paragraph("Reliability and provenance", styles["Heading2"]),
            Paragraph(snapshot["notice"], styles["BodyText"]),
            Paragraph(
                "Aggregate coverage: "
                f"{snapshot['coverage'].get('coverage_start') or 'not available'} — "
                f"{snapshot['coverage'].get('coverage_end') or 'not available'}. "
                "Traffic before aggregate collection is not represented.",
                styles["BodyText"],
            ),
            Paragraph(f"Fleet values are {snapshot['fleet']['basis']}.", styles["BodyText"]),
            Paragraph(
                "Aggregate updates may lag recently received flow windows; see the JSON or CSV "
                "manifest for per-granularity freshness and retention boundaries.",
                styles["BodyText"],
            ),
        ]
    )
    if "fleet_context" in sections:
        fleet = snapshot["fleet"]
        story.extend(
            [
                Paragraph("Current fleet context", styles["Heading2"]),
                Table(
                    [
                        ["Devices", "Online", "Users", "Routes", "Services"],
                        [
                            fleet["devices"],
                            fleet["online"],
                            fleet["users"],
                            fleet["routes"],
                            fleet["services"],
                        ],
                    ],
                    colWidths=[34 * mm] * 5,
                    style=[
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dff5ef")),
                        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b8d5d0")),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ],
                ),
            ]
        )
    document.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return output.getvalue()


def artifact_payloads(snapshot: dict[str, Any]) -> dict[str, tuple[str, str, bytes]]:
    safe_name = (
        "".join(
            character if character.isalnum() or character in "-_" else "-"
            for character in snapshot["title"].casefold()
        ).strip("-")[:80]
        or "network-report"
    )
    return {
        "json": (
            "application/json",
            f"{safe_name}.json",
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode(),
        ),
        "csv": ("application/zip", f"{safe_name}-csv.zip", render_csv_bundle(snapshot)),
        "pdf": ("application/pdf", f"{safe_name}.pdf", render_pdf(snapshot)),
    }


async def generate_report(session: AsyncSession, run: ReportRun, settings: Settings) -> None:
    run.status = "running"
    run.generation_stage = "aggregating"
    run.progress = 10
    run.started_at = datetime.now(UTC)
    run.error = ""
    await session.commit()
    try:

        async def assemble() -> tuple[dict[str, Any], dict[str, tuple[str, str, bytes]]]:
            snapshot_value = await build_report_snapshot(session, run)
            run.generation_stage = "rendering"
            run.progress = 55
            await session.commit()
            artifact_values = await asyncio.to_thread(artifact_payloads, snapshot_value)
            return snapshot_value, artifact_values

        snapshot, artifacts = await asyncio.wait_for(
            assemble(), timeout=settings.report_generation_timeout_seconds
        )
        run.generation_stage = "storing"
        run.progress = 85
        for format_name, (content_type, filename, content) in artifacts.items():
            if len(content) > settings.report_max_artifact_bytes:
                raise ValueError(f"{format_name.upper()} artifact exceeds configured size limit")
            session.add(
                ReportArtifact(
                    run_id=run.id,
                    format=format_name,
                    content_type=content_type,
                    filename=filename,
                    content_hash=hashlib.sha256(content).hexdigest(),
                    size=len(content),
                    content=content,
                )
            )
        run.snapshot = snapshot
        run.snapshot_schema_version = int(REPORT_SCHEMA_VERSION)
        run.status = "completed" if run.coverage.get("complete") else "partial"
        run.generation_stage = "completed"
        run.progress = 100
        run.completed_at = datetime.now(UTC)
        await session.commit()
    except Exception as exc:
        await session.rollback()
        failed = await session.get(ReportRun, run.id)
        if failed:
            failed.status = "failed"
            failed.generation_stage = "failed"
            failed.error = f"Report generation failed ({type(exc).__name__})"[:255]
            failed.completed_at = datetime.now(UTC)
            await session.commit()
        raise


async def recover_stale_report_runs(
    session: AsyncSession, settings: Settings, now: datetime
) -> int:
    cutoff = now - timedelta(seconds=settings.report_generation_timeout_seconds)
    rows = (
        await session.scalars(
            select(ReportRun).where(
                ReportRun.status == "running",
                ReportRun.started_at.is_not(None),
                ReportRun.started_at < cutoff,
            )
        )
    ).all()
    for run in rows:
        run.status = "failed"
        run.generation_stage = "failed"
        run.error = "Report generation was interrupted and exceeded the configured timeout"
        run.completed_at = now
    if rows:
        await session.commit()
    return len(rows)


async def _generate_report_id(report_id: str, settings: Settings) -> None:
    async with SessionLocal() as session:
        run = await session.get(ReportRun, report_id)
        if run is None or run.status != "queued":
            return
        try:
            await generate_report(session, run, settings)
        except Exception:
            log.exception("report_generation_failed", report_id=report_id)


async def enqueue_schedule_run(
    session: AsyncSession, schedule: ReportSchedule, period_end: datetime
) -> ReportRun | None:
    view = await session.get(SavedView, schedule.saved_view_id) if schedule.saved_view_id else None
    if (
        view is None
        or view.page != "flows"
        or not compatible_state(view.page, view.schema_version, view.state)
    ):
        schedule.enabled = False
        schedule.last_error = "Saved Flow view is missing or incompatible"
        return None
    start, end = report_period(schedule.frequency, period_end)
    period_key = f"schedule:{schedule.id}:{start.isoformat()}:{end.isoformat()}"
    existing = await session.scalar(select(ReportRun).where(ReportRun.period_key == period_key))
    if existing:
        return existing
    run = ReportRun(
        period_key=period_key,
        schedule_id=schedule.id,
        saved_view_id=view.id,
        saved_view_revision=view.revision,
        report_options=normalize_report_options(schedule.report_options),
        snapshot_schema_version=int(REPORT_SCHEMA_VERSION),
        requested_by=schedule.created_by,
        title=f"{schedule.name} · {end.date().isoformat()}",
        status="queued",
        range_start=start,
        range_end=end,
        filters={key: value for key, value in view.state.items() if key != "range"},
    )
    session.add(run)
    schedule.last_run_at = datetime.now(UTC)
    schedule.last_error = ""
    schedule.next_run_at = next_schedule_time(schedule, period_end + timedelta(seconds=1))
    return run


async def reporting_cycle(now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    settings = get_settings()
    connection = await engine.connect()
    try:
        if connection.dialect.name == "postgresql":
            acquired = bool(await connection.scalar(text("SELECT pg_try_advisory_lock(81210)")))
            await connection.commit()
            if not acquired:
                return
        async with SessionLocal() as session:
            recovered = await recover_stale_report_runs(session, settings, now)
            if recovered:
                log.warning("stale_report_runs_recovered", count=recovered)
            due = (
                await session.scalars(
                    select(ReportSchedule).where(
                        ReportSchedule.enabled.is_(True), ReportSchedule.next_run_at <= now
                    )
                )
            ).all()
            for schedule in due:
                await enqueue_schedule_run(session, schedule, schedule.next_run_at or now)
            await session.commit()
            queued_ids = (
                await session.scalars(
                    select(ReportRun.id)
                    .where(ReportRun.status == "queued")
                    .order_by(ReportRun.created_at)
                    .limit(settings.report_max_concurrent_jobs)
                )
            ).all()
        await asyncio.gather(
            *(_generate_report_id(report_id, settings) for report_id in queued_ids)
        )
    finally:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("SELECT pg_advisory_unlock(81210)"))
            await connection.commit()
        await connection.close()


async def aggregate_flows_job() -> None:
    connection = await engine.connect()
    try:
        if connection.dialect.name == "postgresql":
            acquired = bool(await connection.scalar(text("SELECT pg_try_advisory_lock(81211)")))
            await connection.commit()
            if not acquired:
                return
        async with SessionLocal() as session:
            try:
                result = await update_flow_aggregates(session)
                log.info("flow_aggregates_updated", **result)
            except Exception:
                await session.rollback()
                log.exception("flow_aggregation_failed")
    finally:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("SELECT pg_advisory_unlock(81211)"))
            await connection.commit()
        await connection.close()


async def cleanup_reporting_job() -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    connection = await engine.connect()
    try:
        if connection.dialect.name == "postgresql":
            acquired = bool(await connection.scalar(text("SELECT pg_try_advisory_lock(81212)")))
            await connection.commit()
            if not acquired:
                return
        async with SessionLocal() as session:
            await cleanup_flow_data(session, settings, now)
            expired_runs = select(ReportRun.id).where(
                ReportRun.completed_at
                < now - timedelta(days=settings.report_artifact_retention_days)
            )
            await session.execute(delete(ReportRun).where(ReportRun.id.in_(expired_runs)))
            await session.commit()
    finally:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("SELECT pg_advisory_unlock(81212)"))
            await connection.commit()
        await connection.close()


def manual_period(range_name: str, end: datetime) -> tuple[datetime, datetime]:
    return end - timedelta(hours=RANGE_HOURS[range_name]), end


def new_manual_run(
    view: SavedView,
    user_id: str,
    range_name: str,
    title: str,
    now: datetime,
    report_options: dict[str, Any] | None = None,
) -> ReportRun:
    start, end = manual_period(range_name, now)
    return ReportRun(
        period_key=f"manual:{uuid.uuid4()}",
        saved_view_id=view.id,
        saved_view_revision=view.revision,
        requested_by=user_id,
        title=title.strip() or f"{view.name} · {end.date().isoformat()}",
        range_start=start,
        range_end=end,
        filters={key: value for key, value in view.state.items() if key != "range"},
        report_options=normalize_report_options(report_options),
        snapshot_schema_version=int(REPORT_SCHEMA_VERSION),
        generation_stage="queued",
        progress=0,
    )


def new_retry_run(run: ReportRun, user_id: str, now: datetime) -> ReportRun:
    return ReportRun(
        period_key=f"retry:{run.id}:{uuid.uuid4()}",
        retry_of_id=run.id,
        schedule_id=run.schedule_id,
        saved_view_id=run.saved_view_id,
        saved_view_revision=run.saved_view_revision,
        requested_by=user_id,
        title=run.title,
        range_start=run.range_start,
        range_end=run.range_end,
        filters=dict(run.filters),
        report_options=normalize_report_options(run.report_options),
        snapshot_schema_version=int(REPORT_SCHEMA_VERSION),
        generation_stage="queued",
        progress=0,
        created_at=now,
    )
