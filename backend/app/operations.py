from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from prometheus_client import Gauge, Histogram
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db import SessionLocal, engine
from .models import (
    BackupVerification,
    CleanupRun,
    Finding,
    Flow,
    FlowAggregate,
    FlowAggregateState,
    NotificationDelivery,
    OperationalJobRun,
    OperationalJobState,
    RawPayload,
    ReportArtifact,
    ReportRun,
    Session,
    SyncJob,
)
from .reporting import cleanup_flow_data

log = structlog.get_logger()
OPERATIONS_LOCK_KEY = 7_410_013

JOB_DURATION = Histogram(
    "tailview_scheduled_job_duration_seconds", "Scheduled job duration", ["job", "status"]
)
JOB_FAILURES = Gauge(
    "tailview_scheduled_job_consecutive_failures", "Consecutive job failures", ["job"]
)
SCHEDULER_HEARTBEAT = Gauge(
    "tailview_scheduler_heartbeat_timestamp_seconds", "Last scheduler heartbeat"
)
QUEUE_DEPTH = Gauge("tailview_queue_depth", "Pending work items", ["queue"])
QUEUE_OLDEST = Gauge("tailview_queue_oldest_age_seconds", "Oldest pending item age", ["queue"])
DATABASE_SIZE = Gauge("tailview_database_size_bytes", "PostgreSQL database size")
AGGREGATE_FRESHNESS = Gauge(
    "tailview_aggregate_last_success_timestamp_seconds", "Aggregate last success", ["granularity"]
)
BACKUP_AGE = Gauge("tailview_backup_verification_age_seconds", "Age of latest verified backup")
CLEANUP_DELETED = Gauge(
    "tailview_cleanup_deleted_rows", "Rows deleted by latest cleanup", ["table"]
)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


async def scheduler_heartbeat() -> None:
    now = datetime.now(UTC)
    async with SessionLocal() as session:
        state = await session.get(OperationalJobState, "scheduler") or OperationalJobState(
            name="scheduler", category="runtime", interval_seconds=30
        )
        state.heartbeat_at = now
        state.last_started_at = now
        state.last_finished_at = now
        state.last_success_at = now
        state.last_status = "success"
        state.consecutive_failures = 0
        session.add(state)
        await session.commit()
    SCHEDULER_HEARTBEAT.set(now.timestamp())


def instrument_job[T](
    name: str,
    category: str,
    interval_seconds: int,
    function: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    async def run(*args: Any, **kwargs: Any) -> T:
        started = datetime.now(UTC)
        run_id = ""
        previous_sync_id: str | None = None
        previous_report_id: str | None = None
        async with SessionLocal() as session:
            if category == "synchronization":
                previous_sync_id = await session.scalar(
                    select(SyncJob.id)
                    .where(SyncJob.kind == name)
                    .order_by(SyncJob.started_at.desc())
                )
            elif category == "reporting":
                previous_report_id = await session.scalar(
                    select(ReportRun.id).order_by(ReportRun.created_at.desc())
                )
            record = OperationalJobRun(
                name=name,
                category=category,
                interval_seconds=interval_seconds,
                status="running",
                started_at=started,
            )
            state = await session.get(OperationalJobState, name) or OperationalJobState(
                name=name, category=category, interval_seconds=interval_seconds
            )
            state.category = category
            state.interval_seconds = interval_seconds
            state.last_started_at = started
            state.last_status = "running"
            state.heartbeat_at = started
            session.add_all([record, state])
            await session.commit()
            run_id = record.id
        status = "success"
        error_class = ""
        try:
            return await function(*args, **kwargs)
        except asyncio.CancelledError:
            status = "cancelled"
            error_class = "CancelledError"
            raise
        except Exception as exc:
            status = "failed"
            error_class = type(exc).__name__
            raise
        finally:
            finished = datetime.now(UTC)
            async with SessionLocal() as session:
                final_record = await session.get(OperationalJobRun, run_id)
                final_state = await session.get(OperationalJobState, name)
                if final_record is not None and category == "synchronization":
                    sync = await session.scalar(
                        select(SyncJob)
                        .where(SyncJob.kind == name)
                        .order_by(SyncJob.started_at.desc())
                        .limit(1)
                    )
                    if sync is None or sync.id == previous_sync_id:
                        status = "lock_skipped"
                    else:
                        final_record.sync_job_id = sync.id
                        final_record.processed = sync.processed
                        final_record.details = {
                            "attempted": sync.attempted,
                            "succeeded": sync.succeeded,
                            "failed": sync.failed,
                        }
                        if sync.status in {"failed", "partial_success", "skipped"}:
                            status = sync.status
                            error_class = "UpstreamError" if sync.status == "failed" else ""
                elif final_record is not None and category == "reporting":
                    report = await session.scalar(
                        select(ReportRun).order_by(ReportRun.created_at.desc()).limit(1)
                    )
                    if report is not None and report.id != previous_report_id:
                        final_record.report_run_id = report.id
                if final_record is not None:
                    final_record.status = status
                    final_record.error_class = error_class
                    final_record.finished_at = finished
                    final_record.duration_ms = int((finished - started).total_seconds() * 1000)
                if final_state is not None:
                    final_state.last_finished_at = finished
                    final_state.last_status = status
                    final_state.heartbeat_at = finished
                    if status == "success":
                        final_state.last_success_at = finished
                        final_state.consecutive_failures = 0
                    elif status not in {"lock_skipped", "skipped"}:
                        final_state.consecutive_failures += 1
                    JOB_FAILURES.labels(name).set(final_state.consecutive_failures)
                await session.commit()
            JOB_DURATION.labels(name, status).observe(max(0, (finished - started).total_seconds()))

    run.__name__ = f"instrumented_{name}"
    return run


async def storage_snapshot(session: AsyncSession) -> dict[str, Any]:
    dialect = session.bind.dialect.name if session.bind is not None else "unknown"
    database_bytes: int | None = None
    relations: list[dict[str, Any]] = []
    if dialect == "postgresql":
        database_bytes = int(
            await session.scalar(text("SELECT pg_database_size(current_database())")) or 0
        )
        result = await session.execute(
            text(
                "SELECT relname, pg_total_relation_size(relid), pg_relation_size(relid), "
                "pg_indexes_size(relid) FROM pg_catalog.pg_statio_user_tables "
                "ORDER BY pg_total_relation_size(relid) DESC"
            )
        )
        relations = [
            {
                "name": name,
                "total_bytes": int(total),
                "table_bytes": int(table),
                "index_bytes": int(index),
            }
            for name, total, table, index in result.all()
        ]
    tracked = {
        "raw_flows": Flow,
        "flow_aggregates": FlowAggregate,
        "report_artifacts": ReportArtifact,
        "raw_payloads": RawPayload,
        "sessions": Session,
        "findings": Finding,
        "delivery_history": NotificationDelivery,
    }
    counts = {
        name: int(await session.scalar(select(func.count()).select_from(model)) or 0)
        for name, model in tracked.items()
    }
    return {
        "database_bytes": database_bytes,
        "relations": relations,
        "counts": counts,
        "host_capacity_reported": False,
    }


async def retention_snapshot(
    session: AsyncSession, settings: Settings | None = None
) -> dict[str, Any]:
    settings = settings or get_settings()
    now = datetime.now(UTC)
    hourly_cutoff = now - timedelta(days=settings.flow_hourly_aggregate_retention_days)
    daily_cutoff = now - timedelta(days=settings.flow_daily_aggregate_retention_days)
    raw_cutoff = now - timedelta(days=settings.flow_retention_days)
    report_cutoff = now - timedelta(days=settings.report_artifact_retention_days)
    payload_cutoff = now - timedelta(days=settings.raw_payload_retention_days)
    finding_cutoff = now - timedelta(days=settings.findings_retention_days)
    states = {
        row.granularity: row for row in (await session.scalars(select(FlowAggregateState))).all()
    }
    def covers_raw_cutoff(state: FlowAggregateState | None) -> bool:
        if state is None or state.last_success is None:
            return False
        start = _aware(state.coverage_start)
        end = _aware(state.coverage_end)
        return bool(start and end and start <= raw_cutoff <= end)

    raw_covered = all(covers_raw_cutoff(states.get(name)) for name in ("hourly", "daily"))
    eligible = {
        "raw_flows": int(
            await session.scalar(
                select(func.count()).select_from(Flow).where(Flow.start < raw_cutoff)
            )
            or 0
        )
        if raw_covered
        else 0,
        "hourly_aggregates": int(
            await session.scalar(
                select(func.count())
                .select_from(FlowAggregate)
                .where(
                    FlowAggregate.granularity == "hourly",
                    FlowAggregate.bucket_start < hourly_cutoff,
                )
            )
            or 0
        ),
        "daily_aggregates": int(
            await session.scalar(
                select(func.count())
                .select_from(FlowAggregate)
                .where(
                    FlowAggregate.granularity == "daily", FlowAggregate.bucket_start < daily_cutoff
                )
            )
            or 0
        ),
        "reports": int(
            await session.scalar(
                select(func.count())
                .select_from(ReportRun)
                .where(ReportRun.completed_at.is_not(None), ReportRun.completed_at < report_cutoff)
            )
            or 0
        ),
        "raw_payloads": int(
            await session.scalar(
                select(func.count())
                .select_from(RawPayload)
                .where(RawPayload.retrieved_at < payload_cutoff)
            )
            or 0
        ),
        "resolved_findings": int(
            await session.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.status == "resolved", Finding.resolved_at < finding_cutoff)
            )
            or 0
        ),
    }
    return {
        "as_of": now,
        "eligible": eligible,
        "raw_flow_cleanup_blocked": not raw_covered,
        "aggregate_coverage": {
            name: {
                "start": row.coverage_start,
                "end": row.coverage_end,
                "last_success": row.last_success,
                "last_error": row.last_error,
            }
            for name, row in states.items()
        },
        "retention_days": {
            "raw_flows": settings.flow_retention_days,
            "hourly_aggregates": settings.flow_hourly_aggregate_retention_days,
            "daily_aggregates": settings.flow_daily_aggregate_retention_days,
            "reports": settings.report_artifact_retention_days,
            "raw_payloads": settings.raw_payload_retention_days,
            "findings": settings.findings_retention_days,
        },
    }


async def _try_operations_lock() -> Any:
    connection = await engine.connect()
    if connection.dialect.name != "postgresql":
        return connection
    acquired = await connection.scalar(
        text("SELECT pg_try_advisory_lock(:key)"), {"key": OPERATIONS_LOCK_KEY}
    )
    if not acquired:
        await connection.close()
        return None
    return connection


async def run_cleanup(trigger: str = "scheduled") -> CleanupRun:
    lock = await _try_operations_lock()
    if lock is None:
        raise RuntimeError("Operations cleanup is already running")
    settings = get_settings()
    async with SessionLocal() as session:
        record = CleanupRun(status="running", trigger=trigger)
        session.add(record)
        await session.commit()
        try:
            preview = await retention_snapshot(session, settings)
            record.preview = preview
            before = dict(preview["eligible"])
            await cleanup_flow_data(session, settings, datetime.now(UTC))
            now = datetime.now(UTC)
            await session.execute(
                delete(RawPayload).where(
                    RawPayload.retrieved_at
                    < now - timedelta(days=settings.raw_payload_retention_days)
                )
            )
            await session.execute(
                delete(Finding).where(
                    Finding.status == "resolved",
                    Finding.resolved_at < now - timedelta(days=settings.findings_retention_days),
                )
            )
            await session.execute(
                delete(ReportRun).where(
                    ReportRun.completed_at.is_not(None),
                    ReportRun.completed_at
                    < now - timedelta(days=settings.report_artifact_retention_days),
                )
            )
            await session.execute(
                delete(OperationalJobRun).where(
                    OperationalJobRun.started_at
                    < now - timedelta(days=settings.operations_job_retention_days)
                )
            )
            await session.execute(
                delete(BackupVerification).where(
                    BackupVerification.verified_at
                    < now - timedelta(days=settings.operations_history_retention_days)
                )
            )
            await session.execute(
                delete(CleanupRun).where(
                    CleanupRun.started_at
                    < now - timedelta(days=settings.operations_history_retention_days)
                )
            )
            await session.commit()
            completed_record = await session.get(CleanupRun, record.id)
            if completed_record is None:
                raise RuntimeError("Cleanup execution record disappeared")
            after = (await retention_snapshot(session, settings))["eligible"]
            completed_record.deleted = {
                key: max(0, int(before.get(key, 0)) - int(after.get(key, 0))) for key in before
            }
            completed_record.status = "success"
            completed_record.finished_at = datetime.now(UTC)
            for key, value in completed_record.deleted.items():
                CLEANUP_DELETED.labels(key).set(value)
            await session.commit()
            return completed_record
        except Exception as exc:
            await session.rollback()
            failed_record = await session.get(CleanupRun, record.id)
            if failed_record is not None:
                failed_record.status = "failed"
                failed_record.error_class = type(exc).__name__
                failed_record.finished_at = datetime.now(UTC)
                await session.commit()
            raise
        finally:
            if lock.dialect.name == "postgresql":
                await lock.execute(
                    text("SELECT pg_advisory_unlock(:key)"), {"key": OPERATIONS_LOCK_KEY}
                )
            await lock.close()


async def cleanup_operations_job() -> None:
    await run_cleanup("scheduled")


async def operations_summary(session: AsyncSession) -> dict[str, Any]:
    settings = get_settings()
    now = datetime.now(UTC)
    states = (
        await session.scalars(select(OperationalJobState).order_by(OperationalJobState.name))
    ).all()
    jobs: list[dict[str, Any]] = []
    degraded = 0
    for state in states:
        heartbeat = _aware(state.heartbeat_at)
        overdue_after = max(state.interval_seconds * 3, 600)
        overdue = state.name != "scheduler" and (
            heartbeat is None or (now - heartbeat).total_seconds() > overdue_after
        )
        unhealthy = (
            overdue
            or state.consecutive_failures >= 2
            or state.last_status == "running"
            and heartbeat is not None
            and (now - heartbeat).total_seconds() > overdue_after
        )
        degraded += int(unhealthy)
        jobs.append(
            {
                "name": state.name,
                "category": state.category,
                "interval_seconds": state.interval_seconds,
                "last_status": state.last_status,
                "last_started_at": state.last_started_at,
                "last_finished_at": state.last_finished_at,
                "last_success_at": state.last_success_at,
                "heartbeat_at": state.heartbeat_at,
                "consecutive_failures": state.consecutive_failures,
                "overdue": overdue,
                "unhealthy": unhealthy,
            }
        )
    queue_values: dict[str, dict[str, Any]] = {}
    for queue, model, statuses, timestamp in (
        ("reports", ReportRun, ["queued"], ReportRun.created_at),
        (
            "notifications",
            NotificationDelivery,
            ["pending", "retrying"],
            NotificationDelivery.created_at,
        ),
    ):
        count = int(
            await session.scalar(
                select(func.count()).select_from(model).where(model.status.in_(statuses))
            )
            or 0
        )
        oldest = await session.scalar(select(func.min(timestamp)).where(model.status.in_(statuses)))
        oldest = _aware(oldest)
        age = int((now - oldest).total_seconds()) if oldest else 0
        queue_values[queue] = {
            "depth": count,
            "oldest_age_seconds": age,
            "warning": age > settings.operations_queue_warn_minutes * 60,
        }
    latest_backup = await session.scalar(
        select(BackupVerification)
        .where(BackupVerification.status == "success")
        .order_by(BackupVerification.verified_at.desc())
        .limit(1)
    )
    latest_cleanup = await session.scalar(
        select(CleanupRun).order_by(CleanupRun.started_at.desc()).limit(1)
    )
    scheduler = next((item for item in jobs if item["name"] == "scheduler"), None)
    verified_at = _aware(latest_backup.verified_at) if latest_backup else None
    backup_age = int((now - verified_at).total_seconds()) if verified_at else None
    return {
        "status": "degraded"
        if degraded or any(item["warning"] for item in queue_values.values())
        else "healthy",
        "generated_at": now,
        "scheduler": scheduler,
        "jobs": jobs,
        "degraded_jobs": degraded,
        "queues": queue_values,
        "backup": {
            "configured": latest_backup is not None,
            "latest_verified_at": latest_backup.verified_at if latest_backup else None,
            "age_seconds": backup_age,
            "max_age_hours": settings.operations_backup_max_age_hours,
            "stale": backup_age is not None
            and backup_age > settings.operations_backup_max_age_hours * 3600,
        },
        "latest_cleanup": {
            "status": latest_cleanup.status,
            "started_at": latest_cleanup.started_at,
            "finished_at": latest_cleanup.finished_at,
            "deleted": latest_cleanup.deleted,
        }
        if latest_cleanup
        else None,
    }


async def refresh_prometheus_metrics() -> None:
    async with SessionLocal() as session:
        summary = await operations_summary(session)
        storage = await storage_snapshot(session)
        if storage["database_bytes"] is not None:
            DATABASE_SIZE.set(storage["database_bytes"])
        for queue, value in summary["queues"].items():
            QUEUE_DEPTH.labels(queue).set(value["depth"])
            QUEUE_OLDEST.labels(queue).set(value["oldest_age_seconds"])
        if summary["backup"]["age_seconds"] is not None:
            BACKUP_AGE.set(summary["backup"]["age_seconds"])
        states = (await session.scalars(select(FlowAggregateState))).all()
        for state in states:
            last_success = _aware(state.last_success)
            if last_success:
                AGGREGATE_FRESHNESS.labels(state.granularity).set(last_success.timestamp())
