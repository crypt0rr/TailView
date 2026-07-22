from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class AppUser(Base):
    __tablename__ = "app_users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str] = mapped_column(ForeignKey("app_users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    initial_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    last_ip: Mapped[str] = mapped_column(String(128), default="unknown")
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    restricted: Mapped[bool] = mapped_column(Boolean, default=False)
    user: Mapped[AppUser] = relationship()


class MfaCredential(Base):
    __tablename__ = "mfa_credentials"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("app_users.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    last_counter: Mapped[int | None] = mapped_column(Integer)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("app_users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("app_users.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(32), default="login_mfa")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuthPolicy(Base):
    __tablename__ = "auth_policy"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="current")
    required_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class LocalSecurityEvent(Base):
    __tablename__ = "local_security_events"
    __table_args__ = (Index("ix_local_security_events_time_id", "occurred_at", "id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    correlation_id: Mapped[str] = mapped_column(String(128), default="")
    source_address: Mapped[str] = mapped_column(String(128), default="unknown")
    user_agent: Mapped[str] = mapped_column(String(512), default="")
    result: Mapped[str] = mapped_column(String(32), default="success")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    success: Mapped[bool] = mapped_column(Boolean)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class TailnetUser(Base):
    __tablename__ = "tailnet_users"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    login_name: Mapped[str] = mapped_column(String(255), default="", index=True)
    role: Mapped[str] = mapped_column(String(64), default="member")
    status: Mapped[str] = mapped_column(String(64), default="unknown")
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="tailscale_user_api")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(64), default="unknown")
    version: Mapped[str] = mapped_column(String(64), default="")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("tailnet_users.id"), index=True)
    online: Mapped[bool | None] = mapped_column(Boolean)
    authorized: Mapped[bool | None] = mapped_column(Boolean)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_expiry_disabled: Mapped[bool | None] = mapped_column(Boolean)
    addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    advertised_routes: Mapped[list[str]] = mapped_column(JSON, default=list)
    approved_routes: Mapped[list[str]] = mapped_column(JSON, default=list)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    primary_role: Mapped[str] = mapped_column(String(64), default="standard_node")
    source: Mapped[str] = mapped_column(String(64), default="tailscale_device_api")
    inventory_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    owner: Mapped[TailnetUser | None] = relationship()


class DeviceConnectivity(Base):
    __tablename__ = "device_connectivity"
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    mapping_varies_by_dest_ip: Mapped[bool | None] = mapped_column(Boolean)
    derp: Mapped[str | None] = mapped_column(String(64))
    endpoints: Mapped[list[Any]] = mapped_column(JSON, default=list)
    latency: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    client_supports: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DevicePostureState(Base):
    __tablename__ = "device_posture_states"
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    error_status: Mapped[str | None] = mapped_column(String(32))
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DevicePostureAttribute(Base):
    __tablename__ = "device_posture_attributes"
    __table_args__ = (
        Index("ix_posture_attributes_key_present", "key", "present"),
        Index("ix_posture_attributes_expiry", "expiry"),
    )
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    namespace: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[Any] = mapped_column(JSON)
    value_type: Mapped[str] = mapped_column(String(16))
    expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PostureIntegration(Base):
    __tablename__ = "posture_integrations"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    provider: Mapped[str] = mapped_column(String(128), default="unknown")
    status: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TailnetSecuritySettings(Base):
    __tablename__ = "tailnet_security_settings"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="current")
    values: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LocalMetadata(Base):
    __tablename__ = "local_metadata"
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    display_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    function: Mapped[str | None] = mapped_column(String(128))
    functional_groups: Mapped[list[str]] = mapped_column(JSON, default=list)
    custom_roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    primary_role_override: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str | None] = mapped_column(String(64))
    location: Mapped[str | None] = mapped_column(String(128))
    criticality: Mapped[str | None] = mapped_column(String(32))
    icon: Mapped[str | None] = mapped_column(String(64))
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    default_map_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_flow_fingerprint"),
        Index("ix_flows_time_pair", "start", "source_device_id", "destination_device_id"),
        Index("ix_flows_source_category_end", "source_device_id", "category", "end"),
        Index("ix_flows_start_id", "start", "id"),
        Index("ix_flows_category_start_id", "category", "start", "id"),
        Index("ix_flows_protocol_start_id", "protocol", "start", "id"),
        Index("ix_flows_destination_port_start_id", "destination_port", "start", "id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    reporting_node_id: Mapped[str | None] = mapped_column(String(128), index=True)
    source_device_id: Mapped[str | None] = mapped_column(String(128), index=True)
    destination_device_id: Mapped[str | None] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(255), default="")
    destination: Mapped[str] = mapped_column(String(255), default="")
    protocol: Mapped[int | None] = mapped_column(Integer)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(32))
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    tx_packets: Mapped[int] = mapped_column(Integer, default=0)
    rx_packets: Mapped[int] = mapped_column(Integer, default=0)
    start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    logged: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FlowAggregate(Base):
    __tablename__ = "flow_aggregates"
    __table_args__ = (
        UniqueConstraint(
            "granularity",
            "bucket_start",
            "source_device_id",
            "destination_device_id",
            "source_raw",
            "destination_raw",
            "source_service_id",
            "destination_service_id",
            "category",
            "protocol",
            "source_port",
            "destination_port",
            "resolved",
            name="uq_flow_aggregate_dimensions",
        ),
        Index("ix_flow_aggregates_granularity_bucket", "granularity", "bucket_start"),
        Index("ix_flow_aggregates_source_bucket", "source_device_id", "bucket_start"),
        Index("ix_flow_aggregates_destination_bucket", "destination_device_id", "bucket_start"),
        Index(
            "ix_flow_aggregates_category_protocol_bucket", "category", "protocol", "bucket_start"
        ),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    granularity: Mapped[str] = mapped_column(String(16))
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_device_id: Mapped[str] = mapped_column(String(128), default="")
    destination_device_id: Mapped[str] = mapped_column(String(128), default="")
    source_raw: Mapped[str] = mapped_column(String(255), default="")
    destination_raw: Mapped[str] = mapped_column(String(255), default="")
    source_service_id: Mapped[str] = mapped_column(String(255), default="")
    destination_service_id: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(32), default="unknown")
    protocol: Mapped[int] = mapped_column(Integer, default=-1)
    source_port: Mapped[int] = mapped_column(Integer, default=-1)
    destination_port: Mapped[int] = mapped_column(Integer, default=-1)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    reported_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    reported_packets: Mapped[int] = mapped_column(BigInteger, default=0)
    record_count: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FlowAggregateState(Base):
    __tablename__ = "flow_aggregate_states"
    granularity: Mapped[str] = mapped_column(String(16), primary_key=True)
    coverage_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    coverage_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str] = mapped_column(String(255), default="")


class ReportSchedule(Base):
    __tablename__ = "report_schedules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128))
    saved_view_id: Mapped[str | None] = mapped_column(
        ForeignKey("saved_views.id", ondelete="SET NULL"), index=True
    )
    frequency: Mapped[str] = mapped_column(String(16))
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    local_time: Mapped[str] = mapped_column(String(5), default="08:00")
    weekday: Mapped[int | None] = mapped_column(Integer)
    month_day: Mapped[int | None] = mapped_column(Integer)
    report_options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("app_users.id"))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ReportRun(Base):
    __tablename__ = "report_runs"
    __table_args__ = (
        UniqueConstraint("period_key", name="uq_report_runs_period_key"),
        Index("ix_report_runs_created_id", "created_at", "id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    period_key: Mapped[str] = mapped_column(String(160))
    schedule_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_schedules.id", ondelete="SET NULL"), index=True
    )
    saved_view_id: Mapped[str | None] = mapped_column(
        ForeignKey("saved_views.id", ondelete="SET NULL"), index=True
    )
    saved_view_revision: Mapped[int | None] = mapped_column(Integer)
    retry_of_id: Mapped[str | None] = mapped_column(
        ForeignKey("report_runs.id", ondelete="SET NULL"), index=True
    )
    requested_by: Mapped[str | None] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    range_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    range_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    filters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    snapshot_schema_version: Mapped[int] = mapped_column(Integer, default=1)
    generation_stage: Mapped[str] = mapped_column(String(32), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    run_id: Mapped[str] = mapped_column(
        ForeignKey("report_runs.id", ondelete="CASCADE"), primary_key=True
    )
    format: Mapped[str] = mapped_column(String(8), primary_key=True)
    content_type: Mapped[str] = mapped_column(String(128))
    filename: Mapped[str] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PolicySnapshot(Base):
    __tablename__ = "policy_snapshots"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hujson: Mapped[str] = mapped_column(Text)
    normalized: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    valid: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_error: Mapped[str | None] = mapped_column(Text)
    unsupported: Mapped[list[str]] = mapped_column(JSON, default=list)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    action: Mapped[str] = mapped_column(String(64))
    actor: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    target: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    old: Mapped[Any] = mapped_column(JSON)
    new: Mapped[Any] = mapped_column(JSON)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Capability(Base):
    __tablename__ = "capabilities"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    source: Mapped[str] = mapped_column(String(128))
    requirement: Mapped[str] = mapped_column(Text, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SyncJob(Base):
    __tablename__ = "sync_jobs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kind: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    processed: Mapped[int] = mapped_column(Integer, default=0)
    attempted: Mapped[int] = mapped_column(Integer, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    partial_success: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)


class OperationalJobState(Base):
    __tablename__ = "operational_job_states"
    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer)
    last_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(32), default="never")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)


class OperationalJobRun(Base):
    __tablename__ = "operational_job_runs"
    __table_args__ = (
        Index("ix_operational_job_runs_started_id", "started_at", "id"),
        Index("ix_operational_job_runs_name_status", "name", "status"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    interval_seconds: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(BigInteger)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    error_class: Mapped[str] = mapped_column(String(128), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sync_job_id: Mapped[str | None] = mapped_column(String(36), index=True)
    report_run_id: Mapped[str | None] = mapped_column(String(36), index=True)


class OperationalSignalState(Base):
    __tablename__ = "operational_signal_states"
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    consecutive_observations: Mapped[int] = mapped_column(Integer, default=0)
    last_present: Mapped[bool] = mapped_column(Boolean, default=False)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CleanupRun(Base):
    __tablename__ = "cleanup_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    status: Mapped[str] = mapped_column(String(32), index=True)
    trigger: Mapped[str] = mapped_column(String(32), default="scheduled")
    preview: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    deleted: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_class: Mapped[str] = mapped_column(String(128), default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BackupVerification(Base):
    __tablename__ = "backup_verifications"
    __table_args__ = (Index("ix_backup_verifications_verified_id", "verified_at", "id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename: Mapped[str] = mapped_column(String(255))
    content_hash: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(32), index=True)
    postgres_version: Mapped[str] = mapped_column(String(64), default="")
    migration_revision: Mapped[str] = mapped_column(String(128), default="")
    checks: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_class: Mapped[str] = mapped_column(String(128), default="")
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TailnetService(Base):
    __tablename__ = "tailnet_services"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    comment: Mapped[str] = mapped_column(Text, default="")
    addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    ports: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="tailscale_services_api")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceHost(Base):
    __tablename__ = "service_hosts"
    id: Mapped[str] = mapped_column(String(512), primary_key=True)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("tailnet_services.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[str | None] = mapped_column(String(128), index=True)
    advertised: Mapped[bool | None] = mapped_column(Boolean)
    approved: Mapped[bool | None] = mapped_column(Boolean)
    status: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ServiceEndpoint(Base):
    __tablename__ = "service_endpoints"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("tailnet_services.id", ondelete="CASCADE"), index=True
    )
    host_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_hosts.id", ondelete="CASCADE"), index=True
    )
    protocol: Mapped[str] = mapped_column(String(32), default="unknown")
    port: Mapped[int | None] = mapped_column(Integer)
    endpoint_type: Mapped[str] = mapped_column(String(32), default="unknown")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DnsConfiguration(Base):
    __tablename__ = "dns_configurations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="current")
    magic_dns: Mapped[bool | None] = mapped_column(Boolean)
    override_local_dns: Mapped[bool | None] = mapped_column(Boolean)
    nameservers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    search_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    split_dns: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    url_display: Mapped[str] = mapped_column(Text, default="")
    subscriptions: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled: Mapped[bool | None] = mapped_column(Boolean)
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="tailscale_webhooks_api")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kind: Mapped[str] = mapped_column(String(32))
    client_id: Mapped[str | None] = mapped_column(String(255))
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TailnetCredential(Base):
    __tablename__ = "tailnet_credentials"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    display_id: Mapped[str] = mapped_column(String(64), default="")
    credential_type: Mapped[str] = mapped_column(String(64), index=True)
    description: Mapped[str] = mapped_column(String(512), default="")
    creator_id: Mapped[str | None] = mapped_column(String(255), index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    reusable: Mapped[bool | None] = mapped_column(Boolean)
    ephemeral: Mapped[bool | None] = mapped_column(Boolean)
    preapproved: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revoked: Mapped[bool | None] = mapped_column(Boolean)
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    stale: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    source: Mapped[str] = mapped_column(String(64), default="tailscale_keys_api")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceInvite(Base):
    __tablename__ = "device_invites"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(128), index=True)
    inviter_id: Mapped[str | None] = mapped_column(String(255), index=True)
    recipient: Mapped[str] = mapped_column(String(512), default="")
    status: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    stale: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TailnetContact(Base):
    __tablename__ = "tailnet_contacts"
    contact_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), default="")
    verified: Mapped[bool | None] = mapped_column(Boolean)
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    stale: Mapped[bool] = mapped_column(Boolean, default=False)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class LogStreamingConfiguration(Base):
    __tablename__ = "log_streaming_configurations"
    log_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool | None] = mapped_column(Boolean, index=True)
    destination_type: Mapped[str] = mapped_column(String(128), default="unknown")
    destination_display: Mapped[str] = mapped_column(String(1024), default="")
    status: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    stale: Mapped[bool] = mapped_column(Boolean, default=False)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SavedView(Base):
    __tablename__ = "saved_views"
    __table_args__ = (Index("ix_saved_views_page_visibility", "page", "visibility"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("app_users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(500), default="")
    page: Mapped[str] = mapped_column(String(64))
    visibility: Mapped[str] = mapped_column(String(16), default="private")
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    owner: Mapped[AppUser] = relationship()


Index(
    "uq_saved_views_owner_page_lower_name",
    SavedView.owner_id,
    SavedView.page,
    func.lower(SavedView.name),
    unique=True,
)


class SavedViewDefault(Base):
    __tablename__ = "saved_view_defaults"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("app_users.id", ondelete="CASCADE"), primary_key=True
    )
    page: Mapped[str] = mapped_column(String(64), primary_key=True)
    view_id: Mapped[str] = mapped_column(
        ForeignKey("saved_views.id", ondelete="CASCADE"), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
        Index("ix_findings_status_severity_last_seen", "status", "severity", "last_seen"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text, default="")
    subject_type: Mapped[str] = mapped_column(String(64), index=True)
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    subject_display: Mapped[str] = mapped_column(String(512), default="")
    visibility: Mapped[str] = mapped_column(String(32), default="viewer", index=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    link_path: Mapped[str] = mapped_column(String(1024), default="")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    stale: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_evaluated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(36))
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suppression_reason: Mapped[str] = mapped_column(String(1000), default="")
    assigned_to: Mapped[str | None] = mapped_column(
        ForeignKey("app_users.id", ondelete="SET NULL"), index=True
    )
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)


class FindingOccurrence(Base):
    __tablename__ = "finding_occurrences"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), default="observed")
    severity: Mapped[str] = mapped_column(String(16))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingTransition(Base):
    __tablename__ = "finding_transitions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    from_status: Mapped[str | None] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[str | None] = mapped_column(String(36))
    reason: Mapped[str] = mapped_column(String(1000), default="")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class NotificationEndpoint(Base):
    __tablename__ = "notification_endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(128))
    url_display: Mapped[str] = mapped_column(String(1024))
    encrypted_url: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    minimum_severity: Mapped[str] = mapped_column(String(16), default="high")
    sources: Mapped[list[str]] = mapped_column(JSON, default=list)
    include_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_notification_delivery_idempotency"),
        Index("ix_notification_delivery_due", "status", "next_attempt"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("notification_endpoints.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(32))
    idempotency_key: Mapped[str] = mapped_column(String(128))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    http_status: Mapped[int | None] = mapped_column(Integer)
    error_class: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RawPayload(Base):
    __tablename__ = "raw_payloads"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(128), index=True)
    schema_version: Mapped[str] = mapped_column(String(64), default="unknown")
    payload: Mapped[dict[str, Any] | list[Any]] = mapped_column(JSON)
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class TelemetryObservation(Base):
    __tablename__ = "telemetry_observations"
    __table_args__ = (
        Index(
            "ix_telemetry_collector_device_time",
            "collector_device_id",
            "observed_at",
        ),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    collector_node_id: Mapped[str | None] = mapped_column(String(128), index=True)
    collector_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL")
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    scope: Mapped[str] = mapped_column(String(64), default="single_collector_node")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    client_version: Mapped[str] = mapped_column(String(64), default="")
    udp: Mapped[bool | None] = mapped_column(Boolean)
    ipv4: Mapped[bool | None] = mapped_column(Boolean)
    ipv6: Mapped[bool | None] = mapped_column(Boolean)
    mapping_varies_by_dest_ip: Mapped[bool | None] = mapped_column(Boolean)
    preferred_derp: Mapped[str | None] = mapped_column(String(64))
    endpoints: Mapped[list[Any]] = mapped_column(JSON, default=list)
    derp_latency: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DeviceHistoryEvent(Base):
    __tablename__ = "device_history_events"
    __table_args__ = (
        Index("ix_device_history_device_time_id", "device_id", "occurred_at", "id"),
        Index("ix_device_history_source_type", "source", "event_type"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(32), default="device_sync", index=True)
    changed_fields: Mapped[list[str]] = mapped_column(JSON, default=list)
    before: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    after: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    actor_id: Mapped[str | None] = mapped_column(String(36), index=True)
    correlation_id: Mapped[str] = mapped_column(String(128), default="")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
