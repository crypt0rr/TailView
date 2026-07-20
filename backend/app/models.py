from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
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
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
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
    user: Mapped[AppUser] = relationship()


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
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    advertised_routes: Mapped[list[str]] = mapped_column(JSON, default=list)
    approved_routes: Mapped[list[str]] = mapped_column(JSON, default=list)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    primary_role: Mapped[str] = mapped_column(String(64), default="standard_node")
    source: Mapped[str] = mapped_column(String(64), default="tailscale_device_api")
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    owner: Mapped[TailnetUser | None] = relationship()


class LocalMetadata(Base):
    __tablename__ = "local_metadata"
    device_id: Mapped[str] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    display_name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    function: Mapped[str | None] = mapped_column(String(128))
    environment: Mapped[str | None] = mapped_column(String(64))
    location: Mapped[str | None] = mapped_column(String(128))
    criticality: Mapped[str | None] = mapped_column(String(32))
    icon: Mapped[str | None] = mapped_column(String(64))
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Flow(Base):
    __tablename__ = "flows"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_flow_fingerprint"),
        Index("ix_flows_time_pair", "start", "source_device_id", "destination_device_id"),
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
    error: Mapped[str | None] = mapped_column(Text)


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    kind: Mapped[str] = mapped_column(String(32))
    client_id: Mapped[str | None] = mapped_column(String(255))
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SavedView(Base):
    __tablename__ = "saved_views"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id: Mapped[str] = mapped_column(ForeignKey("app_users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    page: Mapped[str] = mapped_column(String(64))
    state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
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
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    collector_node_id: Mapped[str | None] = mapped_column(String(128), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    scope: Mapped[str] = mapped_column(String(64), default="single_collector_node")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
