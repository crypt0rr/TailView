from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class SetupRequest(BaseModel):
    setup_token: str
    username: str = Field(min_length=3, max_length=255, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=256)


class UserResponse(BaseModel):
    id: str
    username: str
    role: Literal["administrator", "viewer"]


class Page(BaseModel):
    items: list[Any]
    next_cursor: str | None = None


class MetadataUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    function: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, max_length=64)
    location: str | None = Field(default=None, max_length=128)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    icon: str | None = Field(default=None, max_length=64)
    hidden: bool = False


class CredentialRequest(BaseModel):
    kind: Literal["oauth", "api_token"]
    client_id: str | None = Field(default=None, max_length=255)
    secret: str = Field(min_length=8, max_length=2048)


class CapabilityResponse(BaseModel):
    name: str
    status: str
    source: str
    requirement: str
    detail: str
    last_success: datetime | None
    checked_at: datetime


class FindingActionRequest(BaseModel):
    reason: str = Field(default="", max_length=1000)


class FindingSuppressRequest(BaseModel):
    duration: Literal["1h", "24h", "7d", "30d", "indefinite"]
    reason: str = Field(min_length=1, max_length=1000)


class FindingAssignRequest(BaseModel):
    user_id: str | None = Field(default=None, max_length=36)


class NotificationEndpointRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=8, max_length=2048)
    minimum_severity: Literal["critical", "high", "medium", "low", "info"] = "high"
    sources: list[str] = Field(default_factory=list, max_length=32)
    include_resolved: bool = False
    enabled: bool = True
