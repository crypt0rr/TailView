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
    display_name: str = ""
    must_change_password: bool = False
    mfa_enabled: bool = False
    mfa_required: bool = False
    auth_status: Literal["authenticated", "password_change_required", "mfa_enrollment_required"] = (
        "authenticated"
    )


class AuthResult(BaseModel):
    status: Literal[
        "authenticated", "password_change_required", "mfa_enrollment_required", "mfa_required"
    ]
    user: UserResponse | None = None
    challenge: str | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MfaPasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=64)


class MfaVerifyRequest(MfaCodeRequest):
    challenge: str = Field(min_length=32, max_length=256)


class AppUserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=255, pattern=r"^[A-Za-z0-9_.@-]+$")
    display_name: str = Field(default="", max_length=255)
    role: Literal["administrator", "viewer"] = "viewer"
    temporary_password: str = Field(min_length=12, max_length=256)


class AppUserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: Literal["administrator", "viewer"] | None = None
    active: bool | None = None


class AppUserPasswordResetRequest(BaseModel):
    temporary_password: str = Field(min_length=12, max_length=256)


class AuthPolicyRequest(BaseModel):
    required_roles: list[Literal["administrator", "viewer"]] = Field(max_length=2)


class SavedViewCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    page: str = Field(min_length=1, max_length=64)
    visibility: Literal["private", "shared"] = "private"
    state: dict[str, Any]
    schema_version: Literal[1] = 1


class SavedViewUpdateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)
    visibility: Literal["private", "shared"] = "private"
    state: dict[str, Any]
    schema_version: Literal[1] = 1
    expected_revision: int = Field(ge=1)


class SavedViewCloneRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    visibility: Literal["private", "shared"] = "private"


class SavedViewDefaultRequest(BaseModel):
    view_id: str | None = Field(default=None, max_length=36)


class ReportGenerateRequest(BaseModel):
    saved_view_id: str = Field(min_length=1, max_length=36)
    range: Literal["24h", "7d", "30d", "90d", "13mo"] | None = None
    title: str = Field(default="", max_length=255)


class ReportScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    saved_view_id: str = Field(min_length=1, max_length=36)
    frequency: Literal["daily", "weekly", "monthly"]
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    local_time: str = Field(default="08:00", pattern=r"^(?:[01]\d|2[0-3]):[0-5]\d$")
    weekday: int | None = Field(default=None, ge=0, le=6)
    month_day: int | None = Field(default=None, ge=1, le=28)
    enabled: bool = True


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
