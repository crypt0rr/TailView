from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

PageName = Literal[
    "devices",
    "exit_nodes",
    "subnet_routers",
    "flows",
    "topology",
    "findings",
    "security_posture",
    "services",
    "access_governance",
]
Range = Literal["1h", "24h", "7d", "30d"]

ALL_PAGES = {
    "devices",
    "exit_nodes",
    "subnet_routers",
    "flows",
    "topology",
    "findings",
    "security_posture",
    "services",
    "access_governance",
}
ADMIN_PAGES = {"access_governance"}


class ViewState(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class DeviceViewState(ViewState):
    search: str = Field(default="", max_length=255)
    status: Literal["", "online", "offline", "unknown"] = ""
    owner: str = Field(default="", max_length=255)
    key_expiry: Literal[
        "", "within_14_days", "expired", "valid", "disabled", "not_reported"
    ] = ""
    posture: Literal["", "pass", "fail", "incomplete_data", "not_applicable"] = ""
    columns: dict[str, bool] = Field(default_factory=dict)

    @field_validator("columns")
    @classmethod
    def valid_columns(cls, value: dict[str, bool]) -> dict[str, bool]:
        allowed = {"status", "role", "owner", "os", "version", "key_expiry"}
        if not set(value).issubset(allowed):
            raise ValueError("Unsupported device column")
        return value


class FlowViewState(ViewState):
    range: Range = "24h"
    category: Literal["", "virtual", "subnet", "exit", "physical"] = ""
    source: str = Field(default="", max_length=255)
    destination: str = Field(default="", max_length=255)
    protocol: str = Field(default="", pattern=r"^(|[0-9]{1,3})$")
    port: str = Field(default="", pattern=r"^(|[0-9]{1,5})$")
    resolution: Literal["all", "resolved", "unresolved"] = "all"
    ranking_limit: Literal[5, 10, 20, 50] = 10

    @field_validator("protocol")
    @classmethod
    def valid_protocol(cls, value: str) -> str:
        if value and int(value) > 255:
            raise ValueError("Protocol must be between 0 and 255")
        return value

    @field_validator("port")
    @classmethod
    def valid_port(cls, value: str) -> str:
        if value and not 1 <= int(value) <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return value


class TopologyViewState(ViewState):
    range: Range = "24h"
    layout: Literal["cose", "breadthfirst", "circle", "concentric", "grid"] = "cose"
    search: str = Field(default="", max_length=255)
    observed: bool = False
    permitted: bool = False
    mode: Literal["graph", "table"] = "graph"


class FindingViewState(ViewState):
    status: Literal["", "open", "acknowledged", "suppressed", "resolved"] = ""
    severity: Literal["", "critical", "high", "medium", "low", "info"] = ""
    source: str = Field(default="", max_length=64)
    category: str = Field(default="", max_length=64)
    subject: str = Field(default="", max_length=255)
    assigned_to: str = Field(default="", max_length=36)
    search: str = Field(default="", max_length=255)


class PostureViewState(ViewState):
    result: Literal["", "pass", "fail", "incomplete_data", "not_applicable"] = ""
    posture: str = Field(default="", max_length=255)
    attribute: str = Field(default="", max_length=255)
    owner: str = Field(default="", max_length=255)
    os: str = Field(default="", max_length=64)
    expiry: Literal["", "active", "expiring", "expired"] = ""
    stale: Literal["", "true", "false"] = ""


class ServiceViewState(ViewState):
    search: str = Field(default="", max_length=255)
    status: Literal[
        "", "connected", "offline", "pending_approval", "draining",
        "pre-approved", "needs_configuration", "unknown"
    ] = ""
    host: str = Field(default="", max_length=255)


class GovernanceViewState(ViewState):
    tab: Literal["credentials", "invites", "contacts", "streams"] = "credentials"
    search: str = Field(default="", max_length=255)
    credential_type: Literal[
        "", "auth_key", "api_access_token", "oauth_credential", "federated_credential"
    ] = ""
    status: Literal["", "active", "expired", "revoked", "stale", "inactive"] = ""


STATE_MODELS: dict[str, type[ViewState]] = {
    "devices": DeviceViewState,
    "exit_nodes": DeviceViewState,
    "subnet_routers": DeviceViewState,
    "flows": FlowViewState,
    "topology": TopologyViewState,
    "findings": FindingViewState,
    "security_posture": PostureViewState,
    "services": ServiceViewState,
    "access_governance": GovernanceViewState,
}


def page_allowed(page: str, role: str) -> bool:
    return page in ALL_PAGES and (page not in ADMIN_PAGES or role == "administrator")


def normalize_state(page: str, state: dict[str, Any], max_bytes: int = 16_384) -> dict[str, Any]:
    model = STATE_MODELS.get(page)
    if model is None:
        raise ValueError("Unsupported saved-view page")
    try:
        normalized = model.model_validate(state).model_dump(mode="json")
    except ValidationError as exc:
        raise ValueError("Invalid saved-view state") from exc
    if len(json.dumps(normalized, separators=(",", ":")).encode()) > max_bytes:
        raise ValueError("Saved-view state exceeds 16 KB")
    return normalized


def compatible_state(page: str, schema_version: int, state: dict[str, Any]) -> bool:
    if schema_version != 1:
        return False
    try:
        normalize_state(page, state)
        return True
    except ValueError:
        return False
