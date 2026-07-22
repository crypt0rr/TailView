from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "production"
    app_url: str = "http://localhost:8080"
    database_url: str = "postgresql+psycopg://tailview:tailview@database:5432/tailview"
    setup_token: str = Field(default="change-me-before-starting", alias="TAILVIEW_SETUP_TOKEN")
    encryption_key: str = Field(default="", alias="TAILVIEW_ENCRYPTION_KEY")
    cookie_secure: bool = True
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    demo_mode: bool = False
    tailscale_tailnet: str = ""
    tailscale_api_token: str = ""
    tailscale_oauth_client_id: str = ""
    tailscale_oauth_client_secret: str = ""
    cors_origins: list[str] = []
    log_level: str = "INFO"
    inventory_interval_seconds: int = 300
    posture_interval_seconds: int = 300
    security_settings_interval_seconds: int = 900
    governance_interval_seconds: int = 900
    findings_interval_seconds: int = 300
    findings_retention_days: int = 180
    alert_webhook_host_allowlist: list[str] = []
    policy_interval_seconds: int = 300
    flow_interval_seconds: int = 60
    audit_interval_seconds: int = 300
    flow_retention_days: int = 30
    raw_payload_retention_days: int = 7
    export_row_limit: int = Field(default=10000, ge=1, le=100000)
    saved_view_limit: int = Field(default=50, ge=1, le=500)
    trusted_proxies: list[str] = []
    telemetry_secret: str = Field(default="", alias="TAILVIEW_TELEMETRY_SECRET")

    @field_validator("setup_token")
    @classmethod
    def setup_token_strength(cls, value: str) -> str:
        if len(value) < 20 and value != "change-me-before-starting":
            raise ValueError("TAILVIEW_SETUP_TOKEN must contain at least 20 characters")
        return value

    @property
    def production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
