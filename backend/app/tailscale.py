from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class TailscaleError(RuntimeError):
    def __init__(self, status: int, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class TailscaleClient:
    base_url = "https://api.tailscale.com/api/v2"

    def __init__(
        self,
        tailnet: str,
        api_token: str = "",
        client_id: str = "",
        client_secret: str = "",
    ) -> None:
        self.tailnet = tailnet
        self.api_token = api_token
        self.client_id = client_id
        self.client_secret = client_secret
        self._oauth_token: str | None = None
        self._oauth_expires = datetime.min.replace(tzinfo=UTC)
        self.http = httpx.AsyncClient(timeout=httpx.Timeout(30), follow_redirects=False)

    async def close(self) -> None:
        await self.http.aclose()

    async def _token(self) -> str:
        if self.api_token:
            return self.api_token
        if self._oauth_token and self._oauth_expires > datetime.now(UTC):
            return self._oauth_token
        response = await self.http.post(
            f"{self.base_url}/oauth/token",
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
        )
        self._raise(response)
        body = response.json()
        self._oauth_token = str(body["access_token"])
        lifetime = max(30, int(body.get("expires_in", 3600)) - 60)
        self._oauth_expires = datetime.now(UTC) + timedelta(seconds=lifetime)
        return self._oauth_token

    def _raise(self, response: httpx.Response) -> None:
        if response.is_success:
            return
        retry = response.headers.get("retry-after")
        retry_after = int(retry) if retry and retry.isdigit() else None
        try:
            detail = response.json().get("message", "Upstream request failed")
        except Exception:
            detail = "Upstream request failed"
        raise TailscaleError(response.status_code, str(detail), retry_after)

    async def get(self, path: str, params: dict[str, str] | None = None) -> Any:
        token = await self._token()
        for attempt in range(4):
            response = await self.http.get(
                f"{self.base_url}{path}",
                params=params,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
            if response.status_code not in {429, 502, 503, 504}:
                self._raise(response)
                return response.json()
            delay = int(response.headers.get("retry-after", "0") or 0) or 2**attempt
            await asyncio.sleep(min(delay, 30))
        self._raise(response)
        raise AssertionError("unreachable")

    async def get_text(self, path: str, accept: str = "application/hujson") -> str:
        token = await self._token()
        response = await self.http.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": accept},
        )
        self._raise(response)
        return response.text

    async def devices(self) -> list[dict[str, Any]]:
        body = await self.get(f"/tailnet/{self.tailnet}/devices")
        return list(body.get("devices", []))

    async def users(self) -> list[dict[str, Any]]:
        body = await self.get(f"/tailnet/{self.tailnet}/users")
        return list(body.get("users", []))

    async def routes(self, device_id: str) -> dict[str, Any]:
        return dict(await self.get(f"/device/{device_id}/routes"))

    async def policy(self) -> str:
        return await self.get_text(f"/tailnet/{self.tailnet}/acl")

    async def flows(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        body = await self.get(
            f"/tailnet/{self.tailnet}/logging/network",
            {"start": start.isoformat(), "end": end.isoformat()},
        )
        return list(body.get("logs", []))

    async def audit(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        body = await self.get(
            f"/tailnet/{self.tailnet}/logging/configuration",
            {"start": start.isoformat(), "end": end.isoformat()},
        )
        return list(body.get("logs", []))

    async def services(self) -> list[dict[str, Any]]:
        body = await self.get(f"/tailnet/{self.tailnet}/services")
        return list(body.get("services", []))

    async def dns(self) -> dict[str, Any]:
        return dict(await self.get(f"/tailnet/{self.tailnet}/dns/preferences"))

    async def webhooks(self) -> list[dict[str, Any]]:
        body = await self.get(f"/tailnet/{self.tailnet}/webhooks")
        return list(body.get("webhooks", body.get("endpoints", [])))


def capability_status(error: TailscaleError) -> str:
    if error.status in {401, 403}:
        return "permission_denied"
    if error.status == 404:
        return "unsupported"
    if error.status in {402, 409}:
        return "feature_disabled"
    return "upstream_error"
