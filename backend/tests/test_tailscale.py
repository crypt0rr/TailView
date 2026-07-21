import httpx
import pytest
import respx

from app.tailscale import TailscaleClient, TailscaleError, capability_status


@pytest.mark.asyncio
@respx.mock
async def test_device_client_uses_bearer_and_documented_path() -> None:
    route = respx.get("https://api.tailscale.com/api/v2/tailnet/example.com/devices").mock(
        return_value=httpx.Response(200, json={"devices": [{"id": "n1"}]})
    )
    client = TailscaleClient("example.com", api_token="test-token")
    assert await client.devices() == [{"id": "n1"}]
    assert route.calls[0].request.headers["authorization"] == "Bearer test-token"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_permission_error_is_safe_and_classified() -> None:
    respx.get("https://api.tailscale.com/api/v2/tailnet/example.com/users").mock(
        return_value=httpx.Response(403, json={"message": "denied"})
    )
    client = TailscaleClient("example.com", api_token="test-token")
    with pytest.raises(TailscaleError) as caught:
        await client.users()
    assert caught.value.status == 403
    assert capability_status(caught.value) == "permission_denied"
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_client_retries_read_timeout_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("app.tailscale.asyncio.sleep", no_sleep)
    route = respx.get("https://api.tailscale.com/api/v2/tailnet/example.com/devices").mock(
        side_effect=[
            httpx.ReadTimeout("slow upstream response"),
            httpx.Response(200, json={"devices": [{"nodeId": "n1"}]}),
        ]
    )
    client = TailscaleClient("example.com", api_token="test-token")

    assert await client.devices() == [{"nodeId": "n1"}]
    assert route.call_count == 2
    await client.close()
