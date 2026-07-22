from __future__ import annotations

import base64
import hashlib
import hmac
import json
import socket
from datetime import UTC, datetime, timedelta

import pytest
import respx
from httpx import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import findings as finding_service
from app.api import acknowledge_finding, findings_list, suppress_finding
from app.config import Settings
from app.findings import (
    FindingCandidate,
    deliver_notifications,
    evaluate_findings,
    validate_webhook_url,
)
from app.models import (
    AppUser,
    Base,
    Finding,
    FindingOccurrence,
    FindingTransition,
    NotificationDelivery,
    NotificationEndpoint,
)
from app.schemas import FindingActionRequest, FindingSuppressRequest
from app.security import SecretBox


def candidate(severity: str = "medium") -> FindingCandidate:
    return FindingCandidate(
        source="policy",
        category="broad_access",
        severity=severity,
        title="Broad host access",
        summary="A source can reach a broad destination selector.",
        remediation="Narrow the selector after validating required access.",
        subject_type="policy_rule",
        subject_id="public-rule-reference",
        subject_display="grants[0]",
        rule_id="broad-destination",
        evidence={"path": "grants[0]"},
        link_path="/policy",
    )


def administrator() -> AppUser:
    return AppUser(id="admin-1", username="admin", password_hash="unused", role="administrator")


@pytest.mark.asyncio
async def test_finding_lifecycle_deduplicates_resolves_and_reopens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    current = [candidate()]

    async def collect(*_: object, **__: object) -> tuple[list[FindingCandidate], set[str]]:
        return current, {"policy"}

    monkeypatch.setattr(finding_service, "collect_findings", collect)
    now = datetime.now(UTC)
    async with factory() as session:
        first = await evaluate_findings(session, now)
        second = await evaluate_findings(session, now + timedelta(minutes=5))
        finding = await session.scalar(select(Finding))
        occurrences = (await session.scalars(select(FindingOccurrence))).all()
        assert first == {"created": 1, "reopened": 0, "resolved": 0}
        assert second == {"created": 0, "reopened": 0, "resolved": 0}
        assert finding is not None and finding.occurrence_count == 1
        assert [row.event_type for row in occurrences] == ["opened"]

        current.clear()
        resolved = await evaluate_findings(session, now + timedelta(minutes=10))
        assert resolved["resolved"] == 1
        assert finding.status == "resolved"

        current.append(candidate("high"))
        reopened = await evaluate_findings(session, now + timedelta(minutes=15))
        assert reopened["reopened"] == 1
        assert finding.status == "open"
        assert finding.severity == "high"
        assert finding.occurrence_count == 2
    await engine.dispose()


@pytest.mark.asyncio
async def test_incomplete_evaluation_retains_finding_as_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    responses = [([candidate()], {"policy"}), ([], set())]

    async def collect(*_: object, **__: object) -> tuple[list[FindingCandidate], set[str]]:
        return responses.pop(0)

    monkeypatch.setattr(finding_service, "collect_findings", collect)
    async with factory() as session:
        await evaluate_findings(session)
        await evaluate_findings(session)
        finding = await session.scalar(select(Finding))
        assert finding is not None
        assert finding.status == "open"
        assert finding.stale is True
    await engine.dispose()


@pytest.mark.asyncio
async def test_admin_actions_and_viewer_visibility(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def collect(*_: object, **__: object) -> tuple[list[FindingCandidate], set[str]]:
        return [candidate()], {"policy"}

    monkeypatch.setattr(finding_service, "collect_findings", collect)
    async with factory() as session:
        session.add(administrator())
        await session.commit()
        await evaluate_findings(session)
        finding = await session.scalar(select(Finding))
        assert finding is not None
        admin = administrator()
        admin.id = "admin-1"
        await acknowledge_finding(
            finding.id, FindingActionRequest(reason="Investigating"), admin, None, session
        )
        assert finding.status == "acknowledged"
        finding.severity = "low"
        await session.commit()
        await evaluate_findings(session)
        assert finding.status == "open"
        assert finding.severity == "medium"
        await suppress_finding(
            finding.id,
            FindingSuppressRequest(duration="1h", reason="Approved maintenance"),
            admin,
            None,
            session,
        )
        assert finding.status == "suppressed"
        transitions = (await session.scalars(select(FindingTransition))).all()
        assert [row.to_status for row in transitions][-3:] == [
            "acknowledged",
            "open",
            "suppressed",
        ]

        finding.suppressed_until = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
        await evaluate_findings(session)
        assert finding.status == "open"

        viewer = AppUser(username="viewer", password_hash="unused", role="viewer")
        list_args = {
            "cursor": None,
            "limit": 50,
            "status_filter": "",
            "severity": "",
            "source": "",
            "category": "",
            "subject": "",
            "assigned_to": "",
            "search": "",
        }
        page = await findings_list(viewer, session, **list_args)
        assert len(page["items"]) == 1
        finding.visibility = "administrator"
        await session.commit()
        hidden = await findings_list(viewer, session, **list_args)
        assert hidden["items"] == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_webhook_destination_validation_blocks_private_unless_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def private_address(*_: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", private_address)
    settings = Settings(
        environment="production",
        alert_webhook_host_allowlist=[],
    )
    with pytest.raises(ValueError, match="not public"):
        await validate_webhook_url("https://hooks.example.test/path?secret=value", settings)

    allowed = Settings(
        environment="production",
        alert_webhook_host_allowlist=["hooks.example.test"],
    )
    display = await validate_webhook_url("https://hooks.example.test/path?secret=value", allowed)
    assert display == "https://hooks.example.test/path"


@pytest.mark.asyncio
async def test_webhook_delivery_encrypts_secrets_and_signs_exact_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def public_address(*_: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", public_address)
    engine = create_async_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    settings = Settings.model_validate(
        {"environment": "production", "TAILVIEW_ENCRYPTION_KEY": key}
    )
    box = SecretBox(key)
    secret = "".join(["test", "-signing-secret"])
    payload = {"schemaVersion": "1", "eventId": "event-1", "message": "safe"}
    now = datetime(2026, 7, 22, 10, 0, tzinfo=UTC)
    async with factory() as session:
        endpoint = NotificationEndpoint(
            name="SOC",
            url_display="https://hooks.example.test/tailview",
            encrypted_url=box.encrypt("https://hooks.example.test/tailview"),
            encrypted_secret=box.encrypt(secret),
        )
        session.add(endpoint)
        await session.flush()
        delivery = NotificationDelivery(
            endpoint_id=endpoint.id,
            event_type="opened",
            idempotency_key="event-1",
            payload=payload,
            next_attempt=now,
        )
        session.add(delivery)
        await session.commit()

        assert secret.encode() not in endpoint.encrypted_secret
        with respx.mock(assert_all_called=True) as mocked:
            route = mocked.post("https://hooks.example.test/tailview").mock(
                return_value=Response(202)
            )
            result = await deliver_notifications(session, settings, now)
        request = route.calls[0].request
        body = request.content
        timestamp = str(int(now.timestamp()))
        expected = hmac.new(
            secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
        ).hexdigest()
        assert json.loads(body) == payload
        assert request.headers["X-TailView-Signature"] == f"sha256={expected}"
        assert request.headers["X-TailView-Event-ID"] == "event-1"
        assert request.headers["Idempotency-Key"] == "event-1"
        assert result == {"processed": 1, "delivered": 1, "failed": 0}
        assert delivery.status == "delivered"
    await engine.dispose()


def test_finding_fingerprint_is_stable_and_evidence_independent() -> None:
    left = candidate()
    right = candidate()
    right.evidence = {"path": "grants[0]", "count": 999}
    assert left.fingerprint == right.fingerprint
    right.rule_id = "different-rule"
    assert left.fingerprint != right.fingerprint
