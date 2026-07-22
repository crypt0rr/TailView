from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import socket
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import structlog
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .db import SessionLocal, engine
from .models import (
    Capability,
    Device,
    DeviceInvite,
    DevicePostureAttribute,
    DevicePostureState,
    Finding,
    FindingOccurrence,
    FindingTransition,
    NotificationDelivery,
    NotificationEndpoint,
    PolicySnapshot,
    SyncJob,
    TailnetContact,
    TailnetCredential,
    TailnetUser,
)
from .policy import evaluate_device_postures, security_review_policy
from .security import SecretBox

log = structlog.get_logger()
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RETRY_DELAYS = (30, 120, 600, 3600, 21600)


@dataclass(slots=True)
class FindingCandidate:
    source: str
    category: str
    severity: str
    title: str
    summary: str
    remediation: str
    subject_type: str
    subject_id: str
    subject_display: str
    rule_id: str
    visibility: str = "viewer"
    evidence: dict[str, Any] = field(default_factory=dict)
    link_path: str = ""

    @property
    def fingerprint(self) -> str:
        identity = ":".join(
            [self.source, self.category, self.subject_type, self.subject_id, self.rule_id]
        )
        return hashlib.sha256(identity.encode()).hexdigest()


def public_subject_id(value: str) -> str:
    return hashlib.sha256(f"tailview-subject:{value}".encode()).hexdigest()


def _aware(value: datetime | None) -> datetime | None:
    if value and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _device_policy_dict(device: Device) -> dict[str, Any]:
    return {
        "id": device.id,
        "name": device.name,
        "owner_id": device.owner_id,
        "tags": device.tags,
        "addresses": device.addresses,
        "roles": device.roles,
        "primary_role": device.primary_role,
    }


async def collect_findings(
    session: AsyncSession, now: datetime | None = None
) -> tuple[list[FindingCandidate], set[str]]:
    now = now or datetime.now(UTC)
    candidates: list[FindingCandidate] = []
    capabilities = {row.name: row for row in (await session.scalars(select(Capability))).all()}
    complete: set[str] = {"sync_health"}
    devices = (await session.scalars(select(Device).where(Device.active.is_(True)))).all()

    if (
        capabilities.get("device_inventory")
        and capabilities["device_inventory"].status == "available"
    ):
        complete.add("device_keys")
        for device in devices:
            expiry = _aware(device.key_expiry)
            if (
                device.key_expiry_disabled is False
                and expiry
                and timedelta(0) < expiry - now <= timedelta(days=14)
            ):
                candidates.append(
                    FindingCandidate(
                        source="device_keys",
                        category="credential_expiry",
                        severity="high" if expiry - now <= timedelta(days=7) else "medium",
                        title="Device key expires soon",
                        summary=f"{device.name} has a device key expiring within 14 days.",
                        remediation="Reauthenticate the device or review its key-expiry policy.",
                        subject_type="device",
                        subject_id=device.id,
                        subject_display=device.name,
                        rule_id="device-key-within-14-days",
                        evidence={"expires_at": expiry.isoformat()},
                        link_path=f"/devices?device={device.id}",
                    )
                )

    snapshot = await session.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.valid.is_(True))
        .order_by(PolicySnapshot.retrieved_at.desc())
        .limit(1)
    )
    policy_capability = capabilities.get("policy")
    if snapshot and policy_capability and policy_capability.status == "available":
        complete.add("policy")
        users = (
            await session.scalars(select(TailnetUser).where(TailnetUser.active.is_(True)))
        ).all()
        review = security_review_policy(
            snapshot.normalized,
            [_device_policy_dict(device) for device in devices],
            [
                {
                    "id": user.id,
                    "login_name": user.login_name,
                    "display_name": user.display_name,
                }
                for user in users
            ],
        )
        for item in review["findings"]:
            path = str(item["path"])
            candidates.append(
                FindingCandidate(
                    source="policy",
                    category=str(item["category"]),
                    severity=str(item["severity"]),
                    title=str(item["title"]),
                    summary=str(item["evidence"]),
                    remediation=str(item["recommendation"]),
                    subject_type="policy_rule",
                    subject_id=public_subject_id(path),
                    subject_display=path,
                    rule_id=str(item["id"]),
                    evidence={
                        "path": path,
                        "confidence": item.get("confidence"),
                        "affected_pair_count": item.get("affected_pair_count"),
                    },
                    link_path="/policy",
                )
            )

    posture_capability = capabilities.get("device_posture")
    if snapshot and posture_capability and posture_capability.status == "available":
        complete.add("posture")
        states = {
            row.device_id: row for row in (await session.scalars(select(DevicePostureState))).all()
        }
        attributes = (
            await session.scalars(
                select(DevicePostureAttribute).where(DevicePostureAttribute.present.is_(True))
            )
        ).all()
        by_device: dict[str, list[DevicePostureAttribute]] = {}
        for attribute in attributes:
            by_device.setdefault(attribute.device_id, []).append(attribute)
        for device in devices:
            state = states.get(device.id)
            if state and state.status == "stale":
                candidates.append(
                    FindingCandidate(
                        source="posture",
                        category="stale_evidence",
                        severity="medium",
                        title="Device posture evidence is stale",
                        summary=f"The last successful posture snapshot for {device.name} is stale.",
                        remediation=(
                            "Review posture synchronization and the device's API availability."
                        ),
                        subject_type="device",
                        subject_id=device.id,
                        subject_display=device.name,
                        rule_id="stale-posture-evidence",
                        evidence={"last_success": str(state.last_success)},
                        link_path=f"/devices?device={device.id}",
                    )
                )
                continue
            values = {item.key: item.value for item in by_device.get(device.id, [])}
            expiries = {item.key: _aware(item.expiry) for item in by_device.get(device.id, [])}
            applicable = "subnet_router" not in (device.roles or []) and not any(
                (device.raw or {}).get(key)
                for key in ("isExternal", "isShared", "shared", "sharedTo", "sharedWith")
            )
            results = evaluate_device_postures(
                snapshot.normalized,
                values,
                expiries,
                data_available=bool(state and state.status == "available"),
                applicable=applicable,
                now=now,
            )
            for result in results:
                if result["status"] != "fail":
                    continue
                candidates.append(
                    FindingCandidate(
                        source="posture",
                        category="posture_failure",
                        severity="high",
                        title="Device fails a current policy posture",
                        summary=f"{device.name} fails {result['name']} against current evidence.",
                        remediation="Review the failed assertions and affected policy access.",
                        subject_type="device",
                        subject_id=device.id,
                        subject_display=device.name,
                        rule_id=f"posture-failure:{result['name']}",
                        evidence={"posture": result["name"], "assertions": result["assertions"]},
                        link_path=f"/devices?device={device.id}",
                    )
                )

    if capabilities.get("credential_inventory") and (
        capabilities["credential_inventory"].status == "available"
    ):
        complete.add("governance_credentials")
        credentials = (await session.scalars(select(TailnetCredential))).all()
        for credential in credentials:
            if not credential.present or credential.stale or credential.revoked is True:
                continue
            subject = public_subject_id(credential.id)
            label = credential.description or credential.display_id
            if credential.credential_type == "auth_key" and credential.reusable is True:
                candidates.append(
                    FindingCandidate(
                        source="governance_credentials",
                        category="reusable_auth_key",
                        severity="high",
                        title="Reusable authentication key",
                        summary=f"{label} is an active reusable authentication key.",
                        remediation="Confirm continued need and protect it in a secrets manager.",
                        subject_type="credential",
                        subject_id=subject,
                        subject_display=label,
                        rule_id="reusable-auth-key",
                        visibility="administrator",
                        evidence={"reusable": True, "type": credential.credential_type},
                        link_path="/security/governance",
                    )
                )
            expiry = _aware(credential.expires_at)
            if expiry and timedelta(0) < expiry - now <= timedelta(days=30):
                candidates.append(
                    FindingCandidate(
                        source="governance_credentials",
                        category="credential_expiry",
                        severity="high" if expiry - now <= timedelta(days=7) else "medium",
                        title="Tailnet credential expires soon",
                        summary=f"{label} expires within 30 days.",
                        remediation="Rotate or remove the credential before expiry.",
                        subject_type="credential",
                        subject_id=subject,
                        subject_display=label,
                        rule_id="credential-within-30-days",
                        visibility="administrator",
                        evidence={"expires_at": expiry.isoformat()},
                        link_path="/security/governance",
                    )
                )
            write_scopes = [
                scope
                for scope in credential.scopes
                if scope == "all" or not scope.endswith(":read")
            ]
            if write_scopes:
                candidates.append(
                    FindingCandidate(
                        source="governance_credentials",
                        category="write_capable_scope",
                        severity="high" if "all" in write_scopes else "medium",
                        title="Credential has write-capable scope",
                        summary=f"{label} reports one or more write-capable scopes.",
                        remediation=(
                            "Prefer equivalent read-only scopes when mutation is unnecessary."
                        ),
                        subject_type="credential",
                        subject_id=subject,
                        subject_display=label,
                        rule_id="write-capable-scope",
                        visibility="administrator",
                        evidence={"scopes": write_scopes},
                        link_path="/security/governance",
                    )
                )

    if capabilities.get("device_invites") and capabilities["device_invites"].status == "available":
        complete.add("governance_invites")
        invites = (
            await session.scalars(select(DeviceInvite).where(DeviceInvite.present.is_(True)))
        ).all()
        for invite in invites:
            if invite.status not in {"pending", "created", "unknown"}:
                continue
            created_at = _aware(invite.created_at)
            expires_at = _aware(invite.expires_at)
            age_days = (now - created_at).days if created_at else None
            expiring = bool(expires_at and timedelta(0) < expires_at - now <= timedelta(days=7))
            if (age_days is None or age_days < 14) and not expiring:
                continue
            candidates.append(
                FindingCandidate(
                    source="governance_invites",
                    category="pending_device_invite",
                    severity="medium",
                    title="Device invitation remains pending",
                    summary="A device invitation remains pending or is nearing expiry.",
                    remediation="Confirm the invitation is still expected in the admin console.",
                    subject_type="device_invite",
                    subject_id=public_subject_id(invite.id),
                    subject_display=invite.recipient or "Pending device invitation",
                    rule_id="pending-invite-age-or-expiry",
                    visibility="administrator",
                    evidence={
                        "age_days": age_days,
                        "expires_at": expires_at.isoformat() if expires_at else None,
                    },
                    link_path="/security/governance",
                )
            )

    if capabilities.get("tailnet_contacts") and (
        capabilities["tailnet_contacts"].status == "available"
    ):
        complete.add("governance_contacts")
        contacts = (
            await session.scalars(select(TailnetContact).where(TailnetContact.present.is_(True)))
        ).all()
        for contact in contacts:
            if contact.verified is not False:
                continue
            candidates.append(
                FindingCandidate(
                    source="governance_contacts",
                    category="unverified_contact",
                    severity="medium",
                    title="Tailnet contact is unverified",
                    summary="The API explicitly reports a tailnet contact as unverified.",
                    remediation="Complete verification in the Tailscale admin console.",
                    subject_type="tailnet_contact",
                    subject_id=public_subject_id(contact.contact_type),
                    subject_display=contact.contact_type,
                    rule_id="contact-unverified",
                    visibility="administrator",
                    evidence={"verified": False},
                    link_path="/security/governance",
                )
            )

    jobs = (
        await session.scalars(select(SyncJob).order_by(SyncJob.started_at.desc()).limit(300))
    ).all()
    by_kind: dict[str, list[SyncJob]] = {}
    for job in jobs:
        by_kind.setdefault(job.kind, []).append(job)
    for kind, source_jobs in by_kind.items():
        capability_name = {
            "flows": "network_flow_logs",
            "audit": "configuration_audit_logs",
            "devices": "device_inventory",
            "users": "user_inventory",
            "posture": "device_posture",
            "tailnet_settings": "feature_settings",
        }.get(kind, kind)
        capability = capabilities.get(capability_name)
        if capability and capability.status in {
            "permission_denied",
            "feature_disabled",
            "plan_unavailable",
            "unsupported",
        }:
            continue
        if len(source_jobs) >= 2 and all(job.status == "failed" for job in source_jobs[:2]):
            candidates.append(
                FindingCandidate(
                    source="sync_health",
                    category="repeated_sync_failure",
                    severity="high",
                    title="Synchronization repeatedly failed",
                    summary=f"The {kind} source failed in two consecutive executions.",
                    remediation="Inspect Sync jobs and the capability remediation details.",
                    subject_type="sync_source",
                    subject_id=public_subject_id(kind),
                    subject_display=kind,
                    rule_id="two-consecutive-failures",
                    evidence={"kind": kind, "latest_job": source_jobs[0].id},
                    link_path="/sync",
                )
            )
    return candidates, complete


def _transition(
    session: AsyncSession,
    finding: Finding,
    to_status: str,
    actor_id: str | None = None,
    reason: str = "",
) -> None:
    session.add(
        FindingTransition(
            finding_id=finding.id,
            from_status=finding.status,
            to_status=to_status,
            actor_id=actor_id,
            reason=reason,
        )
    )
    finding.status = to_status


async def _queue_event(
    session: AsyncSession, finding: Finding, event_type: str, now: datetime
) -> None:
    app_url = get_settings().app_url.rstrip("/")
    safe_path = finding.link_path.split("?", 1)[0]
    endpoints = (
        await session.scalars(
            select(NotificationEndpoint).where(NotificationEndpoint.enabled.is_(True))
        )
    ).all()
    for endpoint in endpoints:
        if event_type == "resolved" and not endpoint.include_resolved:
            continue
        if endpoint.sources and finding.source not in endpoint.sources:
            continue
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[endpoint.minimum_severity]:
            continue
        event_id = str(uuid.uuid4())
        payload = {
            "schemaVersion": "1",
            "eventId": event_id,
            "eventType": event_type,
            "occurredAt": now.isoformat(),
            "finding": {
                "id": finding.id,
                "source": finding.source,
                "category": finding.category,
                "severity": finding.severity,
                "status": finding.status,
                "title": finding.title,
                "subject": {"type": finding.subject_type, "display": finding.subject_display},
                "summary": finding.summary,
                "firstSeen": finding.first_seen.isoformat(),
                "lastSeen": finding.last_seen.isoformat(),
                "url": f"{app_url}{safe_path}" if safe_path else app_url,
            },
        }
        session.add(
            NotificationDelivery(
                endpoint_id=endpoint.id,
                finding_id=finding.id,
                event_type=event_type,
                idempotency_key=f"{endpoint.id}:{event_id}",
                payload=payload,
                next_attempt=now,
            )
        )


async def evaluate_findings(session: AsyncSession, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(UTC)
    candidates, complete_sources = await collect_findings(session, now)
    seen: dict[str, set[str]] = {source: set() for source in complete_sources}
    created = reopened = resolved = 0
    for candidate in candidates:
        seen.setdefault(candidate.source, set()).add(candidate.fingerprint)
        finding = await session.scalar(
            select(Finding).where(Finding.fingerprint == candidate.fingerprint)
        )
        event_type: str | None = None
        if finding is None:
            finding = Finding(
                id=candidate.fingerprint,
                fingerprint=candidate.fingerprint,
                source=candidate.source,
                category=candidate.category,
                severity=candidate.severity,
                title=candidate.title,
                summary=candidate.summary,
                remediation=candidate.remediation,
                subject_type=candidate.subject_type,
                subject_id=candidate.subject_id,
                subject_display=candidate.subject_display,
                visibility=candidate.visibility,
                evidence=candidate.evidence,
                link_path=candidate.link_path,
                first_seen=now,
                last_seen=now,
                last_evaluated=now,
            )
            session.add(finding)
            await session.flush()
            session.add(
                FindingTransition(finding_id=finding.id, from_status=None, to_status="open")
            )
            session.add(
                FindingOccurrence(
                    finding_id=finding.id,
                    event_type="opened",
                    severity=candidate.severity,
                    evidence=candidate.evidence,
                    occurred_at=now,
                )
            )
            created += 1
            event_type = "opened"
        else:
            old_severity = finding.severity
            old_evidence = finding.evidence
            suppression = _aware(finding.suppressed_until)
            if finding.status == "suppressed" and suppression and suppression <= now:
                _transition(session, finding, "open", reason="Suppression expired")
            if finding.status == "resolved":
                _transition(session, finding, "open", reason="Finding recurred")
                finding.resolved_at = None
                finding.occurrence_count += 1
                reopened += 1
                event_type = "reopened"
            if SEVERITY_ORDER[candidate.severity] < SEVERITY_ORDER.get(old_severity, 99):
                if finding.status == "acknowledged":
                    _transition(session, finding, "open", reason="Severity increased")
                event_type = "severity_increased"
            finding.severity = candidate.severity
            finding.title = candidate.title
            finding.summary = candidate.summary
            finding.remediation = candidate.remediation
            finding.subject_display = candidate.subject_display
            finding.evidence = candidate.evidence
            finding.link_path = candidate.link_path
            if event_type or old_evidence != candidate.evidence:
                session.add(
                    FindingOccurrence(
                        finding_id=finding.id,
                        event_type=event_type or "evidence_changed",
                        severity=candidate.severity,
                        evidence=candidate.evidence,
                        occurred_at=now,
                    )
                )
        finding.last_seen = now
        finding.last_evaluated = now
        finding.stale = False
        if event_type:
            await _queue_event(session, finding, event_type, now)

    existing = (await session.scalars(select(Finding).where(Finding.status != "resolved"))).all()
    for finding in existing:
        if finding.source not in complete_sources:
            finding.stale = True
            continue
        finding.last_evaluated = now
        if finding.fingerprint not in seen.get(finding.source, set()):
            _transition(session, finding, "resolved", reason="Absent from complete evaluation")
            finding.resolved_at = now
            finding.stale = False
            resolved += 1
            await _queue_event(session, finding, "resolved", now)
    await session.commit()
    return {"created": created, "reopened": reopened, "resolved": resolved}


async def _advisory_lock(key: int) -> Any:
    connection = await engine.connect()
    if connection.dialect.name == "postgresql":
        acquired = bool(
            await connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key})
        )
        await connection.commit()
        if not acquired:
            await connection.close()
            return None
    return connection


async def _advisory_unlock(connection: Any, key: int) -> None:
    try:
        if connection.dialect.name == "postgresql":
            await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": key})
            await connection.commit()
    finally:
        await connection.close()


async def evaluate_findings_job() -> None:
    lock = await _advisory_lock(81201)
    if lock is None:
        return
    try:
        async with SessionLocal() as session:
            result = await evaluate_findings(session)
            log.info("findings_evaluated", **result)
    finally:
        await _advisory_unlock(lock, 81201)


def sanitized_url(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def _host_allowed(
    host: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allow: list[str],
) -> bool:
    if host.casefold() in {value.casefold() for value in allow}:
        return True
    for value in allow:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


async def validate_webhook_url(value: str, settings: Settings) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in ({"https"} if settings.production else {"http", "https"}):
        raise ValueError("Webhook URL must use HTTPS in production")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL must contain a host and no embedded credentials")
    addresses = await asyncio.to_thread(
        socket.getaddrinfo,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )
    if not addresses:
        raise ValueError("Webhook hostname did not resolve")
    for result in addresses:
        address = ipaddress.ip_address(result[4][0])
        if not address.is_global and not _host_allowed(
            parsed.hostname, address, settings.alert_webhook_host_allowlist
        ):
            raise ValueError("Webhook destination is not public or explicitly allowlisted")
    return sanitized_url(value)


async def deliver_notifications(
    session: AsyncSession, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(UTC)
    due = (
        await session.scalars(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.status.in_(["pending", "retrying"]),
                NotificationDelivery.next_attempt <= now,
            )
            .order_by(NotificationDelivery.next_attempt)
            .limit(100)
        )
    ).all()
    delivered = failed = 0
    box = SecretBox(settings.encryption_key)
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        for delivery in due:
            endpoint = await session.get(NotificationEndpoint, delivery.endpoint_id)
            if endpoint is None or not endpoint.enabled:
                delivery.status = "cancelled"
                continue
            try:
                url = box.decrypt(endpoint.encrypted_url)
                await validate_webhook_url(url, settings)
                body = json.dumps(delivery.payload, sort_keys=True, separators=(",", ":")).encode()
                timestamp = str(int(now.timestamp()))
                secret = box.decrypt(endpoint.encrypted_secret)
                signature = hmac.new(
                    secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
                ).hexdigest()
                response = await client.post(
                    url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-TailView-Timestamp": timestamp,
                        "X-TailView-Signature": f"sha256={signature}",
                        "X-TailView-Event-ID": str(delivery.payload.get("eventId", delivery.id)),
                        "X-TailView-Schema-Version": "1",
                        "Idempotency-Key": delivery.idempotency_key,
                    },
                )
                delivery.attempt_count += 1
                delivery.last_attempt = now
                delivery.http_status = response.status_code
                if 200 <= response.status_code < 300:
                    delivery.status = "delivered"
                    delivery.delivered_at = now
                    delivery.error_class = None
                    delivered += 1
                elif response.status_code == 410:
                    delivery.status = "failed"
                    delivery.error_class = "endpoint_gone"
                    endpoint.enabled = False
                    failed += 1
                elif response.status_code == 429 or response.status_code >= 500:
                    retry_after = response.headers.get("retry-after", "")
                    delay = (
                        int(retry_after)
                        if retry_after.isdigit()
                        else RETRY_DELAYS[min(delivery.attempt_count - 1, len(RETRY_DELAYS) - 1)]
                    )
                    if delivery.attempt_count > len(RETRY_DELAYS):
                        delivery.status = "failed"
                        failed += 1
                    else:
                        delivery.status = "retrying"
                        delivery.next_attempt = now + timedelta(seconds=min(delay, 21600))
                    delivery.error_class = f"http_{response.status_code}"
                else:
                    delivery.status = "failed"
                    delivery.error_class = f"http_{response.status_code}"
                    failed += 1
            except Exception as exc:
                delivery.attempt_count += 1
                delivery.last_attempt = now
                delivery.error_class = type(exc).__name__
                if delivery.attempt_count > len(RETRY_DELAYS):
                    delivery.status = "failed"
                    failed += 1
                else:
                    delivery.status = "retrying"
                    delivery.next_attempt = now + timedelta(
                        seconds=RETRY_DELAYS[min(delivery.attempt_count - 1, len(RETRY_DELAYS) - 1)]
                    )
            await session.commit()
    return {"processed": len(due), "delivered": delivered, "failed": failed}


async def deliver_notifications_job() -> None:
    lock = await _advisory_lock(81202)
    if lock is None:
        return
    try:
        async with SessionLocal() as session:
            await deliver_notifications(session, get_settings())
    finally:
        await _advisory_unlock(lock, 81202)


async def cleanup_findings_job() -> None:
    settings = get_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.findings_retention_days)
    async with SessionLocal() as session:
        old_ids = select(Finding.id).where(
            Finding.status == "resolved", Finding.resolved_at < cutoff
        )
        await session.execute(
            delete(NotificationDelivery).where(NotificationDelivery.created_at < cutoff)
        )
        await session.execute(delete(Finding).where(Finding.id.in_(old_ids)))
        await session.commit()
