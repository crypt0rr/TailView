from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import Settings, get_settings
from .db import get_db
from .models import (
    AppUser,
    AuthChallenge,
    AuthPolicy,
    LocalSecurityEvent,
    LoginAttempt,
    MfaCredential,
    MfaRecoveryCode,
    Session,
)
from .schemas import AuthResult, LoginRequest, SetupRequest, UserResponse
from .security import (
    SecretBox,
    hash_password,
    new_recovery_codes,
    new_token,
    session_expiry,
    token_hash,
    verify_password,
    verify_totp,
)

SESSION_COOKIE = "tailview_session"
CSRF_COOKIE = "tailview_csrf"


def source_address(request: Request) -> str:
    return (request.client.host if request.client else "unknown")[:128]


def safe_user_agent(request: Request) -> str:
    value = request.headers.get("user-agent", "")
    return "".join(character for character in value if character.isprintable())[:512]


def enforce_public_origin(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    expected = settings.app_url.rstrip("/")
    if origin and origin.rstrip("/") != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin check failed")
    if not origin and referer and not referer.startswith(f"{expected}/"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Referer check failed")


def add_security_event(
    db: AsyncSession,
    request: Request,
    event: str,
    *,
    actor_id: str | None = None,
    subject_id: str | None = None,
    result: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        LocalSecurityEvent(
            event=event,
            actor_id=actor_id,
            subject_id=subject_id,
            correlation_id=getattr(request.state, "correlation_id", ""),
            source_address=source_address(request),
            user_agent=safe_user_agent(request),
            result=result,
            details=details or {},
        )
    )


async def auth_policy(db: AsyncSession) -> AuthPolicy:
    policy = await db.get(AuthPolicy, "current")
    if policy is None:
        policy = AuthPolicy(id="current", required_roles=[])
        db.add(policy)
        await db.flush()
    return policy


async def mfa_required(db: AsyncSession, user: AppUser) -> bool:
    return user.role in (await auth_policy(db)).required_roles


async def response_for_user(
    db: AsyncSession, user: AppUser, session: Session | None = None
) -> UserResponse:
    required = await mfa_required(db, user)
    if user.must_change_password:
        auth_status = "password_change_required"
    elif required and not user.mfa_enabled:
        auth_status = "mfa_enrollment_required"
    else:
        auth_status = "authenticated"
    if session is not None:
        session.restricted = auth_status != "authenticated"
    return UserResponse(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        must_change_password=user.must_change_password,
        mfa_enabled=user.mfa_enabled,
        mfa_required=required,
        auth_status=auth_status,
    )


def _set_cookies(response: Response, session_token: str, csrf: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
        max_age=settings.session_absolute_hours * 3600,
    )


async def create_session(
    db: AsyncSession,
    user: AppUser,
    response: Response,
    settings: Settings,
    request: Request,
) -> tuple[Session, UserResponse]:
    session_token, csrf = new_token(), new_token()
    session = Session(
        token_hash=token_hash(session_token),
        csrf_hash=token_hash(csrf),
        user_id=user.id,
        expires_at=session_expiry(settings),
        initial_ip=source_address(request),
        last_ip=source_address(request),
        user_agent=safe_user_agent(request),
    )
    db.add(session)
    await db.flush()
    user_response = await response_for_user(db, user, session)
    await db.commit()
    _set_cookies(response, session_token, csrf, settings)
    return session, user_response


async def setup_status(db: AsyncSession) -> dict[str, bool]:
    count = await db.scalar(select(func.count()).select_from(AppUser))
    return {"required": not bool(count)}


async def setup_admin(
    payload: SetupRequest,
    request: Request,
    response: Response,
    db: AsyncSession,
    settings: Settings,
) -> UserResponse:
    enforce_public_origin(request, settings)
    if await db.scalar(select(func.count()).select_from(AppUser)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Initial setup is already complete")
    if not hmac.compare_digest(payload.setup_token, settings.setup_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid setup credentials")
    user = AppUser(
        username=payload.username.casefold(),
        display_name=payload.username,
        password_hash=hash_password(payload.password),
        role="administrator",
        password_changed_at=datetime.now(UTC),
    )
    db.add(user)
    await db.flush()
    add_security_event(db, request, "account.bootstrap", actor_id=user.id, subject_id=user.id)
    _, result = await create_session(db, user, response, settings, request)
    return result


async def _enforce_login_throttle(
    db: AsyncSession, account: str, source: str, now: datetime
) -> None:
    cutoff = now - timedelta(minutes=15)
    failures, last_failure = (
        await db.execute(
            select(func.count(), func.max(LoginAttempt.occurred_at)).where(
                LoginAttempt.account == account,
                LoginAttempt.source == source,
                LoginAttempt.success.is_(False),
                LoginAttempt.occurred_at >= cutoff,
            )
        )
    ).one()
    delay_by_failures = {4: 5, 5: 15, 6: 60, 7: 300}
    delay = 900 if (failures or 0) >= 8 else delay_by_failures.get(failures or 0, 0)
    if delay and last_failure:
        remaining = delay - int((now - last_failure).total_seconds())
        if remaining > 0:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many login attempts; retry later",
                headers={"Retry-After": str(remaining)},
            )


async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession,
    settings: Settings,
) -> AuthResult:
    enforce_public_origin(request, settings)
    account = payload.username.casefold()
    source = source_address(request)
    now = datetime.now(UTC)
    await _enforce_login_throttle(db, account, source, now)
    user = await db.scalar(
        select(AppUser).where(AppUser.username == account, AppUser.active.is_(True))
    )
    valid = bool(user and verify_password(user.password_hash, payload.password))
    db.add(LoginAttempt(account=account, source=source, success=valid))
    add_security_event(
        db,
        request,
        "authentication.password",
        subject_id=user.id if user else None,
        result="success" if valid else "failure",
    )
    await db.commit()
    if not valid or user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    if user.mfa_enabled:
        challenge_token = new_token()
        db.add(
            AuthChallenge(
                token_hash=token_hash(challenge_token),
                user_id=user.id,
                expires_at=now + timedelta(minutes=5),
            )
        )
        await db.commit()
        return AuthResult(status="mfa_required", challenge=challenge_token)
    user.last_login_at = now
    _, user_response = await create_session(db, user, response, settings, request)
    return AuthResult(status=user_response.auth_status, user=user_response)


async def verify_login_mfa(
    challenge_value: str,
    code: str,
    request: Request,
    response: Response,
    db: AsyncSession,
    settings: Settings,
) -> AuthResult:
    enforce_public_origin(request, settings)
    now = datetime.now(UTC)
    challenge = await db.get(AuthChallenge, token_hash(challenge_value))
    if challenge is None or challenge.expires_at <= now or challenge.attempts >= 8:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired verification code")
    user = await db.get(AppUser, challenge.user_id)
    credential = await db.get(MfaCredential, challenge.user_id)
    if user is None or not user.active or credential is None or not user.mfa_enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired verification code")
    challenge.attempts += 1
    normalized = code.replace(" ", "").casefold()
    accepted = False
    used_recovery = False
    secret = SecretBox(settings.encryption_key).decrypt(credential.encrypted_secret)
    counter = verify_totp(secret, normalized, credential.last_counter)
    if counter is not None:
        credential.last_counter = counter
        accepted = True
    else:
        recovery = await db.scalar(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.code_hash == token_hash(normalized),
                MfaRecoveryCode.used_at.is_(None),
            )
        )
        if recovery:
            recovery.used_at = now
            accepted = used_recovery = True
    add_security_event(
        db,
        request,
        "authentication.mfa",
        subject_id=user.id,
        result="success" if accepted else "failure",
        details={"recovery_code": used_recovery} if accepted else {},
    )
    if not accepted:
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired verification code")
    await db.delete(challenge)
    user.last_login_at = now
    _, user_response = await create_session(db, user, response, settings, request)
    return AuthResult(status=user_response.auth_status, user=user_response)


async def current_session(
    request: Request,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Session:
    value = request.cookies.get(SESSION_COOKIE)
    if not value:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    now = datetime.now(UTC)
    session = await db.scalar(
        select(Session)
        .options(selectinload(Session.user))
        .where(
            Session.token_hash == token_hash(value),
            Session.revoked_at.is_(None),
            Session.expires_at > now,
        )
    )
    if (
        not session
        or not session.user.active
        or session.last_seen_at < now - timedelta(minutes=settings.session_idle_minutes)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    session.last_seen_at = now
    session.last_ip = source_address(request)
    session.user_agent = safe_user_agent(request)
    await db.commit()
    return session


async def current_user(session: Session = Depends(current_session)) -> AppUser:
    if session.restricted:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account onboarding required")
    return session.user


async def administrator(user: AppUser = Depends(current_user)) -> AppUser:
    if user.role != "administrator":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required")
    return user


async def enforce_csrf(
    request: Request,
    session: Session = Depends(current_session),
    settings: Settings = Depends(get_settings),
) -> None:
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    expected = settings.app_url.rstrip("/")
    if origin and origin.rstrip("/") != expected:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin check failed")
    if not origin and referer and not referer.startswith(f"{expected}/"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Referer check failed")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    header = request.headers.get("x-csrf-token", "")
    if (
        not cookie
        or not header
        or not hmac.compare_digest(cookie, header)
        or token_hash(header) != session.csrf_hash
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")


async def logout(
    response: Response,
    session: Session,
    db: AsyncSession,
    settings: Settings,
    request: Request | None = None,
) -> None:
    session.revoked_at = datetime.now(UTC)
    if request:
        add_security_event(
            db, request, "session.logout", actor_id=session.user_id, subject_id=session.user_id
        )
    await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.cookie_secure, samesite="lax")


async def replace_recovery_codes(db: AsyncSession, user_id: str) -> list[str]:
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user_id))
    codes = new_recovery_codes()
    db.add_all(
        MfaRecoveryCode(user_id=user_id, code_hash=token_hash(code.casefold())) for code in codes
    )
    return codes


def totp_uri(user: AppUser, secret: str) -> str:
    return (
        f"otpauth://totp/TailView:{quote(user.username)}?secret={secret}"
        "&issuer=TailView&algorithm=SHA1&digits=6&period=30"
    )


async def revoke_user_sessions(
    db: AsyncSession, user_id: str, *, except_session_id: str | None = None
) -> int:
    statement = (
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    if except_session_id:
        statement = statement.where(Session.id != except_session_id)
    result = cast(CursorResult[Any], await db.execute(statement))
    return int(result.rowcount or 0)


async def cleanup_security_records(db: AsyncSession) -> None:
    now = datetime.now(UTC)
    await db.execute(delete(Session).where(Session.expires_at < now - timedelta(days=7)))
    await db.execute(delete(LoginAttempt).where(LoginAttempt.occurred_at < now - timedelta(days=1)))
    await db.execute(delete(AuthChallenge).where(AuthChallenge.expires_at < now))
    await db.commit()
