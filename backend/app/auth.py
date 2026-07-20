from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import Settings, get_settings
from .db import get_db
from .models import AppUser, LoginAttempt, Session
from .schemas import LoginRequest, SetupRequest, UserResponse
from .security import hash_password, new_token, session_expiry, token_hash, verify_password

SESSION_COOKIE = "tailview_session"
CSRF_COOKIE = "tailview_csrf"


def _source(request: Request) -> str:
    return request.client.host if request.client else "unknown"


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
    db: AsyncSession, user: AppUser, response: Response, settings: Settings
) -> None:
    session_token, csrf = new_token(), new_token()
    db.add(
        Session(
            token_hash=token_hash(session_token),
            csrf_hash=token_hash(csrf),
            user_id=user.id,
            expires_at=session_expiry(settings),
        )
    )
    await db.commit()
    _set_cookies(response, session_token, csrf, settings)


async def setup_status(db: AsyncSession) -> dict[str, bool]:
    count = await db.scalar(select(func.count()).select_from(AppUser))
    return {"required": not bool(count)}


async def setup_admin(
    payload: SetupRequest, response: Response, db: AsyncSession, settings: Settings
) -> UserResponse:
    if await db.scalar(select(func.count()).select_from(AppUser)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Initial setup is already complete")
    if not hmac.compare_digest(payload.setup_token, settings.setup_token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid setup credentials")
    user = AppUser(
        username=payload.username.casefold(),
        password_hash=hash_password(payload.password),
        role="administrator",
    )
    db.add(user)
    await db.flush()
    await create_session(db, user, response, settings)
    return UserResponse(id=user.id, username=user.username, role="administrator")


async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession,
    settings: Settings,
) -> UserResponse:
    account = payload.username.casefold()
    source = _source(request)
    cutoff = datetime.now(UTC) - timedelta(minutes=15)
    failures = await db.scalar(
        select(func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.account == account,
            LoginAttempt.source == source,
            LoginAttempt.success.is_(False),
            LoginAttempt.occurred_at >= cutoff,
        )
    )
    if (failures or 0) >= 8:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts; retry later"
        )
    user = await db.scalar(
        select(AppUser).where(AppUser.username == account, AppUser.active.is_(True))
    )
    valid = bool(user and verify_password(user.password_hash, payload.password))
    db.add(LoginAttempt(account=account, source=source, success=valid))
    await db.commit()
    if not valid or user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    await create_session(db, user, response, settings)
    return UserResponse(id=user.id, username=user.username, role=user.role)


async def current_session(
    request: Request, db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
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
    await db.commit()
    return session


async def current_user(session: Session = Depends(current_session)) -> AppUser:
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
    if origin and origin.rstrip("/") != settings.app_url.rstrip("/"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origin check failed")
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
    response: Response, session: Session, db: AsyncSession, settings: Settings
) -> None:
    session.revoked_at = datetime.now(UTC)
    await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.cookie_secure, samesite="lax")


async def cleanup_security_records(db: AsyncSession) -> None:
    now = datetime.now(UTC)
    await db.execute(delete(Session).where(Session.expires_at < now - timedelta(days=7)))
    await db.execute(delete(LoginAttempt).where(LoginAttempt.occurred_at < now - timedelta(days=1)))
    await db.commit()
