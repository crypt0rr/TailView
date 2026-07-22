from __future__ import annotations

import base64
import time

import pytest
from fastapi import HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import api, auth
from app.config import Settings
from app.models import AppUser, Base, LocalSecurityEvent, Session
from app.schemas import AppUserCreateRequest, AppUserUpdateRequest, LoginRequest
from app.security import _totp_at, hash_password, verify_password, verify_totp


def request() -> Request:
    value = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [(b"user-agent", b"TailView test\x00agent")],
            "client": ("192.0.2.8", 1234),
            "scheme": "https",
            "server": ("tailview.test", 443),
        }
    )
    value.state.correlation_id = "test-correlation"
    return value


def settings() -> Settings:
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    return Settings(environment="test", cookie_secure=False, encryption_key=key)


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_temporary_account_login_is_restricted_and_audited(db) -> None:
    admin = AppUser(
        username="admin",
        password_hash=hash_password("administrator-password"),
        role="administrator",
    )
    db.add(admin)
    await db.commit()
    created = await api.create_app_user(
        AppUserCreateRequest(
            username="viewer",
            display_name="TailView Viewer",
            role="viewer",
            temporary_password="temporary-password",
        ),
        request(),
        admin,
        None,
        db,
    )
    viewer = await db.get(AppUser, created["id"])
    assert viewer is not None
    assert viewer.must_change_password is True
    assert verify_password(viewer.password_hash, "temporary-password")
    result = await auth.login(
        LoginRequest(username="viewer", password="temporary-password"),
        request(),
        Response(),
        db,
        settings(),
    )
    assert result.status == "password_change_required"
    stored_session = await db.scalar(select(Session).where(Session.user_id == viewer.id))
    assert stored_session is not None and stored_session.restricted is True
    assert stored_session.last_ip == "192.0.2.8"
    assert "\x00" not in stored_session.user_agent
    assert await db.scalar(select(func.count()).select_from(LocalSecurityEvent)) == 2


@pytest.mark.asyncio
async def test_final_active_administrator_cannot_be_demoted(db) -> None:
    admin = AppUser(
        username="admin",
        password_hash=hash_password("administrator-password"),
        role="administrator",
    )
    db.add(admin)
    await db.commit()
    with pytest.raises(HTTPException, match="final active Administrator"):
        await api.update_app_user(
            admin.id,
            AppUserUpdateRequest(role="viewer"),
            request(),
            admin,
            None,
            db,
        )


@pytest.mark.asyncio
async def test_role_change_revokes_existing_sessions(db) -> None:
    admin = AppUser(
        username="admin",
        password_hash=hash_password("administrator-password"),
        role="administrator",
    )
    viewer = AppUser(username="viewer", password_hash=hash_password("viewer-password-long"))
    db.add_all([admin, viewer])
    await db.flush()
    existing = Session(
        token_hash="a" * 64,
        csrf_hash="b" * 64,
        user_id=viewer.id,
        expires_at=auth.session_expiry(settings()),
    )
    db.add(existing)
    await db.commit()
    await api.update_app_user(
        viewer.id,
        AppUserUpdateRequest(role="administrator"),
        request(),
        admin,
        None,
        db,
    )
    await db.refresh(existing)
    assert existing.revoked_at is not None


def test_totp_window_and_replay_protection() -> None:
    totp_seed = "JBSWY3DPEHPK3PXP"
    counter = int(time.time()) // 30
    code = _totp_at(totp_seed, counter)
    assert verify_totp(totp_seed, code) == counter
    assert verify_totp(totp_seed, code, last_counter=counter) is None
    assert verify_totp(totp_seed, "invalid") is None
