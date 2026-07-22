from __future__ import annotations

import base64

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import api
from app.config import Settings
from app.models import AppUser, Base
from app.saved_views import compatible_state, normalize_state, page_allowed
from app.schemas import (
    SavedViewCloneRequest,
    SavedViewCreateRequest,
    SavedViewDefaultRequest,
    SavedViewUpdateRequest,
)


def settings(limit: int = 50) -> Settings:
    key = base64.urlsafe_b64encode(b"s" * 32).decode()
    return Settings(
        environment="test",
        cookie_secure=False,
        encryption_key=key,
        saved_view_limit=limit,
    )


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


def flow_state(**overrides: object) -> dict[str, object]:
    state: dict[str, object] = {
        "range": "24h",
        "category": "",
        "source": "",
        "destination": "",
        "protocol": "",
        "port": "",
        "resolution": "all",
        "ranking_limit": 10,
    }
    state.update(overrides)
    return state


def create_payload(name: str = "Operations", visibility: str = "private") -> SavedViewCreateRequest:
    return SavedViewCreateRequest(
        name=name,
        page="flows",
        visibility=visibility,
        state=flow_state(),
    )


@pytest.mark.asyncio
async def test_private_shared_clone_defaults_and_optimistic_locking(db) -> None:
    owner = AppUser(username="owner", password_hash="hash", role="viewer")
    teammate = AppUser(username="teammate", password_hash="hash", role="viewer")
    admin = AppUser(username="admin", password_hash="hash", role="administrator")
    db.add_all([owner, teammate, admin])
    await db.commit()

    private = await api.create_saved_view(create_payload(), owner, None, db, settings())
    teammate_list = await api.saved_views(teammate, db, "flows", "all", None, "")
    assert teammate_list["items"] == []
    with pytest.raises(HTTPException) as hidden:
        await api.saved_view_detail(private["id"], teammate, db)
    assert hidden.value.status_code == 404

    shared = await api.update_saved_view(
        private["id"],
        SavedViewUpdateRequest(
            name="Operations",
            description="Team traffic",
            visibility="shared",
            state=flow_state(source="gateway"),
            expected_revision=1,
        ),
        owner,
        None,
        db,
    )
    assert shared["revision"] == 2
    assert shared["is_owner"] is True
    teammate_list = await api.saved_views(teammate, db, "flows", "all", None, "")
    assert teammate_list["items"][0]["can_edit"] is False

    clone = await api.clone_saved_view(
        private["id"],
        SavedViewCloneRequest(name="My operations"),
        teammate,
        None,
        db,
        settings(),
    )
    assert clone["owner"]["username"] == "teammate"
    assert clone["visibility"] == "private"
    await api.set_saved_view_default(
        "flows", SavedViewDefaultRequest(view_id=private["id"]), teammate, None, db
    )
    defaults = await api.saved_view_defaults(teammate, db)
    assert defaults["items"][0]["view"]["is_default"] is True

    with pytest.raises(HTTPException) as conflict:
        await api.update_saved_view(
            private["id"],
            SavedViewUpdateRequest(
                name="Operations",
                visibility="shared",
                state=flow_state(),
                expected_revision=1,
            ),
            admin,
            None,
            db,
        )
    assert conflict.value.status_code == 409

    await api.delete_saved_view(private["id"], owner, None, db)
    assert (await api.saved_view_defaults(teammate, db))["items"] == []


@pytest.mark.asyncio
async def test_name_uniqueness_limit_and_page_authorization(db) -> None:
    viewer = AppUser(username="viewer", password_hash="hash", role="viewer")
    db.add(viewer)
    await db.commit()
    await api.create_saved_view(create_payload("Traffic"), viewer, None, db, settings(limit=1))

    with pytest.raises(HTTPException) as limited:
        await api.create_saved_view(
            create_payload("Second"), viewer, None, db, settings(limit=1)
        )
    assert limited.value.status_code == 409

    assert not await api._saved_view_name_available(db, viewer.id, "flows", "TRAFFIC")

    assert page_allowed("access_governance", "viewer") is False
    with pytest.raises(HTTPException) as unavailable:
        await api.create_saved_view(
            SavedViewCreateRequest(
                name="Credentials",
                page="access_governance",
                state={"tab": "credentials", "search": "", "credential_type": "", "status": ""},
            ),
            viewer,
            None,
            db,
            settings(),
        )
    assert unavailable.value.status_code == 404


def test_strict_versioned_state_validation_and_legacy_compatibility() -> None:
    assert normalize_state("flows", flow_state(protocol="6", port="443"))["port"] == "443"
    with pytest.raises(ValueError):
        normalize_state("flows", flow_state(cursor="secret"))
    with pytest.raises(ValueError):
        normalize_state("flows", flow_state(port="70000"))
    with pytest.raises(ValueError):
        normalize_state("devices", {"columns": {"password": True}})
    assert compatible_state("flows", 2, flow_state()) is False
    assert compatible_state("flows", 1, {"legacy": True}) is False
