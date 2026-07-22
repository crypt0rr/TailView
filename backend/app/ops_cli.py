from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import PurePath
from typing import Any

from .db import SessionLocal, engine
from .models import BackupVerification


def _payload() -> dict[str, Any]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise ValueError("Verification metadata must be an object")
    content_hash = str(value.get("content_hash", ""))
    if len(content_hash) != 64 or any(
        character not in "0123456789abcdef" for character in content_hash
    ):
        raise ValueError("Invalid SHA-256 value")
    return value


async def record_backup_verification() -> None:
    value = _payload()
    async with SessionLocal() as session:
        session.add(
            BackupVerification(
                filename=PurePath(str(value.get("filename", "backup.dump"))).name[:255],
                content_hash=str(value["content_hash"]),
                size=max(0, int(value.get("size", 0))),
                status="success" if value.get("status") == "success" else "failed",
                postgres_version=str(value.get("postgres_version", ""))[:64],
                migration_revision=str(value.get("migration_revision", ""))[:128],
                checks=value.get("checks", {}) if isinstance(value.get("checks"), dict) else {},
                error_class=str(value.get("error_class", ""))[:128],
                verified_at=datetime.now(UTC),
            )
        )
        await session.commit()
    await engine.dispose()


if __name__ == "__main__":
    if sys.argv[1:] != ["record-backup-verification"]:
        raise SystemExit("Usage: python -m app.ops_cli record-backup-verification")
    asyncio.run(record_backup_verification())
