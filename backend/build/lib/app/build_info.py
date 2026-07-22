from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def packaged_schema_heads() -> tuple[str, ...]:
    """Return the migration heads shipped with this application image."""
    backend_root = Path(__file__).resolve().parent.parent
    config = Config(str(backend_root / "alembic.ini"))
    config.set_main_option("script_location", str(backend_root / "migrations"))
    return tuple(sorted(ScriptDirectory.from_config(config).get_heads()))
