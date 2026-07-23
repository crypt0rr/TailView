from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_validate", ROOT / "deploy" / "release_validate.py"
)
assert SPEC is not None and SPEC.loader is not None
release_validate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_validate)
sys.modules["release_validate"] = release_validate
SOAK_SPEC = importlib.util.spec_from_file_location(
    "soak_evidence", ROOT / "deploy" / "soak_evidence.py"
)
assert SOAK_SPEC is not None and SOAK_SPEC.loader is not None
soak_evidence = importlib.util.module_from_spec(SOAK_SPEC)
SOAK_SPEC.loader.exec_module(soak_evidence)


def test_release_tag_pair_requires_same_core_and_commit() -> None:
    commit = "a" * 40
    release_validate.validate_pair("v1.0.0-rc.1", "v1.0.0", commit, commit)
    assert release_validate.core_version("v1.0.0-rc.12") == "1.0.0"
    with pytest.raises(ValueError, match="core versions"):
        release_validate.validate_pair("v1.0.1-rc.1", "v1.0.0", commit, commit)
    with pytest.raises(ValueError, match="same commit"):
        release_validate.validate_pair("v1.0.0-rc.1", "v1.0.0", commit, "b" * 40)
    for invalid in ("v1.0.0", "v1.0.0-beta.1", "v1.0.0-rc.0", "v01.0.0-rc.1"):
        with pytest.raises(ValueError):
            release_validate.validate_pair(invalid, "v1.0.0", commit, commit)


def test_digest_manifest_is_exact_and_candidate_bound(tmp_path: Path) -> None:
    commit = "a" * 40
    manifest = tmp_path / "digests.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "candidate_tag": "v1.0.0-rc.1",
                "core_version": "1.0.0",
                "source_commit": commit,
                "images": {
                    name: f"sha256:{index:064x}"
                    for index, name in enumerate(release_validate.IMAGES, 1)
                },
            }
        ),
        encoding="utf-8",
    )
    values = release_validate.validate_digest_manifest(manifest, "v1.0.0-rc.1", commit)
    assert set(values) == set(release_validate.IMAGES)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["images"]["unexpected"] = f"sha256:{9:064x}"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly"):
        release_validate.validate_digest_manifest(manifest, "v1.0.0-rc.1", commit)


def test_soak_evidence_rejects_short_or_altered_runs(tmp_path: Path) -> None:
    commit = "a" * 40
    evidence = tmp_path / "tailview-1.0.0-rc.1-soak.json"
    payload = {
        "schema_version": 1,
        "candidate_tag": "v1.0.0-rc.1",
        "core_version": "1.0.0",
        "source_commit": commit,
        "result": "go",
        "duration_seconds": 86400,
        "controlled_restart_completed": True,
        "checks": [
            {"passed": True, "checks": {"report_download": True}},
            {"passed": True},
            {"passed": True},
        ],
        "image_digests": {
            name: f"sha256:{index:064x}"
            for index, name in enumerate(release_validate.IMAGES, 1)
        },
    }
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    checksums.write_text(
        f"{hashlib.sha256(evidence.read_bytes()).hexdigest()}  {evidence.name}\n", encoding="utf-8"
    )
    release_validate.validate_evidence(evidence, checksums, "v1.0.0-rc.1", commit, 86400)
    payload["duration_seconds"] = 86399
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    checksums.write_text(
        f"{hashlib.sha256(evidence.read_bytes()).hexdigest()}  {evidence.name}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="duration"):
        release_validate.validate_evidence(evidence, checksums, "v1.0.0-rc.1", commit, 86400)
    payload["duration_seconds"] = 86400
    evidence.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum differs"):
        release_validate.validate_evidence(evidence, checksums, "v1.0.0-rc.1", commit, 86400)


def test_stable_workflow_cannot_build_and_rc_workflow_cannot_move_latest() -> None:
    stable = (ROOT / ".github" / "workflows" / "promote.yml").read_text(encoding="utf-8")
    candidate = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "docker/build-push-action" not in stable
    assert "docker build " not in stable
    assert 'tags:\n      - "v*.*.*-rc.*"' in candidate
    assert "aquasecurity/trivy-action@v0.36.0" in candidate
    assert '"${IMAGE}:latest"' not in candidate


def test_backup_drill_uses_the_running_compose_backend_image() -> None:
    script = (ROOT / "deploy" / "verify-backup.sh").read_text(encoding="utf-8")
    assert "PostgreSQL init process complete" in script
    assert script.index("PostgreSQL init process complete") < script.index("pg_isready")
    assert "Temporary PostgreSQL logs from the failed verification" in script
    assert "docker compose ps -q backend" in script
    assert "docker inspect --format '{{.Image}}'" in script
    assert "docker compose build backend" not in script
    assert "tailview-backend sh -c" not in script


def test_all_release_base_images_are_digest_pinned() -> None:
    files = ("backend/Dockerfile", "frontend/Dockerfile", "deploy/telemetry-agent/Dockerfile")
    for relative in files:
        for line in (ROOT / relative).read_text(encoding="utf-8").splitlines():
            if line.startswith("FROM ") or line.startswith("COPY --from="):
                reference = (
                    line.split()[1]
                    if line.startswith("FROM ")
                    else line.split("=", 1)[1].split()[0]
                )
                if "/" in reference or ":" in reference:
                    assert "@sha256:" in reference


def test_vulnerability_exceptions_expire_fail_closed(tmp_path: Path) -> None:
    exceptions = tmp_path / "trivy.yaml"
    exceptions.write_text(
        "vulnerabilities:\n"
        "  - id: CVE-TEST\n"
        "    paths:\n"
        "      - usr/bin/example\n"
        "    statement: bounded release exception\n"
        "    expired_at: 2026-07-23\n",
        encoding="utf-8",
    )
    release_validate.validate_vulnerability_exceptions(exceptions, date(2026, 7, 22))
    with pytest.raises(ValueError, match="expired"):
        release_validate.validate_vulnerability_exceptions(exceptions, date(2026, 7, 23))


def test_soak_tooling_rejects_live_project_and_environment(tmp_path: Path) -> None:
    soak_env = tmp_path / "soak.env"
    soak_env.write_text("APP_URL=http://localhost:18080\n", encoding="utf-8")
    environment = os.environ | {"SOAK_PROJECT": "tailview", "SOAK_ENV_FILE": str(soak_env)}
    result = subprocess.run(
        ["/bin/sh", "-c", ". deploy/soak-common.sh"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "tailview-soak" in result.stderr

    environment = os.environ | {"SOAK_PROJECT": "tailview-soak", "SOAK_ENV_FILE": ".env"}
    result = subprocess.run(
        ["/bin/sh", "-c", ". deploy/soak-common.sh"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "never .env" in result.stderr


def test_soak_finalization_requires_restart_checks_and_report(tmp_path: Path) -> None:
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "candidate_tag": "v1.0.0-rc.1",
                "core_version": "1.0.0",
                "source_commit": "a" * 40,
                "started_at": "2026-07-21T00:00:00Z",
                "started_epoch": int(time.time()) - 86401,
                "backup_sha256": "b" * 64,
                "schema_revision": ["0014_v1_completion"],
                "image_digests": {
                    name: f"sha256:{index:064x}"
                    for index, name in enumerate(release_validate.IMAGES, 1)
                },
            }
        ),
        encoding="utf-8",
    )
    checks = tmp_path / "checks"
    checks.mkdir()
    for index in range(3):
        (checks / f"{index}.json").write_text(
            json.dumps(
                {
                    "captured_at": f"2026-07-22T00:00:0{index}Z",
                    "passed": True,
                    "checks": {"identity": True},
                    "report_download": {"sha256": "c" * 64, "size": 10},
                }
            ),
            encoding="utf-8",
        )
    restart = tmp_path / "restart.json"
    restart.write_text(json.dumps({"completed": True}), encoding="utf-8")
    output = tmp_path / "out"
    soak_evidence.command_finalize(
        SimpleNamespace(
            state=state,
            checks=checks,
            restart_marker=restart,
            output_dir=output,
            minimum_seconds=86400,
            minimum_checks=3,
        )
    )
    evidence = json.loads((output / "tailview-1.0.0-rc.1-soak.json").read_text())
    assert evidence["result"] == "go"
    assert (output / "tailview-1.0.0-rc.1-SHA256SUMS").is_file()
