#!/usr/bin/env python3
"""Create redacted, deterministic evidence for an isolated TailView RC soak."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from release_validate import IMAGES, core_version, validate_digest_manifest


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain an object")
    return data


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def command_init(args: argparse.Namespace) -> None:
    readiness = read_json(args.readiness)
    digests = validate_digest_manifest(args.digests, args.candidate, args.source_commit)
    version = readiness.get("version", {})
    schema = readiness.get("schema", {})
    if not isinstance(version, dict) or not isinstance(schema, dict):
        raise ValueError("readiness identity is missing")
    if readiness.get("status") != "ready":
        raise ValueError("candidate was not ready after restore")
    if version.get("application") != core_version(args.candidate):
        raise ValueError("candidate runtime core version differs")
    if version.get("revision") != args.source_commit:
        raise ValueError("candidate runtime commit differs")
    if schema.get("current") != schema.get("expected"):
        raise ValueError("restored database is not at the packaged migration head")
    state = {
        "schema_version": 1,
        "candidate_tag": args.candidate,
        "core_version": core_version(args.candidate),
        "source_commit": args.source_commit,
        "project": args.project,
        "started_at": utc_now(),
        "started_epoch": int(time.time()),
        "backup_sha256": args.backup_sha256,
        "image_digests": digests,
        "schema_revision": schema.get("current"),
    }
    write_json(args.output, state)


def command_snapshot(args: argparse.Namespace) -> None:
    state = read_json(args.state)
    readiness = read_json(args.readiness)
    operations = read_json(args.operations)
    capabilities = read_json(args.capabilities)
    sync = read_json(args.sync)
    reports = read_json(args.reports)
    findings = read_json(args.findings)
    retention = read_json(args.retention)
    storage = read_json(args.storage)
    version = readiness.get("version", {})
    schema = readiness.get("schema", {})
    scheduler = operations.get("scheduler")
    queues = operations.get("queues", {})
    queue_healthy = isinstance(queues, dict) and all(
        isinstance(value, dict) and value.get("warning") is False for value in queues.values()
    )
    identity_ok = (
        readiness.get("status") == "ready"
        and isinstance(version, dict)
        and version.get("application") == state.get("core_version")
        and version.get("revision") == state.get("source_commit")
        and isinstance(schema, dict)
        and schema.get("current") == schema.get("expected") == state.get("schema_revision")
    )
    scheduler_ok = (
        isinstance(scheduler, dict)
        and scheduler.get("unhealthy") is False
        and scheduler.get("last_status") in {"success", "running"}
    )
    report_download = None
    if args.report_sha256 and args.report_size is not None:
        report_download = {"sha256": args.report_sha256, "size": args.report_size}
    snapshot = {
        "schema_version": 1,
        "captured_at": utc_now(),
        "captured_epoch": int(time.time()),
        "passed": bool(identity_ok and scheduler_ok and queue_healthy),
        "checks": {
            "identity": identity_ok,
            "scheduler": scheduler_ok,
            "queues": queue_healthy,
            "report_download": report_download is not None,
        },
        "readiness": readiness,
        "operations": operations,
        "capabilities": capabilities,
        "sync": sync,
        "reports": reports,
        "findings": findings,
        "retention": retention,
        "storage": storage,
        "report_download": report_download,
    }
    write_json(args.output, snapshot)


def command_finalize(args: argparse.Namespace) -> None:
    state = read_json(args.state)
    check_paths = sorted(args.checks.glob("*.json"))
    checks = [read_json(path) for path in check_paths]
    now_epoch = int(time.time())
    duration = now_epoch - int(state["started_epoch"])
    restart = read_json(args.restart_marker) if args.restart_marker.is_file() else {}
    errors: list[str] = []
    if duration < args.minimum_seconds:
        errors.append(f"soak duration {duration}s is shorter than {args.minimum_seconds}s")
    if len(checks) < args.minimum_checks:
        errors.append(f"only {len(checks)} checks were captured")
    if any(check.get("passed") is not True for check in checks):
        errors.append("one or more checks failed")
    if restart.get("completed") is not True:
        errors.append("controlled restart evidence is missing")
    if not any(isinstance(check.get("report_download"), dict) for check in checks):
        errors.append("no authenticated report artifact download was verified")
    result = "go" if not errors else "no-go"
    evidence = {
        "schema_version": 1,
        "candidate_tag": state["candidate_tag"],
        "core_version": state["core_version"],
        "source_commit": state["source_commit"],
        "result": result,
        "started_at": state["started_at"],
        "finished_at": utc_now(),
        "duration_seconds": duration,
        "controlled_restart_completed": restart.get("completed") is True,
        "backup_sha256": state["backup_sha256"],
        "schema_revision": state["schema_revision"],
        "image_digests": state["image_digests"],
        "checks": [
            {
                "captured_at": check.get("captured_at"),
                "passed": check.get("passed") is True,
                "checks": check.get("checks", {}),
            }
            for check in checks
        ],
        "errors": errors,
    }
    version = str(state["candidate_tag"])[1:]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_name = f"tailview-{version}-soak.json"
    markdown_name = f"tailview-{version}-go-no-go.md"
    json_path = args.output_dir / json_name
    markdown_path = args.output_dir / markdown_name
    write_json(json_path, evidence)
    mark = "GO" if result == "go" else "NO-GO"
    markdown_path.write_text(
        "\n".join(
            [
                f"# TailView {state['candidate_tag']} release decision: {mark}",
                "",
                f"- Commit: `{state['source_commit']}`",
                f"- Schema: `{state['schema_revision']}`",
                f"- Duration: `{duration}` seconds",
                f"- Evidence checks: `{len(checks)}`",
                "- Controlled restart: "
                f"`{'passed' if restart.get('completed') is True else 'missing'}`",
                f"- Backup SHA-256: `{state['backup_sha256']}`",
                "- Rollback: restore the pre-upgrade backup into a separate volume; "
                "do not downgrade in place.",
                "",
                "## Decision details",
                "",
                *(f"- {error}" for error in errors),
                "- No blocking condition was detected." if not errors else "",
                "",
            ]
        ),
        encoding="utf-8",
    )
    manifest = args.output_dir / f"tailview-{version}-SHA256SUMS"
    lines = []
    for path in (markdown_path, json_path):
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    manifest.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
    if errors:
        raise ValueError("; ".join(errors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--candidate", required=True)
    init.add_argument("--source-commit", required=True)
    init.add_argument("--backup-sha256", required=True)
    init.add_argument("--project", required=True)
    init.add_argument("--readiness", type=Path, required=True)
    init.add_argument("--digests", type=Path, required=True)
    init.add_argument("--output", type=Path, required=True)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("--state", type=Path, required=True)
    snapshot_inputs = (
        "readiness",
        "operations",
        "capabilities",
        "sync",
        "reports",
        "findings",
        "retention",
        "storage",
    )
    for name in snapshot_inputs:
        snapshot.add_argument(f"--{name}", type=Path, required=True)
    snapshot.add_argument("--report-sha256")
    snapshot.add_argument("--report-size", type=int)
    snapshot.add_argument("--output", type=Path, required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--state", type=Path, required=True)
    finalize.add_argument("--checks", type=Path, required=True)
    finalize.add_argument("--restart-marker", type=Path, required=True)
    finalize.add_argument("--output-dir", type=Path, required=True)
    finalize.add_argument("--minimum-seconds", type=int, default=86400)
    finalize.add_argument("--minimum-checks", type=int, default=3)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "init":
            command_init(args)
        elif args.command == "snapshot":
            command_snapshot(args)
        else:
            command_finalize(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"soak evidence failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
