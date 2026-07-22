#!/usr/bin/env python3
"""Fail-closed validation shared by candidate and stable release workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path

RC_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.([1-9][0-9]*)$")
STABLE_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGES = ("tailview-backend", "tailview-frontend", "tailview-telemetry-agent")


def core_version(tag: str) -> str:
    match = RC_RE.fullmatch(tag) or STABLE_RE.fullmatch(tag)
    if match is None:
        raise ValueError("tag is not a supported TailView RC or stable SemVer tag")
    return ".".join(match.groups()[:3])


def validate_pair(candidate: str, stable: str, candidate_commit: str, stable_commit: str) -> None:
    if RC_RE.fullmatch(candidate) is None:
        raise ValueError("candidate_tag must be vMAJOR.MINOR.PATCH-rc.N")
    if STABLE_RE.fullmatch(stable) is None:
        raise ValueError("stable_tag must be vMAJOR.MINOR.PATCH")
    if core_version(candidate) != core_version(stable):
        raise ValueError("candidate and stable core versions differ")
    if not SHA_RE.fullmatch(candidate_commit) or not SHA_RE.fullmatch(stable_commit):
        raise ValueError("release commits must be full lowercase SHA-1 values")
    if candidate_commit != stable_commit:
        raise ValueError("stable and candidate tags do not point to the same commit")


def load_json(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return data


def validate_digest_manifest(path: Path, candidate: str, commit: str) -> dict[str, str]:
    data = load_json(path)
    if data.get("schema_version") != 1:
        raise ValueError("unsupported image-digest manifest schema")
    if data.get("candidate_tag") != candidate or data.get("source_commit") != commit:
        raise ValueError("image-digest manifest identity does not match the candidate")
    if data.get("core_version") != core_version(candidate):
        raise ValueError("image-digest manifest core version does not match")
    images = data.get("images")
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise ValueError("image-digest manifest must contain exactly the three release images")
    result: dict[str, str] = {}
    for image, digest in images.items():
        if (
            not isinstance(image, str)
            or not isinstance(digest, str)
            or DIGEST_RE.fullmatch(digest) is None
        ):
            raise ValueError("image-digest manifest contains an invalid digest")
        result[image] = digest
    return result


def parse_checksums(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None:
            raise ValueError("evidence checksum manifest contains an unsafe or malformed entry")
        digest, name = match.groups()
        if name in entries:
            raise ValueError("evidence checksum manifest contains duplicate entries")
        entries[name] = digest
    if not entries:
        raise ValueError("evidence checksum manifest is empty")
    return entries


def validate_evidence(
    evidence_path: Path,
    checksums_path: Path,
    candidate: str,
    commit: str,
    minimum_seconds: int,
) -> None:
    entries = parse_checksums(checksums_path)
    for name, expected in entries.items():
        artifact = checksums_path.parent / name
        if not artifact.is_file():
            raise ValueError(f"evidence artifact is missing: {name}")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"evidence artifact checksum differs: {name}")
    if evidence_path.name not in entries:
        raise ValueError("canonical soak JSON is not covered by the checksum manifest")

    evidence = load_json(evidence_path)
    if evidence.get("schema_version") != 1 or evidence.get("result") != "go":
        raise ValueError("soak evidence is not an accepted schema-1 go decision")
    if evidence.get("candidate_tag") != candidate or evidence.get("source_commit") != commit:
        raise ValueError("soak evidence identity does not match the candidate")
    if evidence.get("core_version") != core_version(candidate):
        raise ValueError("soak evidence core version does not match")
    if not evidence.get("controlled_restart_completed"):
        raise ValueError("the required controlled restart was not completed")
    duration = evidence.get("duration_seconds")
    if not isinstance(duration, int) or duration < minimum_seconds:
        raise ValueError(f"soak duration must be at least {minimum_seconds} seconds")
    checks = evidence.get("checks")
    if not isinstance(checks, list) or len(checks) < 3:
        raise ValueError("at least three soak checks are required")
    if any(not isinstance(item, dict) or item.get("passed") is not True for item in checks):
        raise ValueError("one or more soak checks failed")
    if evidence.get("errors") not in (None, []):
        raise ValueError("soak evidence records one or more blocking errors")
    if not any(
        isinstance(item.get("checks"), dict) and item["checks"].get("report_download") is True
        for item in checks
        if isinstance(item, dict)
    ):
        raise ValueError("soak evidence does not contain an authenticated report download")
    digests = evidence.get("image_digests")
    if not isinstance(digests, dict) or set(digests) != set(IMAGES):
        raise ValueError("soak evidence does not identify all release images")
    if any(
        not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None
        for value in digests.values()
    ):
        raise ValueError("soak evidence contains an invalid image digest")


def validate_vulnerability_exceptions(path: Path, today: date) -> None:
    text = path.read_text(encoding="utf-8")
    blocks = re.split(r"(?m)^  - id: ", text)[1:]
    for block in blocks:
        identifier = block.splitlines()[0].strip()
        expiry_match = re.search(r"(?m)^    expired_at: (\d{4}-\d{2}-\d{2})$", block)
        if expiry_match is None or "    statement:" not in block or "    paths:" not in block:
            raise ValueError(f"vulnerability exception {identifier} lacks path, reason, or expiry")
        expiry = date.fromisoformat(expiry_match.group(1))
        if expiry <= today:
            raise ValueError(f"vulnerability exception {identifier} expired on {expiry}")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    core = sub.add_parser("core-version")
    core.add_argument("tag")
    pair = sub.add_parser("validate-pair")
    pair.add_argument("--candidate", required=True)
    pair.add_argument("--stable", required=True)
    pair.add_argument("--candidate-commit", required=True)
    pair.add_argument("--stable-commit", required=True)
    digest = sub.add_parser("validate-digests")
    digest.add_argument("--manifest", type=Path, required=True)
    digest.add_argument("--candidate", required=True)
    digest.add_argument("--commit", required=True)
    evidence = sub.add_parser("validate-evidence")
    evidence.add_argument("--evidence", type=Path, required=True)
    evidence.add_argument("--checksums", type=Path, required=True)
    evidence.add_argument("--candidate", required=True)
    evidence.add_argument("--commit", required=True)
    evidence.add_argument("--minimum-seconds", type=int, default=86400)
    exceptions = sub.add_parser("validate-exceptions")
    exceptions.add_argument("--file", type=Path, required=True)
    exceptions.add_argument("--today", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    try:
        if args.command == "core-version":
            print(core_version(args.tag))
        elif args.command == "validate-pair":
            validate_pair(args.candidate, args.stable, args.candidate_commit, args.stable_commit)
        elif args.command == "validate-digests":
            print(
                json.dumps(
                    validate_digest_manifest(args.manifest, args.candidate, args.commit),
                    sort_keys=True,
                )
            )
        elif args.command == "validate-evidence":
            validate_evidence(
                args.evidence,
                args.checksums,
                args.candidate,
                args.commit,
                args.minimum_seconds,
            )
        else:
            validate_vulnerability_exceptions(args.file, args.today)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
