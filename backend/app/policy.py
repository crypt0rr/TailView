from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import json5

SUPPORTED = {
    "grants",
    "acls",
    "ssh",
    "groups",
    "tagOwners",
    "hosts",
    "ipsets",
    "postures",
    "autoApprovers",
    "tests",
    "sshTests",
    "nodeAttrs",
}


@dataclass(frozen=True)
class ParsedPolicy:
    snapshot_id: str
    normalized: dict[str, Any]
    unsupported: list[str]


def parse_policy(source: str) -> ParsedPolicy:
    parsed = json5.loads(source)
    if not isinstance(parsed, dict):
        raise ValueError("Policy root must be an object")
    unsupported = sorted(str(key) for key in parsed if key not in SUPPORTED)
    return ParsedPolicy(hashlib.sha256(source.encode()).hexdigest(), parsed, unsupported)


def _path_key(path: str, key: str) -> str:
    return f"{path}[{json.dumps(key, ensure_ascii=False)}]"


def _deduplicate_value(value: Any, path: str, findings: list[dict[str, Any]]) -> Any:
    if isinstance(value, dict):
        return {
            key: _deduplicate_value(item, _path_key(path, str(key)), findings)
            for key, item in value.items()
        }
    if not isinstance(value, list):
        return value

    result: list[Any] = []
    seen: dict[str, int] = {}
    for index, item in enumerate(value):
        nested_findings: list[dict[str, Any]] = []
        cleaned = _deduplicate_value(item, f"{path}[{index}]", nested_findings)
        canonical = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if canonical in seen:
            findings.append(
                {
                    "kind": "exact_duplicate_array_entry",
                    "path": path,
                    "first_index": seen[canonical],
                    "duplicate_index": index,
                    "value_preview": canonical[:500],
                    "proof": "Canonical JSON values are identical",
                }
            )
            continue
        findings.extend(nested_findings)
        seen[canonical] = index
        result.append(cleaned)
    return result


def review_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Create a conservative, non-mutating duplicate-removal candidate.

    Only arrays nested under documented policy sections are deduplicated. Unknown
    top-level constructs are copied without interpretation or modification.
    """
    candidate = deepcopy(policy)
    findings: list[dict[str, Any]] = []
    for section, value in policy.items():
        if section in SUPPORTED:
            candidate[section] = _deduplicate_value(value, _path_key("$", section), findings)
    candidate_source = json.dumps(candidate, indent=2, ensure_ascii=False) + "\n"
    original_canonical = json.dumps(
        policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    candidate_canonical = json.dumps(
        candidate, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return {
        "duplicate_count": len(findings),
        "changed": original_canonical != candidate_canonical,
        "findings": findings,
        "candidate": candidate_source,
        "candidate_sha256": hashlib.sha256(candidate_source.encode()).hexdigest(),
        "review_scope": "Exact duplicate array entries in documented policy sections only",
        "validation": "not_run",
        "requires_upstream_validation": True,
        "comments_preserved": False,
        "notice": (
            "Read-only suggestion. TailView never applies policy changes. The candidate is "
            "strict JSON (valid HuJSON) and omits source comments; validate it with Tailscale "
            "before any manual replacement."
        ),
    }


def source_line(source: str, fragment: str) -> tuple[int | None, int | None]:
    """Best-effort line location that never claims a span when no exact key match exists."""
    marker = f'"{fragment}"'
    offset = source.find(marker)
    if offset < 0:
        return None, None
    line = source.count("\n", 0, offset) + 1
    return line, line


def expand_selector(
    selector: str,
    policy: dict[str, Any],
    devices: list[dict[str, Any]],
    users: list[dict[str, Any]],
) -> tuple[list[str], list[str], str]:
    path = [selector]
    if selector == "*":
        return [str(d["id"]) for d in devices], path + ["all devices"], "fully_evaluated"
    if selector.startswith("group:"):
        members = policy.get("groups", {}).get(selector)
        if not isinstance(members, list):
            return [], path, "unresolved_selector"
        ids: list[str] = []
        for member in members:
            expanded, member_path, status = expand_selector(str(member), policy, devices, users)
            path.extend(member_path)
            ids.extend(expanded)
            if status != "fully_evaluated":
                return sorted(set(ids)), path, status
        return sorted(set(ids)), path, "fully_evaluated"
    if selector.startswith("tag:"):
        matches = [str(d["id"]) for d in devices if selector in d.get("tags", [])]
        return matches, path + matches, "fully_evaluated"
    if selector.startswith("autogroup:"):
        if selector in {"autogroup:member", "autogroup:tagged"}:
            matches = [
                str(d["id"])
                for d in devices
                if selector == "autogroup:member" or bool(d.get("tags"))
            ]
            return matches, path + matches, "fully_evaluated"
        return [], path, "unsupported_construct"
    matching_users = {
        str(u["id"]) for u in users if selector in {u.get("login_name"), u.get("display_name")}
    }
    matches = [str(d["id"]) for d in devices if d.get("owner_id") in matching_users]
    if matches:
        return matches, path + matches, "fully_evaluated"
    host = policy.get("hosts", {}).get(selector)
    if host:
        matches = [str(d["id"]) for d in devices if host in d.get("addresses", [])]
        return matches, path + [str(host)] + matches, "fully_evaluated"
    return [], path, "unresolved_selector"


def evaluate_policy(
    policy: dict[str, Any], devices: list[dict[str, Any]], users: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    rules = list(policy.get("grants", [])) + list(policy.get("acls", []))
    for index, rule in enumerate(rules):
        sources = rule.get("src", rule.get("users", []))
        destinations = rule.get("dst", rule.get("ports", []))
        for source_selector in sources:
            source_ids, source_path, source_status = expand_selector(
                str(source_selector), policy, devices, users
            )
            for destination_selector in destinations:
                selector = str(destination_selector)
                destination_name, _, port = selector.rpartition(":")
                if not destination_name or not port.replace("-", "").isdigit():
                    destination_name, port = selector, "*"
                destination_ids, destination_path, destination_status = expand_selector(
                    destination_name, policy, devices, users
                )
                status = (
                    "fully_evaluated"
                    if source_status == destination_status == "fully_evaluated"
                    else source_status
                    if source_status != "fully_evaluated"
                    else destination_status
                )
                for source_id in source_ids:
                    for destination_id in destination_ids:
                        relationships.append(
                            {
                                "id": f"rule-{index}-{source_id}-{destination_id}-{port}",
                                "source": source_id,
                                "destination": destination_id,
                                "ports": rule.get("ip", [port]),
                                "protocol": rule.get("proto", "any"),
                                "status": status,
                                "source_path": source_path,
                                "destination_path": destination_path,
                                "rule_index": index,
                                "posture": rule.get("srcPosture", []),
                            }
                        )
    return relationships
