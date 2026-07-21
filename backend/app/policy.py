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


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _acl_destination_selector(value: str) -> tuple[str, str]:
    """Split an ACL destination selector without mistaking tag/IPv6 colons for ports."""
    destination, separator, port = value.rpartition(":")
    if separator and (port == "*" or port.replace("-", "").isdigit()):
        return destination, port
    return value, "*"


def _is_broad_selector(selector: str) -> bool:
    return selector in {
        "*",
        "autogroup:member",
        "autogroup:shared",
        "autogroup:tagged",
    } or selector.startswith("user:*@")


def _is_sensitive_selector(selector: str) -> bool:
    normalized = selector.lower()
    terms = ("prod", "admin", "critical", "infra", "database", "db", "server", "router")
    return selector.startswith("tag:") and any(term in normalized for term in terms)


def security_review_policy(
    policy: dict[str, Any], devices: list[dict[str, Any]], users: list[dict[str, Any]]
) -> dict[str, Any]:
    """Return conservative policy exposure heuristics without changing the policy.

    Findings describe potential review targets, not proven vulnerabilities or proof
    that access is unnecessary. Selector expansion is capped to summary counts and
    samples so large policies cannot create an unbounded response.
    """
    findings: list[dict[str, Any]] = []
    reviewed_rules = 0
    incomplete_rules = 0

    def add(
        *,
        finding_id: str,
        severity: str,
        title: str,
        category: str,
        path: str,
        evidence: str,
        recommendation: str,
        confidence: str = "high",
        rule_index: int | None = None,
        affected_pair_count: int | None = None,
        sample_sources: list[str] | None = None,
        sample_destinations: list[str] | None = None,
    ) -> None:
        if len(findings) >= 500:
            return
        findings.append(
            {
                "id": finding_id,
                "severity": severity,
                "title": title,
                "category": category,
                "path": path,
                "rule_index": rule_index,
                "evidence": evidence,
                "recommendation": recommendation,
                "confidence": confidence,
                "affected_pair_count": affected_pair_count,
                "sample_sources": sample_sources or [],
                "sample_destinations": sample_destinations or [],
            }
        )

    device_names = {
        str(device["id"]): str(device.get("name") or device["id"]) for device in devices
    }
    sections = (("grants", policy.get("grants", [])), ("acls", policy.get("acls", [])))
    for section, raw_rules in sections:
        if not isinstance(raw_rules, list):
            continue
        for index, rule in enumerate(raw_rules):
            if not isinstance(rule, dict):
                incomplete_rules += 1
                continue
            reviewed_rules += 1
            path = f'$["{section}"][{index}]'
            sources = _string_list(rule.get("src", rule.get("users")))
            raw_destinations = _string_list(rule.get("dst", rule.get("ports")))
            if section == "acls":
                parsed_destinations = [_acl_destination_selector(item) for item in raw_destinations]
                destinations = [item[0] for item in parsed_destinations]
                ports = [item[1] for item in parsed_destinations]
                unrestricted = any(port == "*" for port in ports) and not rule.get("proto")
            else:
                destinations = raw_destinations
                permissions = _string_list(rule.get("ip"))
                unrestricted = "*" in permissions
                # Application-defined capabilities are not treated as IP access.
                if not permissions:
                    continue

            broad_sources = sorted(
                {selector for selector in sources if _is_broad_selector(selector)}
            )
            broad_destinations = sorted(
                {selector for selector in destinations if _is_broad_selector(selector)}
            )
            global_access = "*" in broad_sources and "*" in broad_destinations and unrestricted
            if global_access:
                add(
                    finding_id=f"{section}-{index}-global-network-access",
                    severity="critical",
                    title="Unrestricted all-to-all network access",
                    category="network_access",
                    path=path,
                    rule_index=index,
                    evidence=(
                        "The rule selects every source and destination and permits every IP "
                        "protocol/port."
                    ),
                    recommendation=(
                        "Replace wildcard sources, destinations, and permissions with the smallest "
                        "required identities, tagged roles, protocols, and ports; validate in "
                        "a staged policy."
                    ),
                )
            else:
                if broad_sources:
                    add(
                        finding_id=f"{section}-{index}-broad-source",
                        severity="high" if unrestricted else "medium",
                        title="Broad source population",
                        category="identity_scope",
                        path=path,
                        rule_index=index,
                        evidence=f"Broad source selector(s): {', '.join(broad_sources)}.",
                        recommendation=(
                            "Review whether a smaller group, user set, tag, or posture-constrained "
                            "source "
                            "can provide the required access."
                        ),
                    )
                if broad_destinations:
                    add(
                        finding_id=f"{section}-{index}-broad-destination",
                        severity="high" if unrestricted else "medium",
                        title="Broad destination population",
                        category="destination_scope",
                        path=path,
                        rule_index=index,
                        evidence=f"Broad destination selector(s): {', '.join(broad_destinations)}.",
                        recommendation=(
                            "Replace the wildcard with explicit destination roles, tags, or hosts "
                            "where practical."
                        ),
                    )

            source_ids: set[str] = set()
            destination_ids: set[str] = set()
            expansion_complete = True
            for selector in sources:
                ids, _, status = expand_selector(selector, policy, devices, users)
                source_ids.update(ids)
                expansion_complete = expansion_complete and status == "fully_evaluated"
            for selector in destinations:
                ids, _, status = expand_selector(selector, policy, devices, users)
                destination_ids.update(ids)
                expansion_complete = expansion_complete and status == "fully_evaluated"
            if not expansion_complete:
                incomplete_rules += 1

            pair_count = sum(
                1
                for source_id in source_ids
                for destination_id in destination_ids
                if source_id != destination_id
            )
            sensitive = any(_is_sensitive_selector(selector) for selector in destinations) or any(
                device.get("primary_role") in {"exit_node", "subnet_router", "service_hosting"}
                for device in devices
                if str(device["id"]) in destination_ids
            )
            posture = _string_list(rule.get("srcPosture"))
            if not global_access and unrestricted and pair_count >= 10:
                severity = "high" if pair_count >= 25 else "medium"
                add(
                    finding_id=f"{section}-{index}-lateral-expansion",
                    severity=severity,
                    title="Large unrestricted host-to-host expansion",
                    category="lateral_movement",
                    path=path,
                    rule_index=index,
                    evidence=(
                        f"Current inventory expansion permits up to {pair_count:,} distinct "
                        "source-to-destination "
                        f"device pairs without protocol or port restriction."
                    ),
                    recommendation=(
                        "Confirm that every role-to-role path is required, then constrain "
                        "destinations and network permissions. Split rules by workload purpose "
                        "when that improves reviewability."
                    ),
                    confidence="high" if expansion_complete else "medium",
                    affected_pair_count=pair_count,
                    sample_sources=[device_names[item] for item in sorted(source_ids)[:5]],
                    sample_destinations=[
                        device_names[item] for item in sorted(destination_ids)[:5]
                    ],
                )
            if broad_sources and sensitive and not posture:
                add(
                    finding_id=f"{section}-{index}-sensitive-without-posture",
                    severity="medium",
                    title="Broad access to infrastructure without source posture",
                    category="device_posture",
                    path=path,
                    rule_index=index,
                    evidence=(
                        "A broad source reaches infrastructure-like destinations and the rule has "
                        "no srcPosture constraint."
                    ),
                    recommendation=(
                        "If supported by the intended clients, consider requiring an appropriate "
                        "posture "
                        "condition in addition to narrowing identity and network scope."
                    ),
                    confidence="medium",
                )

    ssh_rules = policy.get("ssh", [])
    if isinstance(ssh_rules, list):
        for index, rule in enumerate(ssh_rules):
            if not isinstance(rule, dict):
                incomplete_rules += 1
                continue
            reviewed_rules += 1
            if str(rule.get("action", "")).lower() != "accept":
                continue
            sources = _string_list(rule.get("src"))
            destinations = _string_list(rule.get("dst"))
            login_users = _string_list(rule.get("users"))
            broad_sources = [selector for selector in sources if _is_broad_selector(selector)]
            broad_destinations = [
                selector for selector in destinations if _is_broad_selector(selector)
            ]
            risky_users = [
                user for user in login_users if user in {"root", "autogroup:nonroot", "*"}
            ]
            if broad_sources or broad_destinations or risky_users:
                add(
                    finding_id=f"ssh-{index}-broad-accept",
                    severity="high" if "root" in risky_users or broad_destinations else "medium",
                    title="Broad Tailscale SSH accept rule",
                    category="ssh_access",
                    path=f'$["ssh"][{index}]',
                    rule_index=index,
                    evidence=(
                        "The accept rule combines review-sensitive selectors: "
                        + ", ".join(broad_sources + broad_destinations + risky_users)
                        + "."
                    ),
                    recommendation=(
                        "Narrow source, destination, and login users. Consider check with an "
                        "appropriate "
                        "reauthentication period for privileged or sensitive destinations."
                    ),
                )

    tag_owners = policy.get("tagOwners", {})
    if isinstance(tag_owners, dict):
        for tag, owners in tag_owners.items():
            broad = [owner for owner in _string_list(owners) if _is_broad_selector(owner)]
            if broad:
                add(
                    finding_id=f"tag-owner-{hashlib.sha256(str(tag).encode()).hexdigest()[:12]}",
                    severity="high",
                    title="Broad tag ownership",
                    category="tag_ownership",
                    path=_path_key(_path_key("$", "tagOwners"), str(tag)),
                    evidence=(
                        f"{tag} can be assigned by broad owner selector(s): {', '.join(broad)}."
                    ),
                    recommendation=(
                        "Restrict tag ownership to the smallest trusted user, group, or existing "
                        "tag set."
                    ),
                )

    auto_approvers = policy.get("autoApprovers", {})
    if isinstance(auto_approvers, dict):
        for kind in ("routes", "exitNode"):
            values = auto_approvers.get(kind, {})
            entries = values.items() if isinstance(values, dict) else [(kind, values)]
            for target, approvers in entries:
                broad = [item for item in _string_list(approvers) if _is_broad_selector(item)]
                if broad:
                    add(
                        finding_id=f"auto-approver-{kind}-{hashlib.sha256(str(target).encode()).hexdigest()[:12]}",
                        severity="high",
                        title="Broad route auto-approval authority",
                        category="route_approval",
                        path=_path_key(
                            _path_key(_path_key("$", "autoApprovers"), kind), str(target)
                        ),
                        evidence=(
                            f"{target} accepts broad approver selector(s): {', '.join(broad)}."
                        ),
                        recommendation=(
                            "Limit automatic approval authority to dedicated, trusted identities "
                            "or device tags."
                        ),
                    )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda finding: (order[finding["severity"]], finding["path"], finding["id"]))
    counts = {severity: 0 for severity in order}
    for finding in findings:
        counts[finding["severity"]] += 1
    return {
        "review_status": "heuristic",
        "reviewed_rule_count": reviewed_rules,
        "incomplete_rule_count": incomplete_rules,
        "finding_count": len(findings),
        "counts": counts,
        "findings": findings,
        "truncated": len(findings) >= 500,
        "notice": (
            "Potential exposure for human review, not proof of exploitation, policy invalidity, "
            "or that access is unnecessary. TailView does not change the policy."
        ),
        "limitations": [
            "Business intent and workload sensitivity cannot be inferred from policy syntax alone.",
            "Selector impact is evaluated against the current synchronized inventory, which may "
            "be incomplete.",
            "Application capabilities and unsupported or unresolved selectors are not interpreted "
            "as network access.",
            "Findings do not incorporate denied traffic because Tailscale flow logs contain "
            "successful connections only.",
        ],
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
