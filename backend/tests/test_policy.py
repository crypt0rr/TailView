import json

from app.policy import (
    evaluate_policy,
    expand_selector,
    parse_policy,
    review_policy,
    security_review_policy,
    source_line,
)

POLICY = """{
  // Comment and trailing commas are HuJSON-compatible.
  "groups": {"group:eng": ["alice@example.com",],},
  "grants": [{"src": ["group:eng"], "dst": ["tag:api"], "ip": ["tcp:443"],},],
}"""


def test_parse_hujson_and_source_location() -> None:
    parsed = parse_policy(POLICY)
    assert parsed.normalized["groups"]["group:eng"] == ["alice@example.com"]
    assert parsed.unsupported == []
    assert source_line(POLICY, "grants") == (4, 4)


def test_future_construct_is_explicitly_unsupported() -> None:
    parsed = parse_policy('{"futureThing": {}}')
    assert parsed.unsupported == ["futureThing"]


def test_selector_resolution_and_additive_allow() -> None:
    devices = [
        {"id": "laptop", "owner_id": "alice", "tags": [], "addresses": ["100.64.0.1"]},
        {"id": "api", "owner_id": None, "tags": ["tag:api"], "addresses": ["100.64.0.2"]},
    ]
    users = [{"id": "alice", "login_name": "alice@example.com", "display_name": "Alice"}]
    parsed = parse_policy(POLICY)
    expanded, path, status = expand_selector("group:eng", parsed.normalized, devices, users)
    assert expanded == ["laptop"]
    assert "alice@example.com" in path
    assert status == "fully_evaluated"
    relationships = evaluate_policy(parsed.normalized, devices, users)
    assert relationships[0]["source"] == "laptop"
    assert relationships[0]["destination"] == "api"
    assert relationships[0]["ports"] == ["tcp:443"]


def test_unknown_autogroup_is_not_guessed() -> None:
    expanded, _, status = expand_selector("autogroup:future", {}, [], [])
    assert expanded == []
    assert status == "unsupported_construct"


def test_duplicate_review_removes_only_exact_entries_without_mutating_source() -> None:
    grant = {"src": ["group:eng"], "dst": ["tag:api", "tag:api"], "ip": ["tcp:443"]}
    policy = {
        "groups": {"group:eng": ["alice@example.com", "alice@example.com"]},
        "grants": [grant, grant],
        "futureThing": {"ordered": ["same", "same"]},
    }

    review = review_policy(policy)
    candidate = json.loads(review["candidate"])

    assert review["duplicate_count"] == 3
    assert candidate["groups"]["group:eng"] == ["alice@example.com"]
    assert candidate["grants"] == [{"src": ["group:eng"], "dst": ["tag:api"], "ip": ["tcp:443"]}]
    assert candidate["futureThing"]["ordered"] == ["same", "same"]
    assert policy["grants"][0]["dst"] == ["tag:api", "tag:api"]
    assert review["requires_upstream_validation"] is True
    assert review["comments_preserved"] is False


def test_duplicate_review_returns_unchanged_candidate_when_none_exist() -> None:
    review = review_policy({"grants": [{"src": ["*"], "dst": ["tag:web"]}]})

    assert review["duplicate_count"] == 0
    assert review["changed"] is False


def test_security_review_flags_unrestricted_all_to_all_access() -> None:
    review = security_review_policy({"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}, [], [])

    assert review["counts"]["critical"] == 1
    assert review["findings"][0]["category"] == "network_access"
    assert "not proof" in review["notice"]


def test_security_review_summarizes_large_lateral_expansion() -> None:
    devices = [
        {
            "id": f"source-{index}",
            "name": f"Source {index}",
            "owner_id": "alice",
            "tags": [],
            "addresses": [],
            "primary_role": "standard_node",
        }
        for index in range(6)
    ] + [
        {
            "id": f"server-{index}",
            "name": f"Server {index}",
            "owner_id": None,
            "tags": ["tag:server"],
            "addresses": [],
            "primary_role": "service_hosting",
        }
        for index in range(6)
    ]
    users = [{"id": "alice", "login_name": "alice@example.com", "display_name": "Alice"}]
    policy = {
        "groups": {"group:staff": ["alice@example.com"]},
        "grants": [{"src": ["group:staff"], "dst": ["tag:server"], "ip": ["*"]}],
    }

    review = security_review_policy(policy, devices, users)
    finding = next(item for item in review["findings"] if item["category"] == "lateral_movement")

    assert finding["severity"] == "high"
    assert finding["affected_pair_count"] == 36
    assert len(finding["sample_sources"]) == 5
    assert len(finding["sample_destinations"]) == 5


def test_security_review_flags_broad_ssh_tag_and_route_authority() -> None:
    review = security_review_policy(
        {
            "ssh": [
                {
                    "action": "accept",
                    "src": ["autogroup:member"],
                    "dst": ["*"],
                    "users": ["root"],
                }
            ],
            "tagOwners": {"tag:prod": ["autogroup:member"]},
            "autoApprovers": {"routes": {"10.0.0.0/8": ["autogroup:member"]}},
        },
        [],
        [],
    )

    categories = {finding["category"] for finding in review["findings"]}
    assert {"ssh_access", "tag_ownership", "route_approval"} <= categories
    assert review["counts"]["high"] == 3


def test_security_review_does_not_treat_app_capability_as_network_access() -> None:
    review = security_review_policy(
        {
            "grants": [
                {
                    "src": ["autogroup:member"],
                    "dst": ["tag:app"],
                    "app": {"example.com/capability": [{"role": "reader"}]},
                }
            ]
        },
        [],
        [],
    )

    assert review["finding_count"] == 0
