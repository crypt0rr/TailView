from app.policy import evaluate_policy, expand_selector, parse_policy, source_line

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
