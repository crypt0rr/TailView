from datetime import UTC, datetime

from app.sync import build_address_index, classify, parse_time, redact, split_endpoint


def test_classification_is_multi_role_and_deterministic() -> None:
    roles, primary = classify({"tags": ["tag:infra"], "os": "linux"}, ["0.0.0.0/0", "10.0.0.0/8"])
    assert roles == ["exit_node", "subnet_router", "tagged_server"]
    assert primary == "exit_node"


def test_redaction_is_recursive() -> None:
    assert redact({"Authorization": "Bearer x", "nested": {"clientSecret": "x"}, "safe": 1}) == {
        "Authorization": "[REDACTED]",
        "nested": {"clientSecret": "[REDACTED]"},
        "safe": 1,
    }


def test_endpoint_parser_handles_ipv4_ipv6_and_missing_ports() -> None:
    assert split_endpoint("100.64.0.1:443") == ("100.64.0.1", 443)
    assert split_endpoint("[fd7a::1]:53") == ("fd7a::1", 53)
    assert split_endpoint("100.64.0.1") == ("100.64.0.1", None)


def test_rfc3339_time_parser() -> None:
    assert parse_time("2026-07-20T10:00:00Z") == datetime(2026, 7, 20, 10, tzinfo=UTC)
    assert parse_time(None) is None


def test_address_index_matches_exact_addresses_and_omits_ambiguity() -> None:
    index = build_address_index(
        [
            ("node-a", ["100.64.0.1", "fd7a::1"]),
            ("node-b", ["100.64.0.2", "fd7a::1"]),
        ]
    )
    assert index == {"100.64.0.1": "node-a", "100.64.0.2": "node-b"}
