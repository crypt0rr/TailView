from datetime import UTC, datetime, timedelta

import pytest

from app.addresses import (
    PhysicalEndpointObservation,
    aggregate_physical_endpoints,
    classify_address,
    tailnet_address_items,
)


@pytest.mark.parametrize(
    ("value", "classification", "family"),
    [
        ("8.8.8.8", "public", 4),
        ("2001:4860:4860::8888", "public", 6),
        ("10.1.2.3", "private", 4),
        ("172.16.1.2", "private", 4),
        ("192.168.1.2", "private", 4),
        ("fd00::1", "private", 6),
        ("100.64.0.8", "shared", 4),
        ("127.0.0.1", "loopback", 4),
        ("fe80::1", "link_local", 6),
        ("224.0.0.1", "multicast", 4),
        ("192.0.2.1", "reserved", 4),
        ("not-an-address", "unknown", None),
    ],
)
def test_classify_address(value: str, classification: str, family: int | None) -> None:
    assert classify_address(value) == (classification, family)


def test_tailnet_addresses_remain_api_reported() -> None:
    items = tailnet_address_items(["100.100.10.20", "fd7a:115c:a1e0::1"])

    assert [item["family"] for item in items] == ["IPv4", "IPv6"]
    assert {item["reliability"] for item in items} == {"api_reported"}
    assert {item["scope"] for item in items} == {"tailnet"}


def test_endpoint_aggregation_deduplicates_ip_and_bounds_ports_and_observers() -> None:
    now = datetime.now(UTC)
    observations = [
        PhysicalEndpointObservation(
            address="8.8.8.8",
            port=41641 + index,
            start=now - timedelta(minutes=index + 1),
            end=now - timedelta(minutes=index),
            reporting_node_id=f"observer-{index % 2}",
            reported_bytes=100,
        )
        for index in range(7)
    ]

    result = aggregate_physical_endpoints(
        observations,
        {"observer-0": "Laptop", "observer-1": "Server"},
    )

    assert len(result) == 1
    assert result[0]["ports"] == [41641, 41642, 41643, 41644, 41645]
    assert result[0]["observer_count"] == 2
    assert result[0]["observers"] == [
        {"id": "observer-0", "name": "Laptop"},
        {"id": "observer-1", "name": "Server"},
    ]
    assert result[0]["reported_bytes"] == 700
    assert result[0]["reliability"] == "client_reported_unverified"


def test_endpoint_aggregation_ignores_missing_addresses_and_limits_results() -> None:
    now = datetime.now(UTC)
    observations = [
        PhysicalEndpointObservation(
            address="" if index == 0 else f"10.0.0.{index}",
            port=None,
            start=now,
            end=now + timedelta(seconds=index),
            reporting_node_id=None,
            reported_bytes=0,
        )
        for index in range(6)
    ]

    result = aggregate_physical_endpoints(observations, {}, limit=3)

    assert [item["address"] for item in result] == ["10.0.0.5", "10.0.0.4", "10.0.0.3"]
