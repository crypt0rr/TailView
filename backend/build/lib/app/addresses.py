from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import datetime
from typing import Any, NamedTuple


class PhysicalEndpointObservation(NamedTuple):
    address: str
    port: int | None
    start: datetime
    end: datetime
    reporting_node_id: str | None
    reported_bytes: int


def classify_address(value: str) -> tuple[str, int | None]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown", None
    if address.is_loopback:
        return "loopback", address.version
    if address.is_link_local:
        return "link_local", address.version
    if address.is_multicast:
        return "multicast", address.version
    if address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        return "shared", address.version
    if address.version == 4 and any(
        address in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    ):
        return "private", address.version
    if address.version == 6 and address in ipaddress.ip_network("fc00::/7"):
        return "private", address.version
    if address.is_global:
        return "public", address.version
    return "reserved", address.version


def tailnet_address_items(addresses: Iterable[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in addresses:
        _, family = classify_address(value)
        result.append(
            {
                "address": value,
                "family": f"IPv{family}" if family else "Unknown",
                "scope": "tailnet",
                "provenance": "tailscale_device_api",
                "reliability": "api_reported",
            }
        )
    return result


def aggregate_physical_endpoints(
    observations: Iterable[PhysicalEndpointObservation],
    device_labels: dict[str, str],
    *,
    limit: int = 50,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for observation in observations:
        if not observation.address:
            continue
        classification, family = classify_address(observation.address)
        item = grouped.setdefault(
            observation.address,
            {
                "address": observation.address,
                "family": f"IPv{family}" if family else "Unknown",
                "classification": classification,
                "ports": [],
                "first_observed_at": observation.start,
                "last_observed_at": observation.end,
                "reporting_node_ids": set(),
                "reported_bytes": 0,
                "provenance": "network_flow_logs_physical",
                "reliability": "client_reported_unverified",
            },
        )
        item["first_observed_at"] = min(item["first_observed_at"], observation.start)
        item["last_observed_at"] = max(item["last_observed_at"], observation.end)
        item["reported_bytes"] += observation.reported_bytes
        if observation.reporting_node_id:
            item["reporting_node_ids"].add(observation.reporting_node_id)
        if observation.port is not None and observation.port not in item["ports"]:
            # Input is ordered newest-first, so this retains the five most recent ports.
            if len(item["ports"]) < 5:
                item["ports"].append(observation.port)

    ordered = sorted(grouped.values(), key=lambda item: item["last_observed_at"], reverse=True)[
        :limit
    ]
    for item in ordered:
        reporter_ids = sorted(item.pop("reporting_node_ids"))
        item["observer_count"] = len(reporter_ids)
        item["observers"] = [
            {"id": reporter_id, "name": device_labels.get(reporter_id, reporter_id)}
            for reporter_id in reporter_ids[:10]
        ]
    return ordered
