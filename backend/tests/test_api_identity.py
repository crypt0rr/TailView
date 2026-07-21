from app.api import device_dict, flow_identity, preferred_device_label
from app.models import Device, TailnetUser


def test_device_response_prefers_owner_display_name() -> None:
    device = Device(
        id="node-1",
        name="database.example.ts.net",
        hostname="database",
        owner_id="user-1",
        online=True,
        authorized=True,
        addresses=[],
        tags=[],
        advertised_routes=[],
        approved_routes=[],
        roles=["service_hosting"],
        primary_role="service_hosting",
    )
    owner = TailnetUser(
        id="user-1",
        display_name="Alice Example",
        login_name="alice@example.com",
    )

    response = device_dict(device, owner=owner)

    assert response["owner_display_name"] == "Alice Example"
    assert response["owner_login_name"] == "alice@example.com"
    assert response["owner_id"] == "user-1"


def test_flow_identity_prefers_device_name_and_retains_raw_value() -> None:
    identity = flow_identity(
        "node-1", "100.64.0.1", {"node-1": "database.example.ts.net"}, "Unresolved"
    )

    assert identity == {
        "id": "node-1",
        "label": "database.example.ts.net",
        "raw": "100.64.0.1",
    }


def test_flow_identity_retains_unresolved_address() -> None:
    identity = flow_identity(None, "192.0.2.10", {}, "Unresolved")

    assert identity == {"id": None, "label": "192.0.2.10", "raw": "192.0.2.10"}


def test_export_label_prefers_device_name() -> None:
    assert preferred_device_label("node-1", "100.64.0.1", {"node-1": "database"}) == "database"
