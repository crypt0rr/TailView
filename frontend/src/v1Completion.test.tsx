import axe from "axe-core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as apiModule from "./api";
import type { CurrentUser } from "./api";
import { Telemetry, Topology } from "./pages";
import { TimeRangeProvider } from "./timeRange";
import type { Device, TelemetryObservation, TopologyData } from "./types";

const administrator: CurrentUser = {
  id: "admin", username: "admin", display_name: "Administrator",
  role: "administrator", must_change_password: false, mfa_enabled: false,
  mfa_required: false, auth_status: "authenticated",
};

const device: Device = {
  id: "node", name: "Database", source_name: "database.example.ts.net", hostname: "database",
  os: "linux", version: "1.84.0", owner_id: null, owner_display_name: null,
  owner_login_name: null, online: true, authorized: true, active: true, last_seen: null,
  created: null, key_expiry: null, key_expiry_disabled: true, addresses: ["100.64.0.1"],
  tags: ["tag:database"], advertised_routes: [], approved_routes: [],
  roles: ["database"], api_roles: ["tagged_server"], primary_role: "database",
  api_primary_role: "tagged_server", source: "tailscale_device_api", metadata: {
    display_name: "Database", description: "Production data", function: "production",
    functional_groups: ["production"], custom_roles: ["database"],
    primary_role_override: "database", environment: "production", location: "Amsterdam",
    criticality: "critical", icon: "database", hidden: false,
    default_map_visible: true, revision: 2,
  },
};

function renderWithProviders(node: React.ReactNode, route: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><TimeRangeProvider>{node}</TimeRangeProvider></MemoryRouter></QueryClientProvider>);
}

afterEach(() => vi.restoreAllMocks());

describe("v1 completion", () => {
  it("offers an accessible topology table with equivalent relationships and device selection", async () => {
    const topology: TopologyData = { nodes: [device], edges: [{ id: "self", source: "node", target: "node", kind: "observed", reported_bytes: 12 }], notice: "Separated layers" };
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (String(path).startsWith("/topology")) return topology as never;
      if (String(path).startsWith("/saved-views")) return { items: [], next_cursor: null } as never;
      if (path === "/devices/node?address_hours=168") return { ...device, flows: [] } as never;
      return { items: [] } as never;
    });
    const view = renderWithProviders(<Topology user={administrator} />, "/topology?mode=table&observed=true");
    expect(await screen.findByLabelText("Topology table alternative")).toBeTruthy();
    expect(screen.getByText("12 B")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Database" }));
    expect(await screen.findByLabelText("Device details for Database")).toBeTruthy();
    const results = await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } });
    expect(results.violations).toEqual([]);
  });

  it("allows an administrator to update source-separated local metadata", async () => {
    const requests = vi.spyOn(apiModule, "request").mockImplementation(async (path, options) => {
      if (String(path).startsWith("/topology")) return { nodes: [device], edges: [], notice: "" } as never;
      if (String(path).startsWith("/saved-views")) return { items: [], next_cursor: null } as never;
      if (path === "/devices/node?address_hours=168") return { ...device, flows: [] } as never;
      if (path === "/devices/node/metadata" && options?.method === "PUT") return { status: "updated", revision: 3 } as never;
      return { items: [] } as never;
    });
    renderWithProviders(<Topology user={administrator} />, "/topology?mode=table");
    fireEvent.click(await screen.findByRole("button", { name: "Database" }));
    fireEvent.click(await screen.findByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Description"), { target: { value: "Updated description" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    await waitFor(() => expect(requests).toHaveBeenCalledWith(
      "/devices/node/metadata",
      expect.objectContaining({ method: "PUT", body: expect.stringContaining("Updated description") }),
    ));
  });

  it("renders normalized telemetry with provenance and no serious accessibility violations", async () => {
    const observation: TelemetryObservation = {
      id: "obs", collector_node_id: "node", collector_device_id: "node",
      collector_name: "Database", client_version: "1.84.0", udp: true, ipv4: true,
      ipv6: false, mapping_varies_by_dest_ip: false, preferred_derp: "ams",
      endpoints: [], derp_latency: { ams: 0.012 }, observed_at: new Date().toISOString(),
      received_at: new Date().toISOString(), stale: false, scope: "single_collector_node",
      provenance: "local_telemetry", notice: "Single collector",
    };
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/telemetry/summary") return { collectors: [observation], counts: { collectors: 1, fresh: 1, stale: 0, unmapped: 0 }, status: "available", notice: "Local-only evidence." } as never;
      if (String(path).startsWith("/telemetry/observations")) return { items: [observation], next_cursor: null } as never;
      return {} as never;
    });
    const view = renderWithProviders(<Telemetry />, "/telemetry");
    expect(await screen.findByRole("heading", { name: "Telemetry" })).toBeTruthy();
    expect(screen.getByText("UDP yes · IPv4 yes · IPv6 no")).toBeTruthy();
    expect(screen.getByText("local only")).toBeTruthy();
    const results = await axe.run(view.container, { rules: { "color-contrast": { enabled: false } } });
    expect(results.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
  });
});
