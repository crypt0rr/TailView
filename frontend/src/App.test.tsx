import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { navigationForRole, Shell, nav, partitionNavigation } from "./App";
import * as apiModule from "./api";
import { api } from "./api";
import {
  AddressInventoryView,
  AccessGovernance,
  AccountSecurity,
  DeviceTrafficRanking,
  DeviceTable,
  dnsConfigurationEntries,
  Findings,
  PolicySecurityReview,
  SecurityPosture,
  TailViewAccess,
  dashboardPairFlowHref,
  dashboardMetricCards,
  keyExpiryState,
  trafficChartData,
  trafficTimeLabel,
  trafficVolumeLabel,
} from "./pages";
import { TimeRangeProvider, useTimeRange } from "./timeRange";
import type { AddressInventory, Device } from "./types";

describe("TailView", () => {
  it("keeps the product name stable", () => {
    expect("TailView").toMatch(/TailView/);
  });

  it("keeps administrator-only workspaces out of Viewer navigation", () => {
    const viewerLabels = navigationForRole("viewer").map(([label]) => label);

    expect(viewerLabels).not.toContain("Operations");
    expect(viewerLabels).not.toContain("Access governance");
    expect(viewerLabels).not.toContain("DNS");
    expect(viewerLabels).not.toContain("Settings");
    expect(viewerLabels).toEqual(expect.arrayContaining([
      "Dashboard",
      "Topology",
      "Flows",
      "Reports",
      "Devices",
      "Policy",
      "Security posture",
      "Findings",
    ]));
  });

  it("moves unavailable and successfully empty inventories out of active navigation", () => {
    const items = nav.filter(([label]) => ["Flows", "Services", "Devices"].includes(label));
    const result = partitionNavigation(
      items,
      [
        { name: "network_flow_logs", status: "plan_unavailable", requirement: "Premium", detail: "Not included", last_success: null },
        { name: "services", status: "available", requirement: "all:read", detail: "Retrieved", last_success: null },
      ],
      {
        "/services": {
          count: 0,
          evaluated: true,
          in_use: false,
          status: "not_configured",
          detail: "Successfully synchronized; no Tailscale Services are currently configured.",
          checked_at: "2026-07-22T10:00:00Z",
        },
      },
    );

    expect(result.active.map(([label]) => label)).toEqual(["Devices"]);
    expect(result.inactive.map(({ item }) => item[0])).toEqual(["Flows", "Services"]);
    expect(result.inactive[0]?.capability.detail).toBe("Not included");
    expect(result.inactive[1]?.capability.status).toBe("not_configured");
  });

  it("keeps every reported split-DNS field visible in stable order", () => {
    expect(
      dnsConfigurationEntries({
        routes: { "corp.example": ["100.64.0.53"] },
        fallback: true,
      }),
    ).toEqual([
      ["fallback", true],
      ["routes", { "corp.example": ["100.64.0.53"] }],
    ]);
  });

  it("deep-links unresolved dashboard pairs to their exact raw flow endpoints", () => {
    expect(dashboardPairFlowHref({
      source: "apple-tv.example.ts.net",
      source_device_id: "node-apple-tv",
      source_raw: null,
      source_resolved: true,
      destination: "203.0.113.10",
      destination_device_id: null,
      destination_raw: "203.0.113.10",
      destination_resolved: false,
      reported_bytes: 1024,
    }, "24h")).toBe(
      "/flows?range=24h&source=node-apple-tv&destination=203.0.113.10&resolution=unresolved",
    );
  });

  it("leaves the authenticated shell after logout", async () => {
    const logout = vi.spyOn(api, "logout").mockResolvedValue(undefined);
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    function LogoutHarness() {
      const [signedIn, setSignedIn] = useState(true);
      if (!signedIn) return <div>Welcome back</div>;
      return (
        <Shell
          user={{
            id: "admin",
            username: "admin",
            display_name: "Administrator",
            role: "administrator",
            must_change_password: false,
            mfa_enabled: false,
            mfa_required: false,
            auth_status: "authenticated",
          }}
          onLogout={() => setSignedIn(false)}
        />
      );
    }

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <TimeRangeProvider>
            <LogoutHarness />
          </TimeRangeProvider>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const dashboardNavigation = screen.getByRole("button", { name: "Dashboard" });
    expect(dashboardNavigation).not.toHaveAttribute("title");
    fireEvent.click(screen.getByRole("button", { name: "Toggle sidebar" }));
    expect(dashboardNavigation).toHaveAttribute("title", "Dashboard");

    fireEvent.click(screen.getByTitle("Log out"));
    await waitFor(() => expect(screen.getByText("Welcome back")).toBeTruthy());
    expect(logout).toHaveBeenCalledOnce();
    logout.mockRestore();
  });

  it("opens device details from the inventory table instead of navigating", () => {
    const device: Device = {
      id: "n1CNTRL",
      name: "router.example.ts.net",
      source_name: "router.example.ts.net",
      hostname: "router",
      os: "linux",
      version: "1.0",
      owner_id: "user-1",
      owner_display_name: "Alice Example",
      owner_login_name: "alice@example.com",
      online: true,
      authorized: true,
      last_seen: "2026-07-21T10:00:00Z",
      created: null,
      key_expiry: null,
      key_expiry_disabled: null,
      addresses: ["100.64.0.1"],
      tags: [],
      advertised_routes: ["0.0.0.0/0"],
      approved_routes: ["0.0.0.0/0"],
      roles: ["exit_node"],
      primary_role: "exit_node",
      source: "tailscale_device_api",
      metadata: null,
    };
    const onSelect = vi.fn();
    render(
      <MemoryRouter>
        <DeviceTable devices={[device]} onSelect={onSelect} />
      </MemoryRouter>,
    );

    const owner = screen.getByRole("link", { name: "Alice Example" });
    expect(owner.getAttribute("href")).toBe("/users?user=user-1");

    fireEvent.click(
      screen.getByRole("button", {
        name: /view details for router\.example\.ts\.net/i,
      }),
    );

    expect(onSelect).toHaveBeenCalledOnce();
    expect(onSelect).toHaveBeenCalledWith(device);
  });

  it("shows self-service account security and current sessions", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/auth/sessions") return { items: [{
        id: "session-1", user_id: "viewer-1", created_at: "2026-07-22T08:00:00Z",
        last_seen_at: "2026-07-22T09:00:00Z", expires_at: "2026-07-22T20:00:00Z",
        revoked_at: null, initial_ip: "192.0.2.10", last_ip: "192.0.2.10",
        user_agent: "Firefox on Linux", restricted: false, current: true,
      }] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter><AccountSecurity user={{ username: "viewer", role: "viewer", mfa_enabled: false, mfa_required: false }} /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText("Account security")).toBeTruthy();
    expect(screen.getByText("Firefox on Linux")).toBeTruthy();
    expect(screen.getByText("Current")).toBeTruthy();
    request.mockRestore();
  });

  it("separates TailView account administration from tailnet users", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (String(path).startsWith("/settings/app-users?")) return { items: [{ id: "local-1", username: "viewer", display_name: "Local Viewer", role: "viewer", active: true, must_change_password: true, mfa_enabled: false, last_login_at: null, password_changed_at: null, deactivated_at: null, created_at: "2026-07-22T08:00:00Z", session_count: 0 }], next_cursor: null } as never;
      if (String(path).startsWith("/settings/app-sessions?")) return { items: [], next_cursor: null } as never;
      if (path === "/settings/auth-policy") return { required_roles: [] } as never;
      if (path === "/settings/auth-events?limit=25") return { items: [], next_cursor: null } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter><TailViewAccess /></MemoryRouter></QueryClientProvider>);
    expect(await screen.findByText("TailView access")).toBeTruthy();
    expect(screen.getByText("Local Viewer")).toBeTruthy();
    expect(screen.getByText("Password change required")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Change role" }).classList.contains("button")).toBe(true);
    expect(screen.getByRole("button", { name: "Change role" }).classList.contains("ghost")).toBe(true);
    request.mockRestore();
  });

  it("shows fleet posture metrics, limitations, findings, and filters", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/security/posture") {
        return {
          counts: { devices: 2, pass: 1, fail: 1, incomplete: 0, stale: 1, pending_approval: 0, expiring_attributes: 1 },
          coverage: { devices_with_fresh_evidence: 1, percent: 50 },
          attribute_coverage: [{ key: "node:os", device_count: 2, percent: 100 }],
          namespaces: { node: 2 }, auto_update: { true: 1 }, release_tracks: { stable: 2 },
          findings: [{ severity: "high", kind: "posture_failure", device_id: "n1", device: "node-one", message: "Current posture fails." }],
          capability: { status: "available", detail: "", last_success: null, required_scope: "all:read" },
          limitations: ["Current evidence only."],
        } as never;
      }
      if (path.startsWith("/security/posture/devices")) return { items: [], next_cursor: null } as never;
      if (path === "/security/posture/integrations") return { items: [], capability_status: "available" } as never;
      if (path === "/security/settings") return { available: true, values: { devicesApprovalOn: true }, synced_at: null, capability_status: "available" } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter><SecurityPosture /></MemoryRouter></QueryClientProvider>);

    expect(await screen.findByText("Security posture")).toBeTruthy();
    expect(screen.getByText("50%")).toBeTruthy();
    expect(screen.getByText("Current posture fails.")).toBeTruthy();
    expect(screen.getByText("Current evidence only.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Posture result filter"), { target: { value: "fail" } });
    await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes("result=fail"))).toBe(true));
    request.mockRestore();
  });

  it("shows administrator governance findings and sanitized credential metadata", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/security/governance") return {
        counts: { credentials: 1, active_credentials: 1, expiring_credentials: 1, pending_invites: 0, verified_contacts: 1, enabled_streams: 1 },
        findings: [{ id: "expiry:key", severity: "high", kind: "credential_expiring", record_type: "credential", record_id: "key", label: "CI key", message: "A credential expires soon.", remediation: "Rotate it.", evidence: {} }],
        capabilities: {
          credentials: { status: "available", detail: "", last_success: null, checked_at: null, required_scope: "all:read" },
          invites: { status: "available", detail: "", last_success: null, checked_at: null, required_scope: "devices_invites:read" },
          contacts: { status: "available", detail: "", last_success: null, checked_at: null, required_scope: "account_settings:read" },
          log_streaming: { status: "available", detail: "", last_success: null, checked_at: null, required_scope: "log_streaming:read" },
        },
        freshness: {}, limitations: ["Secrets are never requested."],
      } as never;
      if (String(path).startsWith("/security/governance/credentials")) return { items: [{ id: "full-id", display_id: "tskey-auth-…123456", type: "auth_key", description: "CI key", creator_id: "Alice", scopes: ["all:read"], tags: ["tag:ci"], reusable: true, ephemeral: false, preapproved: true, created_at: null, expires_at: "2026-08-01T00:00:00Z", status: "active", present: true, stale: false, synced_at: "2026-07-22T00:00:00Z", provenance: "tailscale_keys_api" }], next_cursor: null } as never;
      if (path === "/security/governance/invites" || path === "/security/governance/contacts" || path === "/security/governance/log-streaming") return { items: [] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter><AccessGovernance /></MemoryRouter></QueryClientProvider>);

    expect(await screen.findByText("Access governance")).toBeTruthy();
    expect(screen.getByText("A credential expires soon.")).toBeTruthy();
    expect(await screen.findByText("tskey-auth-…123456")).toBeTruthy();
    expect(screen.queryByText("full-id")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: "contacts" }));
    expect(await screen.findByText("No contacts reported")).toBeTruthy();
    request.mockRestore();
  });

  it("shows durable findings, filters, and lifecycle details", async () => {
    const finding = {
      id: "finding-1", source: "policy", category: "broad_access", severity: "high",
      title: "Broad host access", summary: "A host can reach a broad destination.",
      remediation: "Narrow the selector.", subject_type: "policy_rule",
      subject_id: "public-reference", subject_display: "grants[0]", evidence: { path: "grants[0]" },
      link_path: "/policy", status: "open", stale: false,
      first_seen: "2026-07-22T08:00:00Z", last_seen: "2026-07-22T09:00:00Z",
      last_evaluated: "2026-07-22T09:00:00Z", resolved_at: null,
      acknowledged_at: null, suppressed_until: null, suppression_reason: "",
      assigned_to: null, assignee: null, occurrence_count: 2,
    };
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/findings/summary") return { total: 1, open: 1, by_status: { open: 1 }, by_severity: { high: 1 }, open_by_severity: { high: 1 }, by_source: { policy: 1 }, generated_at: "2026-07-22T09:00:00Z" } as never;
      if (String(path).startsWith("/findings?")) return { items: [finding], next_cursor: null } as never;
      if (path === "/findings/finding-1") return { ...finding, transitions: [{ id: "transition-1", from_status: null, to_status: "open", actor_id: null, reason: "", occurred_at: "2026-07-22T08:00:00Z" }], occurrences: [] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={queryClient}><MemoryRouter><Findings user={{ id: "viewer", username: "viewer", role: "viewer" }} /></MemoryRouter></QueryClientProvider>);

    expect(await screen.findByText("Broad host access")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Finding severity"), { target: { value: "high" } });
    await waitFor(() => expect(request.mock.calls.some(([path]) => String(path).includes("severity=high"))).toBe(true));
    fireEvent.click(await screen.findByText("Broad host access"));
    expect(await screen.findByText("Narrow the selector.")).toBeTruthy();
    expect(screen.getByText("created → open")).toBeTruthy();
    expect(screen.queryByText("Acknowledge")).toBeNull();
    request.mockRestore();
  });

  it("builds dashboard traffic points only from server aggregates", () => {
    const points = trafficChartData([
      { bucket_start: "2026-07-21T10:00:00Z", reported_bytes: 2_500_000 },
      { bucket_start: "2026-07-21T11:00:00Z", reported_bytes: 0 },
    ]);
    expect(points.map((point) => point.reported)).toEqual([2.5, 0]);
    expect(points.at(0)?.time).toBe("2026-07-21T10:00:00Z");
  });

  it("ranks devices by reported traffic from highest to lowest", () => {
    render(
      <MemoryRouter>
        <DeviceTrafficRanking
          devices={[
            {
              device_id: "low",
              name: "Low traffic",
              reported_bytes: 100,
              reported_packets: 1,
              record_count: 1,
            },
            {
              device_id: "high",
              name: "High traffic",
              reported_bytes: 10_000,
              reported_packets: 20,
              record_count: 4,
            },
          ]}
          limit={10}
          setLimit={vi.fn()}
        />
      </MemoryRouter>,
    );

    const ranked = screen.getAllByRole("listitem");
    expect(ranked[0]?.textContent).toContain("High traffic");
    expect(ranked[1]?.textContent).toContain("Low traffic");
  });

  it("links dashboard metrics to their inventory overviews", () => {
    const cards = dashboardMetricCards({ devices: 47, online: 44, users: 4, expiring_keys: 9 });
    expect(cards.find((card) => card.label === "Expiring keys")?.href).toBe(
      "/devices?key_expiry=within_14_days",
    );
    expect(cards.find((card) => card.label === "Online")?.href).toBe(
      "/devices?status=online",
    );
  });

  it("distinguishes expiring keys from already expired keys", () => {
    const now = Date.parse("2026-07-21T12:00:00Z");
    expect(keyExpiryState("2026-07-20T12:00:00Z", false, now)).toBe("expired");
    expect(keyExpiryState("2026-07-28T12:00:00Z", false, now)).toBe("expiring");
    expect(keyExpiryState("2026-08-21T12:00:00Z", false, now)).toBe("valid");
    expect(keyExpiryState("2024-01-01T00:00:00Z", true, now)).toBe("disabled");
    expect(keyExpiryState(null, false, now)).toBe("not_reported");
    expect(keyExpiryState("2026-07-28T12:00:00Z", null, now)).toBe("not_reported");
  });

  it("uses compact, bounded traffic-axis labels", () => {
    expect(trafficVolumeLabel(0)).toBe("0 MB");
    expect(trafficVolumeLabel(400)).toBe("400 MB");
    expect(trafficVolumeLabel(1600)).toBe("1.6 GB");
    expect(trafficVolumeLabel(8438.261424)).toBe("8.4 GB");
    expect(trafficTimeLabel("not-a-date")).toBe("not-a-date");
  });

  it("restores and persists the global range through the URL", () => {
    localStorage.clear();
    function Probe() {
      const { range, hours, setRange } = useTimeRange();
      const location = useLocation();
      return (
        <>
          <span>{`${range}:${hours}:${location.search}`}</span>
          <button onClick={() => setRange("30d")}>Change range</button>
        </>
      );
    }
    render(
      <MemoryRouter initialEntries={["/flows?range=7d"]}>
        <TimeRangeProvider>
          <Probe />
        </TimeRangeProvider>
      </MemoryRouter>,
    );
    expect(screen.getByText("7d:168:?range=7d")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Change range" }));
    expect(screen.getByText("30d:720:?range=30d")).toBeTruthy();
    expect(localStorage.getItem("tailview.timeRange")).toBe("30d");
  });

  it("honors persisted device column visibility", () => {
    const device: Device = {
      id: "n1",
      name: "node.example.ts.net",
      source_name: "node.example.ts.net",
      hostname: "node",
      os: "linux",
      version: "1.0",
      owner_id: null,
      owner_display_name: null,
      owner_login_name: null,
      online: true,
      authorized: true,
      last_seen: null,
      created: null,
      key_expiry: null,
      key_expiry_disabled: null,
      addresses: [],
      tags: [],
      advertised_routes: [],
      approved_routes: [],
      roles: ["standard_node"],
      primary_role: "standard_node",
      source: "tailscale_device_api",
      metadata: null,
    };
    render(
      <MemoryRouter>
        <DeviceTable devices={[device]} onSelect={vi.fn()} columns={{ owner: false }} />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("columnheader", { name: "Owner" })).toBeNull();
  });

  it("renders policy security evidence and limitations", () => {
    render(
      <PolicySecurityReview
        query={{
          isLoading: false,
          error: null,
          data: {
            available: true,
            finding_count: 1,
            reviewed_rule_count: 3,
            incomplete_rule_count: 0,
            review_status: "heuristic",
            counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
            notice: "Potential exposure for human review, not proof of exploitation.",
            findings: [
              {
                id: "grant-1-lateral",
                severity: "high",
                category: "lateral_movement",
                path: '$["grants"][1]',
                title: "Large unrestricted host-to-host expansion",
                evidence: "The current inventory expands this rule to 42 device pairs.",
                recommendation: "Constrain destinations and network permissions.",
                confidence: "high",
                affected_pair_count: 42,
                sample_sources: ["laptop"],
                sample_destinations: ["database"],
              },
            ],
            limitations: ["Business intent cannot be inferred."],
          },
        }}
      />,
    );

    expect(screen.getByText("Large unrestricted host-to-host expansion")).toBeTruthy();
    expect(screen.getByText("42 device pairs")).toBeTruthy();
    expect(screen.getByText("Business intent cannot be inferred.")).toBeTruthy();
  });

  it("separates authoritative and observed device addresses", () => {
    const writeText = vi.fn();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const setAddressHours = vi.fn();
    const inventory: AddressInventory = {
      tailnet: [
        {
          address: "100.100.10.20",
          family: "IPv4",
          scope: "tailnet",
          provenance: "tailscale_device_api",
          reliability: "api_reported",
        },
      ],
      observed: [
        {
          address: "8.8.8.8",
          family: "IPv4",
          classification: "public",
          ports: [41641, 41642],
          first_observed_at: "2026-07-21T10:00:00Z",
          last_observed_at: "2026-07-21T11:00:00Z",
          observer_count: 2,
          observers: [
            { id: "node-1", name: "laptop.example.ts.net" },
            { id: "node-2", name: "server.example.ts.net" },
          ],
          reported_bytes: 2048,
          provenance: "network_flow_logs_physical",
          reliability: "client_reported_unverified",
        },
      ],
      status: "available",
      capability_status: "available",
      requested_hours: 168,
      retention_days: 30,
      truncated: false,
      notice: "Client-reported candidates, not authoritative addresses.",
    };

    render(
      <AddressInventoryView
        inventory={inventory}
        fallbackAddresses={[]}
        addressHours={168}
        setAddressHours={setAddressHours}
      />,
    );

    expect(screen.getByText("Tailnet addresses")).toBeTruthy();
    expect(screen.getByText("Observed physical endpoints")).toBeTruthy();
    expect(screen.getByText("8.8.8.8")).toBeTruthy();
    expect(screen.getByText("Physical flow logs · unverified")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Copy observed endpoint 8.8.8.8" }));
    expect(writeText).toHaveBeenCalledWith("8.8.8.8");

    fireEvent.change(screen.getByLabelText("Observed endpoint range"), {
      target: { value: "720" },
    });
    expect(setAddressHours).toHaveBeenCalledWith(720);
  });

  it.each([
    ["capability_unavailable", "Flow logs unavailable"],
    ["retention_limited", "Range exceeds retention"],
    ["no_observations", "No endpoint candidates observed"],
  ] as const)("renders the %s address state", (status, expected) => {
    render(
      <AddressInventoryView
        inventory={{
          tailnet: [],
          observed: [],
          status,
          capability_status: "feature_disabled",
          requested_hours: 168,
          retention_days: 7,
          truncated: false,
          notice: "Unverified observations.",
        }}
        fallbackAddresses={[]}
        addressHours={168}
        setAddressHours={vi.fn()}
      />,
    );

    expect(screen.getByText(expected)).toBeTruthy();
  });
});
