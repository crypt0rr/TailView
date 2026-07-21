import { useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { Shell } from "./App";
import { api } from "./api";
import {
  AddressInventoryView,
  DeviceTrafficRanking,
  DeviceTable,
  dnsConfigurationEntries,
  PolicySecurityReview,
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
          user={{ id: "admin", username: "admin", role: "administrator" }}
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
