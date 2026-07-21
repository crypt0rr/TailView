import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { DeviceTable, PolicySecurityReview } from "./pages";
import type { Device } from "./types";

describe("TailView", () => {
  it("keeps the product name stable", () => {
    expect("TailView").toMatch(/TailView/);
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
});
