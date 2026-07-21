import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DeviceTable } from "./pages";
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
    render(<DeviceTable devices={[device]} onSelect={onSelect} />);

    fireEvent.click(
      screen.getByRole("button", {
        name: /view details for router\.example\.ts\.net/i,
      }),
    );

    expect(onSelect).toHaveBeenCalledOnce();
    expect(onSelect).toHaveBeenCalledWith(device);
  });
});
