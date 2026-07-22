import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as apiModule from "./api";
import { Reports } from "./pages";
import type { NetworkReport, SavedViewRecord } from "./types";

const report: NetworkReport = {
  id: "report-1",
  title: "Weekly gateway traffic",
  status: "completed",
  schedule_id: null,
  saved_view_id: "view-1",
  saved_view_revision: 2,
  range_start: "2026-07-15T12:00:00Z",
  range_end: "2026-07-22T12:00:00Z",
  filters: { source: "gateway" },
  coverage: { complete: true, granularity: "hourly" },
  error: "",
  created_at: "2026-07-22T12:00:00Z",
  started_at: "2026-07-22T12:00:01Z",
  completed_at: "2026-07-22T12:00:03Z",
  artifacts: [
    { format: "pdf", content_type: "application/pdf", filename: "weekly.pdf", content_hash: "a".repeat(64), size: 2048 },
    { format: "json", content_type: "application/json", filename: "weekly.json", content_hash: "b".repeat(64), size: 1024 },
    { format: "csv", content_type: "application/zip", filename: "weekly-csv.zip", content_hash: "c".repeat(64), size: 4096 },
  ],
};

const savedView: SavedViewRecord = {
  id: "view-1", name: "Gateway", description: "", page: "flows", visibility: "shared",
  state: { range: "7d", category: "", source: "gateway", destination: "", protocol: "", port: "", resolution: "all", ranking_limit: 10 },
  schema_version: 1, revision: 2, created_at: "2026-07-22T00:00:00Z", updated_at: "2026-07-22T00:00:00Z",
  owner: { id: "admin", username: "admin", display_name: "Administrator" },
  can_edit: true, is_owner: true, is_default: false, compatible: true,
};

function renderReports(role: "administrator" | "viewer") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter><Reports user={{ role }} /></MemoryRouter></QueryClientProvider>);
}

afterEach(() => vi.restoreAllMocks());

describe("network reports", () => {
  it("lets Viewers inspect completed reports and authenticated formats", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/reports/summary") return { counts: { completed: 1 }, latest: report } as never;
      if (String(path).startsWith("/reports?")) return { items: [report], next_cursor: null } as never;
      if (path === "/reports/report-1") return { ...report, snapshot: {
        notice: "Client-reported traffic.",
        traffic: { totals: { reported_bytes: 5000, reported_packets: 50, record_count: 2 }, series: [], top_devices: [] },
      } } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderReports("viewer");
    expect(await screen.findByText("Weekly gateway traffic")).toBeTruthy();
    expect(screen.queryByText("Queue report")).toBeNull();
    fireEvent.click(screen.getByText("Weekly gateway traffic"));
    const pdf = await screen.findByRole("link", { name: /PDF/ });
    expect(pdf.getAttribute("href")).toBe("/api/v1/reports/report-1/download?format=pdf");
  });

  it("queues an Administrator report from a compatible saved Flow view", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path, options) => {
      if (path === "/reports/summary") return { counts: {}, latest: null } as never;
      if (String(path).startsWith("/reports?")) return { items: [], next_cursor: null } as never;
      if (path === "/report-schedules") return { items: [] } as never;
      if (path === "/saved-views?page=flows") return { items: [savedView] } as never;
      if (path === "/reports/generate" && options?.method === "POST") return { ...report, status: "queued" } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderReports("administrator");
    fireEvent.change(await screen.findByLabelText("Report saved Flow view"), { target: { value: "view-1" } });
    fireEvent.click(screen.getByRole("button", { name: /Queue report/ }));
    await waitFor(() => expect(request).toHaveBeenCalledWith(
      "/reports/generate",
      expect.objectContaining({ method: "POST" }),
    ));
  });
});
