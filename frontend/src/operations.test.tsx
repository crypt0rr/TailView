import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as apiModule from "./api";
import { Operations } from "./pages";

const summary = {
  status: "degraded",
  generated_at: "2026-07-22T12:00:00Z",
  scheduler: { name: "scheduler", category: "runtime", interval_seconds: 30, last_status: "success", last_started_at: null, last_finished_at: null, last_success_at: "2026-07-22T12:00:00Z", heartbeat_at: "2026-07-22T12:00:00Z", consecutive_failures: 0, overdue: false, unhealthy: false },
  jobs: [
    { name: "scheduler", category: "runtime", interval_seconds: 30, last_status: "success", last_started_at: null, last_finished_at: null, last_success_at: "2026-07-22T12:00:00Z", heartbeat_at: "2026-07-22T12:00:00Z", consecutive_failures: 0, overdue: false, unhealthy: false },
    { name: "network-reports", category: "reporting", interval_seconds: 30, last_status: "failed", last_started_at: "2026-07-22T11:59:00Z", last_finished_at: "2026-07-22T11:59:02Z", last_success_at: "2026-07-22T11:00:00Z", heartbeat_at: "2026-07-22T11:59:02Z", consecutive_failures: 2, overdue: false, unhealthy: true },
  ],
  degraded_jobs: 1,
  queues: { reports: { depth: 2, oldest_age_seconds: 900, warning: true }, notifications: { depth: 0, oldest_age_seconds: 0, warning: false } },
  backup: { configured: true, latest_verified_at: "2026-07-22T01:00:00Z", age_seconds: 39600, max_age_hours: 48, stale: false },
  latest_cleanup: null,
};

function renderOperations(route = "/operations") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[route]}><Operations /></MemoryRouter></QueryClientProvider>);
}

afterEach(() => vi.restoreAllMocks());

describe("operations center", () => {
  it("shows degraded runtime, queues, retention protection, and recovery evidence", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/operations/summary") return summary as never;
      if (path === "/operations/storage") return { database_bytes: 1024, relations: [], counts: {}, host_capacity_reported: false } as never;
      if (path === "/operations/retention") return { as_of: summary.generated_at, eligible: { raw_flows: 0 }, raw_flow_cleanup_blocked: true, aggregate_coverage: {}, retention_days: { raw_flows: 7 } } as never;
      if (path === "/operations/backups") return { items: [{ id: "backup-1", filename: "tailview.dump", content_hash: "a".repeat(64), size: 1024, status: "success", postgres_version: "17.5", migration_revision: "0014_v1_completion", checks: { restore: true }, error_class: "", verified_at: summary.backup.latest_verified_at }] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderOperations();
    expect(await screen.findByText("Degraded jobs")).toBeTruthy();
    expect(screen.getByText("network-reports")).toBeTruthy();
    expect(screen.getByText(/Raw-flow cleanup is blocked/)).toBeTruthy();
    expect(screen.getByText("Verification recorded")).toBeTruthy();
  });

  it("restores job filters from the URL and links domain references", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/operations/summary") return summary as never;
      if (String(path).startsWith("/operations/jobs?")) return { items: [{ id: "run-1", name: "network-reports", category: "reporting", interval_seconds: 30, status: "failed", started_at: summary.generated_at, finished_at: summary.generated_at, duration_ms: 2000, processed: 0, error_class: "WorkerError", details: {}, sync_job_id: null, report_run_id: "report-1" }], next_cursor: null } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderOperations("/operations?tab=jobs&job=network-reports&status=failed");
    expect(await screen.findByText("WorkerError")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Report" }).getAttribute("href")).toBe("/reports?report=report-1");
    await waitFor(() => expect(request).toHaveBeenCalledWith(expect.stringContaining("job=network-reports")));
  });

  it("requires confirmation before a manual retention cleanup", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path, options) => {
      if (path === "/operations/summary") return summary as never;
      if (path === "/operations/retention") return { as_of: summary.generated_at, eligible: { raw_payloads: 12 }, raw_flow_cleanup_blocked: false, aggregate_coverage: {}, retention_days: { raw_payloads: 7 } } as never;
      if (path === "/operations/cleanup/run" && options?.method === "POST") return { deleted: { raw_payloads: 12 } } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderOperations("/operations?tab=retention");
    fireEvent.click(await screen.findByRole("button", { name: "Run cleanup" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith("/operations/cleanup/run", { method: "POST" }));
  });

  it("keeps storage cards independently sized and relation tables contained", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/operations/summary") return summary as never;
      if (path === "/operations/storage") return {
        database_bytes: 4096,
        counts: { raw_flows: 1_841_626, findings: 14 },
        relations: [{ name: "flows", total_bytes: 4096, table_bytes: 3072, index_bytes: 1024 }],
        host_capacity_reported: false,
      } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderOperations("/operations?tab=storage");

    const managedHeading = await screen.findByRole("heading", { name: "Managed records" });
    const relationsHeading = screen.getByRole("heading", { name: "PostgreSQL relations" });
    expect(managedHeading.closest(".operations-storage-grid")).toBeTruthy();
    expect(managedHeading.closest(".operations-storage-card")).toBeTruthy();
    expect(relationsHeading.closest(".operations-storage-card")?.querySelector(".table-scroll"))
      .toBeTruthy();
  });
});
