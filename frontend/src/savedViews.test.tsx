import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as apiModule from "./api";
import { SavedViews } from "./savedViews";
import type { SavedViewRecord } from "./types";

const builtIn = { range: "24h", category: "", source: "" };
const savedState = { range: "7d", category: "physical", source: "gateway" };

function record(overrides: Partial<SavedViewRecord> = {}): SavedViewRecord {
  return {
    id: "view-1",
    name: "Gateway traffic",
    description: "Physical traffic from the gateway",
    page: "flows",
    visibility: "shared",
    state: savedState,
    schema_version: 1,
    revision: 2,
    created_at: "2026-07-22T10:00:00Z",
    updated_at: "2026-07-22T10:00:00Z",
    owner: { id: "owner-1", username: "alice", display_name: "Alice" },
    can_edit: false,
    is_owner: false,
    is_default: false,
    compatible: true,
    ...overrides,
  };
}

function renderToolbar(
  route: string,
  apply = vi.fn(),
  hasExplicitState = false,
  current = savedState,
) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <SavedViews
          page="flows"
          state={current}
          builtIn={builtIn}
          apply={apply}
          hasExplicitState={hasExplicitState}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return apply;
}

afterEach(() => vi.restoreAllMocks());

describe("SavedViews", () => {
  it("applies authenticated share links and can return to the built-in state", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/saved-views?page=flows") return { items: [record()] } as never;
      if (path === "/saved-views/defaults") return { items: [] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const apply = renderToolbar("/flows?view=view-1");

    await waitFor(() => expect(apply).toHaveBeenCalledWith(savedState));
    fireEvent.change(screen.getByLabelText("Saved view"), { target: { value: "builtin" } });
    expect(apply).toHaveBeenLastCalledWith(builtIn);
  });

  it("applies a personal default only without explicit view-controlled parameters", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/saved-views?page=flows") return { items: [record({ is_default: true })] } as never;
      if (path === "/saved-views/defaults") return { items: [{ page: "flows", view: record({ is_default: true }) }] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    const apply = renderToolbar("/flows");
    await waitFor(() => expect(apply).toHaveBeenCalledWith(savedState));
  });

  it("shows a safe unavailable state for inaccessible private links", async () => {
    vi.spyOn(apiModule, "request").mockImplementation(async (path) => {
      if (path === "/saved-views?page=flows") return { items: [] } as never;
      if (path === "/saved-views/defaults") return { items: [] } as never;
      throw new Error(`Unexpected request ${path}`);
    });
    renderToolbar("/flows?view=private-view");
    expect(await screen.findByText("Saved view not found or unavailable.")).toBeTruthy();
  });

  it("saves a clone when the loaded shared view is read-only", async () => {
    const request = vi.spyOn(apiModule, "request").mockImplementation(async (path, options) => {
      if (path === "/saved-views?page=flows") return { items: [record()] } as never;
      if (path === "/saved-views/defaults") return { items: [] } as never;
      if (path === "/saved-views" && options?.method === "POST") {
        return record({ id: "copy-1", name: "My gateway" }) as never;
      }
      throw new Error(`Unexpected request ${path}`);
    });
    renderToolbar("/flows?view=view-1");
    fireEvent.click(await screen.findByRole("button", { name: "Save as new" }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "My gateway" } });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(request).toHaveBeenCalledWith(
      "/saved-views",
      expect.objectContaining({ method: "POST" }),
    ));
  });
});
