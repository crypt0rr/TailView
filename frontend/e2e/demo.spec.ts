import { expect, test } from "@playwright/test";
import axe from "axe-core";

async function authenticatedMutation(
  page: import("@playwright/test").Page,
  path: string,
  method: "POST" | "PUT" | "PATCH" | "DELETE",
  body?: unknown,
) {
  return page.evaluate(async ({ path, method, body }) => {
    const csrf = document.cookie
      .split("; ")
      .find((item) => item.startsWith("tailview_csrf="))
      ?.split("=")[1] ?? "";
    const response = await fetch(`/api/v1${path}`, {
      method,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": decodeURIComponent(csrf),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: response.status, body: await response.text() };
  }, { path, method, body });
}

async function authenticate(page: import("@playwright/test").Page) {
  const username = process.env.E2E_USERNAME ?? "smoke-admin";
  const password = process.env.E2E_PASSWORD ?? "temporary-smoke-password-2026";
  await page.goto("/");

  const setupHeading = page.getByRole("heading", { name: "Create your administrator" });
  const loginHeading = page.getByRole("heading", { name: "Welcome back" });
  await expect(setupHeading.or(loginHeading)).toBeVisible();
  if (await setupHeading.isVisible()) {
    await page.getByLabel("Setup token").fill(process.env.E2E_SETUP_TOKEN ?? "");
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: /Create administrator/ }).click();
  } else {
    await page.getByLabel("Username").fill(username);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: /Sign in/ }).click();
  }

  await expect(page.getByRole("heading", { name: "Tailnet overview" })).toBeVisible();
}

test("setup or login reaches the demo dashboard and topology", async ({ page }) => {
  await authenticate(page);

  await expect(page.getByText("Total nodes")).toBeVisible();
  await page.getByLabel("Global time range").selectOption("7d");
  await expect(page).toHaveURL(/range=7d/);
  await page.getByRole("button", { name: "Flows" }).click();
  await expect(page.getByRole("heading", { name: "Flow explorer" })).toBeVisible();
  await page.getByRole("button", { name: /More filters/ }).click();
  await page.getByLabel("Source").fill("alice");
  await expect(page).toHaveURL(/source=alice/);
  await page.getByRole("button", { name: "Topology" }).click();
  await expect(page.getByRole("heading", { name: "Topology" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Observed" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Permitted" })).toBeVisible();
});

test("demo reporting exposes trends, immutable evidence, and schedules", async ({ page }) => {
  await authenticate(page);
  await page.getByRole("button", { name: "Reports" }).click();
  await expect(page.getByRole("heading", { name: "Reports" })).toBeVisible();
  await expect(page.getByText("Latest report trend")).toBeVisible();
  await page.getByRole("button", { name: /Open report/ }).click();
  await expect(page.getByLabel("Report details")).toBeVisible();
  await expect(page.getByRole("link", { name: /PDF/ })).toBeVisible();
  await expect(page.getByText("Reproducibility")).toBeVisible();
  await page.getByLabel("Close report").click();
  await page.getByRole("tab", { name: "Schedules" }).click();
  await expect(page.getByText("Weekly production usage")).toBeVisible();
  await expect(page.getByText("Recent runs")).toBeVisible();
});

test("device workspaces expose metadata, table topology, history, and telemetry", async ({ page }) => {
  await authenticate(page);
  await page.getByRole("button", { name: "Topology" }).click();
  await page.getByRole("button", { name: "Table" }).click();
  await expect(page.getByLabel("Topology table alternative")).toBeVisible();
  await page.getByRole("button", { name: "Production API" }).click();
  await expect(page.getByText("TailView local metadata")).toBeVisible();
  await page.getByRole("button", { name: "history" }).click();
  await expect(page.getByText(/history begins after/i)).toBeVisible();
  await page.getByLabel("Close device details").click();
  await page.getByRole("button", { name: "Telemetry" }).click();
  await expect(page.getByRole("heading", { name: "Telemetry" })).toBeVisible();
  await expect(page.getByText(/never a tailnet-wide live view/i)).toBeVisible();
});

test("Administrator release-critical mutations remain functional", async ({ page }) => {
  await authenticate(page);

  const devices = await page.evaluate(async () => {
    const response = await fetch("/api/v1/devices?limit=1", { credentials: "include" });
    return response.json() as Promise<{ items: Array<{ id: string }> }>;
  });
  const deviceId = devices.items[0]?.id;
  expect(deviceId).toBeTruthy();
  const metadata = await authenticatedMutation(
    page,
    `/devices/${encodeURIComponent(deviceId!)}/metadata`,
    "PUT",
    {
      display_name: "RC verified device",
      description: "Updated by the release acceptance suite",
      functional_groups: ["release-validation"],
      custom_roles: [],
      default_map_visible: true,
    },
  );
  expect(metadata.status).toBe(200);

  const createdView = await authenticatedMutation(page, "/saved-views", "POST", {
    name: "RC acceptance flow view",
    description: "Created by Playwright",
    page: "flows",
    visibility: "private",
    schema_version: 1,
    state: {
      range: "24h",
      category: "",
      source: "",
      destination: "",
      protocol: "",
      port: "",
      resolution: "all",
      ranking_limit: 10,
    },
  });
  expect(createdView.status).toBe(200);
  const view = JSON.parse(createdView.body) as { id: string; revision: number };
  const updatedView = await authenticatedMutation(page, `/saved-views/${view.id}`, "PUT", {
    name: "RC acceptance flow view",
    description: "Optimistic update verified",
    visibility: "shared",
    schema_version: 1,
    expected_revision: view.revision,
    state: {
      range: "7d",
      category: "virtual",
      source: "",
      destination: "",
      protocol: "",
      port: "",
      resolution: "all",
      ranking_limit: 10,
    },
  });
  expect(updatedView.status).toBe(200);
  const queuedReport = await authenticatedMutation(page, "/reports/generate", "POST", {
    saved_view_id: view.id,
    range: "7d",
    title: "RC acceptance report",
  });
  expect(queuedReport.status).toBe(202);

  const acknowledged = await authenticatedMutation(
    page,
    "/findings/demo-finding-open/acknowledge",
    "POST",
    { reason: "Release acceptance" },
  );
  expect(acknowledged.status).toBe(200);
  const reopened = await authenticatedMutation(
    page,
    "/findings/demo-finding-open/reopen",
    "POST",
    { reason: "Restore demo fixture state" },
  );
  expect(reopened.status).toBe(200);

  const cleanupPreview = await authenticatedMutation(page, "/operations/cleanup/preview", "POST");
  expect(cleanupPreview.status).toBe(200);
  const sessions = await authenticatedMutation(page, "/auth/sessions/revoke-others", "POST");
  expect(sessions.status).toBe(200);
  const deletedView = await authenticatedMutation(page, `/saved-views/${view.id}`, "DELETE");
  expect(deletedView.status).toBe(200);
});

test("Viewer onboarding preserves read access and blocks administrative surfaces", async ({ page }) => {
  await authenticate(page);
  const created = await authenticatedMutation(page, "/settings/app-users", "POST", {
    username: "e2e-viewer",
    display_name: "Acceptance Viewer",
    role: "viewer",
    temporary_password: "temporary-viewer-password-2026",
  });
  expect(created.status).toBe(200);

  await page.getByTitle("Log out").click();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await page.getByLabel("Username").fill("e2e-viewer");
  await page.getByLabel("Password").fill("temporary-viewer-password-2026");
  await page.getByRole("button", { name: /Sign in/ }).click();
  await expect(page.getByRole("heading", { name: "Choose a permanent password" })).toBeVisible();
  await page.getByLabel("Temporary password").fill("temporary-viewer-password-2026");
  await page.getByLabel("New password").fill("permanent-viewer-password-2026");
  await page.getByRole("button", { name: /Update password/ }).click();
  await expect(page.getByRole("heading", { name: "Tailnet overview" })).toBeVisible();

  await expect(page.getByRole("button", { name: "Flows" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reports" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Operations" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Settings" })).toHaveCount(0);
  await page.goto("/operations");
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Tailnet overview" })).toBeVisible();

  const devices = await page.evaluate(async () => {
    const response = await fetch("/api/v1/devices?limit=1", { credentials: "include" });
    return response.json() as Promise<{ items: Array<{ id: string }> }>;
  });
  expect(devices.items.length).toBeGreaterThan(0);
  const denied = await authenticatedMutation(
    page,
    `/devices/${encodeURIComponent(devices.items[0]!.id)}/metadata`,
    "PUT",
    {},
  );
  expect(denied.status).toBe(403);
});

test("mandatory MFA policy routes an unenrolled Viewer into protected onboarding", async ({ page }) => {
  await authenticate(page);
  const created = await authenticatedMutation(page, "/settings/app-users", "POST", {
    username: "e2e-mfa-viewer",
    display_name: "MFA Acceptance Viewer",
    role: "viewer",
    temporary_password: "temporary-mfa-password-2026",
  });
  expect(created.status).toBe(200);
  const policy = await authenticatedMutation(page, "/settings/auth-policy", "PUT", {
    required_roles: ["viewer"],
  });
  expect(policy.status).toBe(200);

  await page.getByTitle("Log out").click();
  await page.getByLabel("Username").fill("e2e-mfa-viewer");
  await page.getByLabel("Password").fill("temporary-mfa-password-2026");
  await page.getByRole("button", { name: /Sign in/ }).click();
  await expect(page.getByRole("heading", { name: "Choose a permanent password" })).toBeVisible();
  await page.getByLabel("Temporary password").fill("temporary-mfa-password-2026");
  await page.getByLabel("New password").fill("permanent-mfa-password-2026");
  await page.getByRole("button", { name: /Update password/ }).click();
  await expect(page.getByRole("heading", { name: "Protect your account" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Start MFA enrollment/ })).toBeVisible();
  await page.goto("/flows");
  await expect(page.getByRole("heading", { name: "Protect your account" })).toBeVisible();
});

test("primary workspaces have no serious automated accessibility violations", async ({ page }) => {
  await authenticate(page);
  const routes = [
    "/", "/topology?mode=table", "/flows", "/devices", "/users", "/groups",
    "/routes", "/services", "/exit-nodes", "/subnet-routers", "/tags", "/policy",
    "/security/posture", "/findings", "/security/governance", "/audit", "/sync",
    "/dns", "/telemetry", "/reports", "/operations", "/settings",
    "/settings/access", "/security/account",
  ];
  for (const route of routes) {
    await page.goto(route);
    await expect(page.locator("main h1").first()).toBeVisible();
    // Playwright's isolated evaluation is intentionally used so production CSP
    // remains strict and does not need an unsafe-inline exception for testing.
    await page.evaluate(axe.source);
    const violations = await page.evaluate(async () => {
      const engine = (window as unknown as {
        axe: { run: (options: object) => Promise<{ violations: Array<{ id: string; impact: string | null }> }> };
      }).axe;
      const result = await engine.run({
        runOnly: { type: "tag", values: ["wcag2a", "wcag2aa"] },
        // axe cannot reliably resolve this UI's color-mix/backdrop composition;
        // palette contrast is covered separately by token-level visual checks.
        rules: { "color-contrast": { enabled: false } },
      });
      return result.violations.filter((violation) => violation.impact === "critical" || violation.impact === "serious");
    });
    expect(violations, `Accessibility violations on ${route}`).toEqual([]);
  }
});

test("release-critical surfaces retain their light and dark appearance", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => { localStorage.theme = "dark"; });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page).toHaveScreenshot("authentication-dark.png", { animations: "disabled", maxDiffPixelRatio: 0.001 });
  await page.evaluate(() => { localStorage.theme = "light"; });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Welcome back" })).toBeVisible();
  await expect(page).toHaveScreenshot("authentication-light.png", { animations: "disabled", maxDiffPixelRatio: 0.001 });

  await authenticate(page);
  for (const theme of ["light", "dark"] as const) {
    await page.evaluate((value) => { localStorage.theme = value; }, theme);
    await page.goto("/operations");
    await expect(page.getByRole("heading", { name: "Operations" })).toBeVisible();
    await expect(page).toHaveScreenshot(`operations-${theme}.png`, { animations: "disabled", maxDiffPixelRatio: 0.001 });
    await page.goto("/settings/access");
    await expect(page.getByRole("heading", { name: "TailView access" })).toBeVisible();
    await expect(page).toHaveScreenshot(`tailview-access-${theme}.png`, { animations: "disabled", maxDiffPixelRatio: 0.001 });
  }
});
