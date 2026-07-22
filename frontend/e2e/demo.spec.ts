import { expect, test } from "@playwright/test";
import axe from "axe-core";

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
