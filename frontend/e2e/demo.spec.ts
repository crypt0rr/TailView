import { expect, test } from "@playwright/test";

test("setup or login reaches the demo dashboard and topology", async ({ page }) => {
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
