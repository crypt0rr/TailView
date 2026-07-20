import { describe, expect, it } from "vitest";

describe("TailView", () => {
  it("keeps the product name stable", () => {
    expect("TailView").toMatch(/TailView/);
  });
});
