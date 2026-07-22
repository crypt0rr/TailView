import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(resolve(process.cwd(), "src/styles.css"), "utf8");

function luminance(hex: string) {
  const value = hex.slice(1);
  const channels = [0, 2, 4].map((offset) => Number.parseInt(value.slice(offset, offset + 2), 16) / 255);
  const [red, green, blue] = channels.map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * red! + 0.7152 * green! + 0.0722 * blue!;
}

function contrast(foreground: string, background: string) {
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

function palette(selector: string) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const block = stylesheet.match(new RegExp(`${escaped}\\s*\\{([^}]+)\\}`))?.[1] ?? "";
  return Object.fromEntries(
    [...block.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?)/g)].map(
      (match) => [
        match[1],
        match[2]!.length === 4
          ? `#${[...match[2]!.slice(1)].map((value) => value.repeat(2)).join("")}`
          : match[2],
      ],
    ),
  );
}

describe("release palette contrast", () => {
  it.each([
    [":root", "light"],
    [':root[data-theme="dark"]', "dark"],
  ])("keeps %s text, muted text, and accent controls readable", (selector) => {
    const colors = palette(selector);
    expect(contrast(colors.text!, colors.bg!)).toBeGreaterThanOrEqual(7);
    expect(contrast(colors.muted!, colors.surface!)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(colors.accent!, colors.surface!)).toBeGreaterThanOrEqual(4.5);
  });
});
