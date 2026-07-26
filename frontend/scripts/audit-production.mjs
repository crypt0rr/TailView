import { spawnSync } from "node:child_process";

const allowedAdvisories = new Map([
  [
    "https://github.com/advisories/GHSA-qwww-vcr4-c8h2",
    "TailView is a client-rendered SPA and does not use React Server Components or actions.",
  ],
]);

const result = spawnSync("npm", ["audit", "--omit=dev", "--json"], {
  encoding: "utf8",
  shell: false,
});

if (result.error || !result.stdout) {
  console.error(result.error?.message || result.stderr || "npm audit returned no report");
  process.exit(1);
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  console.error("npm audit returned invalid JSON");
  process.exit(1);
}

const blocking = new Map();
const observedAllowed = new Set();
for (const vulnerability of Object.values(report.vulnerabilities || {})) {
  for (const advisory of vulnerability.via || []) {
    if (typeof advisory !== "object" || !["high", "critical"].includes(advisory.severity)) {
      continue;
    }
    if (allowedAdvisories.has(advisory.url)) {
      observedAllowed.add(advisory.url);
    } else {
      blocking.set(advisory.url || advisory.title, advisory);
    }
  }
}

for (const [url, advisory] of blocking) {
  console.error(`${advisory.severity}: ${advisory.title} (${url})`);
}
if (blocking.size) {
  process.exit(1);
}
if (result.status !== 0 && !observedAllowed.size) {
  console.error(result.stderr || "npm audit failed without an allowed advisory");
  process.exit(1);
}
for (const url of observedAllowed) {
  console.warn(`Allowed advisory: ${url} — ${allowedAdvisories.get(url)}`);
}
console.log("No unapproved high or critical production advisories found.");
