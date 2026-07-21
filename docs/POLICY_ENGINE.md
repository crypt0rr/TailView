# Policy engine

TailView parses the current HuJSON policy read-only and evaluates additive allow relationships. It does not modify policy and does not create explicit deny edges. “No matching allow rule” is not evidence that a connection attempt occurred or was blocked.

## Processing

1. Store the exact policy and content hash.
2. Parse HuJSON comments/trailing commas into a normalized representation while retaining the original source.
3. Normalize Grants, legacy ACLs, groups, tags, hosts, IP sets, SSH, postures, auto-approvers, tests, node attributes, and known autogroups.
4. Expand selectors against the synchronized device/user snapshot.
5. Produce source, destination, protocol/port, matching rule, expansion path, posture references, and an evaluation status.
6. Compare current permissions with observations in the selected historical range.

Statuses are `fully_evaluated`, `partially_evaluated`, `unsupported_construct`, and `unresolved_selector`. Unknown autogroups, missing posture attributes, app-specific capability semantics, ambiguous routes, and future syntax are never guessed. Application capabilities are displayed as source policy unless their official semantics are explicitly supported.

Historical observations without a current allow are labelled: “Observed historically; no matching allow rule exists in the current policy. The policy may have changed after this flow occurred.” This is never automatically described as a policy bypass.

## Duplicate review

The Policy Explorer can produce a conservative duplicate review. It recursively removes only canonically identical array entries inside documented policy sections. Unsupported top-level sections are copied without interpretation, and TailView never submits or applies the generated candidate.

The candidate is regenerated as strict JSON, which is valid HuJSON, but original comments and formatting are not retained. It must therefore be treated as a review artifact and validated with Tailscale before any manual replacement. TailView does not combine overlapping selectors, reorder rules, infer semantic equivalence, or perform other speculative optimizations.
