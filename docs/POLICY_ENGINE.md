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

