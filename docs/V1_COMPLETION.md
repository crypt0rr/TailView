# V1 device workspaces and accessibility

## Local metadata

Administrators can edit TailView-local presentation fields in the device drawer. Display names,
functional groups, custom roles, environment, location, criticality, icons, and default-map
visibility never modify Tailscale or replace synchronized source facts. Updates use optimistic
revisions and create local security and device-history events.

## Device access and history

The Access tab joins current policy relationships to observations from the selected range. Current
policy and current posture are not historical evidence. Traffic without a current matching allow is
labelled `historical_without_current_allow`, never a bypass. Device history begins after migration
`0014_v1_completion`; earlier changes cannot be reconstructed. History defaults to 365 days.

## Local telemetry

The optional collector submits signed `tailscale status --json` and `tailscale netcheck` snapshots.
TailView normalizes collector identity, connectivity availability, mapping behavior, preferred DERP,
endpoints, and DERP latency. Normalized snapshots are visible to signed-in users; redacted raw
diagnostics remain backend-only and follow raw-payload retention. Data describes one collector at one
time. It is not live, tailnet-wide, geolocated, scanned, or actively probed.

## Accessibility

Topology provides graph and table presentations over the same filtered nodes and visible edge
layers. Drawers support keyboard closing and initial focus, controls have accessible names, status
changes use live regions, and reduced-motion preferences disable nonessential animation.
