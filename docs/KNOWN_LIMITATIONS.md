# Known limitations

- Device history starts when TailView first runs migration `0014_v1_completion`; it is not backfilled.
- Access explanations evaluate the current synchronized policy and posture only. Historical flows do
  not prove that the same policy or posture applied at observation time.
- Flow logs contain successful, client-reported windows and can overlap between peers. They do not
  contain denied attempts, packet contents, DNS queries, URLs, or direct user activity.
- Local telemetry is optional, passive, and collector-specific. TailView does not run pings, scans,
  geolocation, or reverse DNS and does not infer tailnet-wide connectivity.
- Unknown upstream fields and policy constructs remain explicit unsupported or incomplete data.
- OIDC, SCIM, and active collector diagnostics are backlog items, not v1 behavior.
