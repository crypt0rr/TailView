export interface Device {
  id: string;
  name: string;
  source_name: string;
  hostname: string;
  os: string;
  version: string;
  owner_id: string | null;
  owner_display_name: string | null;
  owner_login_name: string | null;
  online: boolean | null;
  authorized: boolean | null;
  active?: boolean;
  stale?: boolean;
  last_seen: string | null;
  created: string | null;
  key_expiry: string | null;
  key_expiry_disabled: boolean | null;
  addresses: string[];
  tags: string[];
  advertised_routes: string[];
  approved_routes: string[];
  roles: string[];
  primary_role: string;
  source: string;
  inventory_details?: Record<string, unknown>;
  metadata: null | {
    description?: string;
    function?: string;
    environment?: string;
    location?: string;
    criticality?: string;
    icon?: string;
    hidden: boolean;
  };
  address_inventory?: AddressInventory;
  posture?: DevicePosture;
  connectivity?: DeviceConnectivity;
}

export interface AppSession {
  id: string;
  user_id: string;
  username?: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string | null;
  initial_ip: string;
  last_ip: string;
  user_agent: string;
  restricted: boolean;
  current: boolean;
}

export interface TailViewAccount {
  id: string;
  username: string;
  display_name: string;
  role: "administrator" | "viewer";
  active: boolean;
  must_change_password: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  password_changed_at: string | null;
  deactivated_at: string | null;
  created_at: string;
  session_count: number;
}

export interface SavedViewRecord {
  id: string;
  name: string;
  description: string;
  page: string;
  visibility: "private" | "shared";
  state: Record<string, unknown>;
  schema_version: number;
  revision: number;
  created_at: string;
  updated_at: string;
  owner: { id: string; username: string; display_name: string };
  can_edit: boolean;
  is_owner: boolean;
  is_default: boolean;
  compatible: boolean;
}

export interface OperationalJobState {
  name: string;
  category: string;
  interval_seconds: number;
  last_status: string;
  last_started_at: string | null;
  last_finished_at: string | null;
  last_success_at: string | null;
  heartbeat_at: string | null;
  consecutive_failures: number;
  overdue: boolean;
  unhealthy: boolean;
}

export interface OperationsSummary {
  status: "healthy" | "degraded";
  generated_at: string;
  scheduler: OperationalJobState | null;
  jobs: OperationalJobState[];
  degraded_jobs: number;
  queues: Record<string, { depth: number; oldest_age_seconds: number; warning: boolean }>;
  backup: { configured: boolean; latest_verified_at: string | null; age_seconds: number | null; max_age_hours: number; stale: boolean };
  latest_cleanup: null | { status: string; started_at: string; finished_at: string | null; deleted: Record<string, number> };
}

export interface OperationalJobRun {
  id: string;
  name: string;
  category: string;
  interval_seconds: number;
  status: string;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  processed: number;
  error_class: string;
  details: Record<string, unknown>;
  sync_job_id: string | null;
  report_run_id: string | null;
}

export interface OperationsStorage {
  database_bytes: number | null;
  relations: Array<{ name: string; total_bytes: number; table_bytes: number; index_bytes: number }>;
  counts: Record<string, number>;
  host_capacity_reported: boolean;
}

export interface OperationsRetention {
  as_of: string;
  eligible: Record<string, number>;
  raw_flow_cleanup_blocked: boolean;
  aggregate_coverage: Record<string, { start: string | null; end: string | null; last_success: string | null; last_error: string }>;
  retention_days: Record<string, number>;
}

export interface BackupVerification {
  id: string;
  filename: string;
  content_hash: string;
  size: number;
  status: string;
  postgres_version: string;
  migration_revision: string;
  checks: Record<string, boolean>;
  error_class: string;
  verified_at: string;
}
export interface PostureAttribute {
  key: string;
  namespace: string;
  value: string | number | boolean;
  value_type: "string" | "number" | "boolean";
  expiry: string | null;
  expiry_state: "active" | "expiring" | "expired";
  synced_at: string;
  provenance: string;
}
export interface PostureEvaluation {
  name: string;
  status:
    | "pass"
    | "fail"
    | "incomplete_data"
    | "unsupported_condition"
    | "not_applicable";
  assertions: Array<{
    condition: string;
    key?: string;
    operator?: string;
    expected?: unknown;
    actual: unknown;
    status: string;
    source_lines?: { start: number | null; end: number | null };
  }>;
  policy_uses: Array<{
    policy_path: string;
    source_lines: { start: number | null; end: number | null };
    affected_destinations: string[];
  }>;
}
export interface DevicePosture {
  status: "pass" | "fail" | "incomplete_data" | "not_applicable";
  evidence_status: string;
  stale: boolean;
  checked_at: string | null;
  last_success: string | null;
  attributes: PostureAttribute[];
  evaluations: PostureEvaluation[];
  rule_impacts: Array<{
    policy_path: string;
    status: string;
    required_postures: string[];
    semantics: "any_required_posture_may_pass";
    affected_destinations: string[];
  }>;
  notice: string;
}
export interface DeviceConnectivity {
  status: "available" | "not_reported";
  mapping_varies_by_dest_ip?: boolean | null;
  derp?: string | null;
  endpoints?: unknown[];
  latency?: Record<string, unknown>;
  client_supports?: Record<string, unknown>;
  retrieved_at: string | null;
  provenance: string;
  notice: string;
}
export interface SecurityPostureSummary {
  counts: {
    devices: number;
    pass: number;
    fail: number;
    incomplete: number;
    stale: number;
    pending_approval: number;
    expiring_attributes: number;
  };
  coverage: { devices_with_fresh_evidence: number; percent: number };
  attribute_coverage: Array<{ key: string; device_count: number; percent: number }>;
  namespaces: Record<string, number>;
  auto_update: Record<string, number>;
  release_tracks: Record<string, number>;
  findings: Array<{
    severity: string;
    kind: string;
    device_id: string;
    device: string;
    message: string;
    attribute?: string;
    expiry?: string;
  }>;
  capability: {
    status: string;
    detail: string;
    last_success: string | null;
    required_scope: string;
  };
  limitations: string[];
}
export interface GovernanceSummary {
  counts: {
    credentials: number;
    active_credentials: number;
    expiring_credentials: number;
    pending_invites: number;
    verified_contacts: number;
    enabled_streams: number;
  };
  findings: Array<{
    id: string;
    severity: string;
    kind: string;
    record_type: string;
    record_id: string;
    label: string;
    message: string;
    remediation: string;
    evidence: Record<string, unknown>;
  }>;
  capabilities: Record<string, {
    status: string;
    detail: string;
    last_success: string | null;
    checked_at: string | null;
    required_scope: string;
  }>;
  freshness: Record<string, number>;
  limitations: string[];
}
export interface GovernanceCredential {
  id: string;
  display_id: string;
  type: string;
  description: string;
  creator_id: string | null;
  scopes: string[];
  tags: string[];
  reusable: boolean | null;
  ephemeral: boolean | null;
  preapproved: boolean | null;
  created_at: string | null;
  expires_at: string | null;
  status: string;
  present: boolean;
  stale: boolean;
  synced_at: string;
  provenance: string;
}
export interface FindingSummary {
  total: number;
  open: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  open_by_severity: Record<string, number>;
  by_source: Record<string, number>;
  generated_at: string;
}
export interface FindingRecord {
  id: string;
  source: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  summary: string;
  remediation: string;
  subject_type: string;
  subject_id: string;
  subject_display: string;
  evidence: Record<string, unknown>;
  link_path: string;
  status: "open" | "acknowledged" | "suppressed" | "resolved";
  stale: boolean;
  first_seen: string;
  last_seen: string;
  last_evaluated: string;
  resolved_at: string | null;
  acknowledged_at: string | null;
  suppressed_until: string | null;
  suppression_reason: string;
  assigned_to: string | null;
  assignee: string | null;
  occurrence_count: number;
  occurrences?: Array<{
    id: string;
    event_type: string;
    severity: string;
    evidence: Record<string, unknown>;
    occurred_at: string;
  }>;
  transitions?: Array<{
    id: string;
    from_status: string | null;
    to_status: string;
    actor_id: string | null;
    reason: string;
    occurred_at: string;
  }>;
}
export interface TailnetAddress {
  address: string;
  family: string;
  scope: "tailnet";
  provenance: "tailscale_device_api";
  reliability: "api_reported";
}
export interface ObservedPhysicalEndpoint {
  address: string;
  family: string;
  classification:
    | "public"
    | "private"
    | "shared"
    | "link_local"
    | "loopback"
    | "multicast"
    | "reserved"
    | "unknown";
  ports: number[];
  first_observed_at: string;
  last_observed_at: string;
  observer_count: number;
  observers: Array<{ id: string; name: string }>;
  reported_bytes: number;
  provenance: "network_flow_logs_physical";
  reliability: "client_reported_unverified";
}
export interface AddressInventory {
  tailnet: TailnetAddress[];
  observed: ObservedPhysicalEndpoint[];
  status:
    | "available"
    | "capability_unavailable"
    | "retention_limited"
    | "no_observations";
  capability_status: string;
  requested_hours: 24 | 168 | 720;
  retention_days: number;
  truncated: boolean;
  notice: string;
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "observed" | "permitted" | "hosting";
  reported_bytes?: number;
  ports?: string[];
  status?: string;
  rule_index?: number;
}
export interface TopologyData {
  nodes: Array<Device | ServiceSummary>;
  edges: GraphEdge[];
  notice: string;
}
export interface ServiceSummary {
  id: string;
  service_id?: string;
  name: string;
  comment?: string;
  status: string;
  addresses: string[];
  tags: string[];
  ports: string[];
  host_count?: number;
  source: string;
  synced_at?: string;
  stale?: boolean;
  kind?: "service";
  primary_role?: "service";
  online?: null;
}

export interface ServiceDetail extends ServiceSummary {
  availability: string;
  hosts: Array<{ id: string; device_id: string | null; device_name: string | null; advertised: boolean | null; approved: boolean | null; status: string }>;
  endpoints: Array<{ id: string; host_id: string | null; protocol: string; port: number | null; type: string }>;
  policy_references: Array<{ section: string; rule_index: number }>;
  provenance: string;
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  notice?: string;
}

export interface FlowRecord {
  id: number;
  source: string;
  source_device_id: string | null;
  source_service_id: string | null;
  source_raw: string | null;
  destination: string;
  destination_device_id: string | null;
  destination_service_id: string | null;
  destination_raw: string | null;
  protocol: number | null;
  source_port: number | null;
  destination_port: number | null;
  category: "virtual" | "subnet" | "exit" | "physical";
  reported_bytes: number;
  reported_packets: number;
  start: string;
  end: string;
  reporting_node: string;
  reporting_node_id: string | null;
  provenance: string;
}

export interface FlowSummaryPoint {
  bucket_start: string;
  reported_bytes: number;
  reported_packets: number;
  record_count: number;
}

export interface FlowSummary {
  series: FlowSummaryPoint[];
  reported_bytes: number;
  reported_packets: number;
  record_count: number;
  top_devices: FlowDeviceTraffic[];
  range_hours: number;
  notice: string;
}

export interface FlowDeviceTraffic {
  device_id: string;
  name: string;
  reported_bytes: number;
  reported_packets: number;
  record_count: number;
}

export interface DnsConfiguration {
  available: boolean;
  stale: boolean;
  status: string;
  source: string;
  required_scope: string;
  detail: string;
  checked_at: string | null;
  last_success: string | null;
  synced_at?: string | null;
  magic_dns?: boolean | null;
  override_local_dns?: boolean | null;
  nameservers?: unknown[];
  search_paths?: string[];
  split_dns?: Record<string, unknown>;
}

export interface ReportArtifactMetadata {
  format: "pdf" | "json" | "csv";
  content_type: string;
  filename: string;
  content_hash: string;
  size: number;
}

export type ReportSection =
  | "trends"
  | "devices"
  | "pairs"
  | "services"
  | "protocols"
  | "ports"
  | "categories"
  | "resolution"
  | "fleet_context";

export interface ReportOptions {
  description: string;
  ranking_limit: 5 | 10 | 20;
  include_previous_period: boolean;
  sections: ReportSection[];
}

export interface NetworkReport {
  id: string;
  title: string;
  status: "queued" | "running" | "completed" | "partial" | "failed";
  schedule_id: string | null;
  saved_view_id: string | null;
  saved_view_revision: number | null;
  retry_of_id: string | null;
  report_options: ReportOptions;
  snapshot_schema_version: number;
  generation_stage: "queued" | "aggregating" | "rendering" | "storing" | "completed" | "failed";
  progress: number;
  range_start: string;
  range_end: string;
  filters: Record<string, unknown>;
  coverage: { complete?: boolean; coverage_start?: string | null; coverage_end?: string | null; granularity?: string };
  error: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  artifacts: ReportArtifactMetadata[];
  snapshot?: Record<string, any>;
}

export interface ReportScheduleRecord {
  id: string;
  name: string;
  saved_view_id: string | null;
  frequency: "daily" | "weekly" | "monthly";
  timezone: string;
  local_time: string;
  weekday: number | null;
  month_day: number | null;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_error: string;
  created_at: string;
  updated_at: string;
  report_options: ReportOptions;
  recent_runs?: Array<{
    id: string;
    title: string;
    status: NetworkReport["status"];
    created_at: string;
    completed_at: string | null;
    retry_of_id: string | null;
  }>;
}
