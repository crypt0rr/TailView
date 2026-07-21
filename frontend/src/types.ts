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
  addresses: string[];
  tags: string[];
  advertised_routes: string[];
  approved_routes: string[];
  roles: string[];
  primary_role: string;
  source: string;
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
  range_hours: number;
  notice: string;
}
