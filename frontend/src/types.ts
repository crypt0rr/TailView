export interface Device {
  id: string;
  name: string;
  source_name: string;
  hostname: string;
  os: string;
  version: string;
  owner_id: string | null;
  online: boolean | null;
  authorized: boolean | null;
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
}
export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "observed" | "permitted";
  reported_bytes?: number;
  ports?: string[];
  status?: string;
  rule_index?: number;
}
export interface TopologyData {
  nodes: Device[];
  edges: GraphEdge[];
  notice: string;
}
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  notice?: string;
}
