import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import cytoscape from "cytoscape";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  Copy,
  Download,
  Eye,
  Filter,
  Scan,
  GitCompareArrows,
  KeyRound,
  List,
  Maximize2,
  Network,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  X,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { request } from "./api";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorState,
  Loading,
  Status,
  formatBytes,
  relativeTime,
  roleIcon,
  statusIcon,
} from "./components";
import type { Device, Page, TopologyData } from "./types";

const palette = [
  "#5be7c4",
  "#7b8cff",
  "#f8ba62",
  "#f2749d",
  "#70b7ff",
  "#a689fa",
];

export function Dashboard() {
  const query = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => request<Record<string, any>>("/dashboard"),
  });
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} />;
  const d = query.data!;
  const cards = [
    ["Total nodes", d.devices, Network, "All registered devices"],
    ["Online", d.online, Zap, "API-reported state"],
    ["Users", d.users, Users, "Tailnet identities"],
    ["Expiring keys", d.expiring_keys, KeyRound, "Within 14 days"],
  ];
  return (
    <div className="page">
      <PageHead
        eyebrow="OPERATIONS"
        title="Tailnet overview"
        description="A concise view of inventory health, reported traffic, and access posture."
      />
      <div className="metric-grid">
        {cards.map(([label, value, Icon, detail], i) => (
          <Card key={String(label)} className="metric-card">
            <div className={`metric-icon c${i}`}>
              <Icon />
            </div>
            <span>{label}</span>
            <strong>{value}</strong>
            <small>{detail}</small>
            <i className="metric-rule" />
          </Card>
        ))}
      </div>
      <div className="dashboard-grid">
        <Card className="chart-card wide">
          <CardHead
            title="Network activity"
            detail={String(d.traffic_label)}
            action={
              <Badge tone="success">
                <CircleDot /> Reporting
              </Badge>
            }
          />
          <TrafficChart />
        </Card>
        <Card className="chart-card">
          <CardHead
            title="Operating systems"
            detail="Current inventory distribution"
          />
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={d.operating_systems}
                dataKey="value"
                nameKey="name"
                innerRadius={60}
                outerRadius={90}
                paddingAngle={4}
              >
                {(d.operating_systems as any[]).map((_: any, i: number) => (
                  <Cell key={i} fill={palette[i % palette.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend iconType="circle" />
            </PieChart>
          </ResponsiveContainer>
        </Card>
        <Card className="chart-card">
          <CardHead title="Node roles" detail="Primary classification" />
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={d.roles} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="name"
                width={110}
                tick={{ fill: "var(--muted)", fontSize: 12 }}
              />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value" fill="#5be7c4" radius={[0, 5, 5, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
        <Card className="chart-card wide">
          <CardHead
            title="Top node pairs"
            detail="Aggregated reported volume"
            action={
              <a href="/flows">
                Explore flows <ChevronRight />
              </a>
            }
          />
          <div className="pair-list">
            {(d.top_pairs as any[]).map((p: any, i: number) => (
              <div key={`${p.source}-${p.destination}`}>
                <span className="rank">0{i + 1}</span>
                <div>
                  <strong>{p.source}</strong>
                  <small>to {p.destination}</small>
                </div>
                <span className="flow-line">
                  <i style={{ width: `${Math.max(12, 100 - i * 18)}%` }} />
                </span>
                <strong>{formatBytes(p.reported_bytes)}</strong>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function TrafficChart() {
  const data = Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, "0")}:00`,
    reported: Math.round(8 + Math.sin(i / 3) * 4 + (i % 5) * 1.4),
  }));
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="traffic" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#5be7c4" stopOpacity={0.35} />
            <stop offset="1" stopColor="#5be7c4" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
        <XAxis
          dataKey="time"
          tick={{ fill: "var(--muted)", fontSize: 11 }}
          interval={3}
        />
        <YAxis tick={{ fill: "var(--muted)", fontSize: 11 }} unit=" MB" />
        <Tooltip contentStyle={tooltipStyle} />
        <Area
          type="monotone"
          dataKey="reported"
          stroke="#5be7c4"
          fill="url(#traffic)"
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function Devices({ role = "" }: { role?: string }) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Device | null>(null);
  const query = useQuery({
    queryKey: ["devices", search, role],
    queryFn: () =>
      request<Page<Device>>(
        `/devices?search=${encodeURIComponent(search)}&role=${encodeURIComponent(role)}`,
      ),
  });
  return (
    <div className="page">
      <PageHead
        eyebrow="INVENTORY"
        title={role ? role.replaceAll("_", " ") : "Devices"}
        description="API-derived device state with local metadata kept visibly separate."
        actions={
          <Button variant="secondary">
            <Download /> Export CSV
          </Button>
        }
      />
      <Toolbar search={search} setSearch={setSearch} />
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : !query.data?.items.length ? (
        <Empty
          title="No devices found"
          detail="Adjust filters or check device synchronization."
        />
      ) : (
        <DeviceTable devices={query.data.items} onSelect={setSelected} />
      )}
      {selected && (
        <NodeDrawer device={selected} close={() => setSelected(null)} />
      )}
    </div>
  );
}
export function DeviceTable({
  devices,
  onSelect,
}: {
  devices: Device[];
  onSelect: (device: Device) => void;
}) {
  return (
    <Card className="table-card">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Status</th>
              <th>Role</th>
              <th>Owner</th>
              <th>OS / Version</th>
              <th>Addresses</th>
              <th>Last seen</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr
                key={d.id}
                className="device-row"
                tabIndex={0}
                aria-label={`Open details for ${d.name}`}
                onClick={() => onSelect(d)}
                onKeyDown={(event) => {
                  if (event.target !== event.currentTarget) return;
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect(d);
                  }
                }}
              >
                <td>
                  <button
                    type="button"
                    className="device-name"
                    aria-label={`View details for ${d.name}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelect(d);
                    }}
                  >
                    <span className="device-icon">
                      {roleIcon(d.primary_role)}
                    </span>
                    <span>
                      <strong>{d.name}</strong>
                      <small>{d.hostname}</small>
                    </span>
                  </button>
                </td>
                <td>
                  <Status online={d.online} />
                </td>
                <td>
                  <Badge>{d.primary_role.replaceAll("_", " ")}</Badge>
                  {d.roles.length > 1 && (
                    <small className="more">+{d.roles.length - 1}</small>
                  )}
                </td>
                <td>
                  {d.owner_id ?? <span className="muted">Tagged identity</span>}
                </td>
                <td>
                  <strong>{d.os}</strong>
                  <small className="block">{d.version || "Not reported"}</small>
                </td>
                <td>
                  <code>{d.addresses[0] ?? "—"}</code>
                </td>
                <td>{relativeTime(d.last_seen)}</td>
                <td>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={`Open details for ${d.name}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      onSelect(d);
                    }}
                  >
                    <ChevronRight />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function Topology() {
  const [selected, setSelected] = useState<Device | null>(null);
  const [showPolicy, setShowPolicy] = useState(false);
  const [showObserved, setShowObserved] = useState(false);
  const [layout, setLayout] = useState("cose");
  const [search, setSearch] = useState("");
  const query = useQuery({
    queryKey: ["topology"],
    queryFn: () => request<TopologyData>("/topology"),
  });
  const container = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  useEffect(() => {
    const requestedNode = new URLSearchParams(window.location.search).get(
      "node",
    );
    if (!requestedNode || !query.data) return;
    const device = query.data.nodes.find((node) => node.id === requestedNode);
    if (device) setSelected(device);
  }, [query.data]);
  useEffect(() => {
    if (!container.current || !query.data) return;
    const filtered = query.data.nodes.filter((n) =>
      n.name.toLowerCase().includes(search.toLowerCase()),
    );
    const ids = new Set(filtered.map((n) => n.id));
    const elements: any[] = [
      ...filtered.map((n) => ({
        data: {
          id: n.id,
          label: n.name.split(".")[0],
          role: n.primary_role,
          online: String(n.online),
          device: n,
        },
      })),
      ...query.data.edges
        .filter(
          (e) =>
            ids.has(e.source) &&
            ids.has(e.target) &&
            ((e.kind === "observed" && showObserved) ||
              (e.kind === "permitted" && showPolicy)),
        )
        .map((e) => ({ data: { ...e, id: e.id } })),
    ];
    const cy = cytoscape({
      container: container.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "#263449",
            "border-color": "#64748b",
            "border-width": 2,
            label: "data(label)",
            color: "#cbd5e1",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 8,
            width: 34,
            height: 34,
          },
        },
        {
          selector: 'node[online = "true"]',
          style: { "border-color": "#5be7c4", "border-width": 3 },
        },
        {
          selector: 'node[role *= "exit"]',
          style: { shape: "diamond", "background-color": "#6d5bd0" },
        },
        {
          selector: 'node[role *= "router"]',
          style: { shape: "hexagon", "background-color": "#2f81a8" },
        },
        {
          selector: 'node[role *= "service"]',
          style: { shape: "round-rectangle", "background-color": "#257d6c" },
        },
        {
          selector: 'edge[kind = "observed"]',
          style: {
            "line-color": "#5be7c4",
            "target-arrow-color": "#5be7c4",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            width: 2,
            opacity: 0.75,
          },
        },
        {
          selector: 'edge[kind = "permitted"]',
          style: {
            "line-color": "#7b8cff",
            "target-arrow-color": "#7b8cff",
            "target-arrow-shape": "vee",
            "curve-style": "bezier",
            width: 1,
            "line-style": "dashed",
            opacity: 0.55,
          },
        },
        {
          selector: ":selected",
          style: {
            "overlay-color": "#5be7c4",
            "overlay-opacity": 0.15,
            "overlay-padding": 8,
          },
        },
      ],
      layout: { name: layout, animate: true, padding: 40 } as any,
    });
    cy.on("tap", "node", (e) => setSelected(e.target.data("device") as Device));
    cyRef.current = cy;
    return () => cy.destroy();
  }, [query.data, showPolicy, showObserved, layout, search]);
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} />;
  return (
    <div className="topology-page">
      <div className="topology-head">
        <PageHead
          eyebrow="LIVE MODEL"
          title="Topology"
          description="Observed traffic and current policy are separate layers."
        />
        <div className="topology-tools">
          <label className="search-field">
            <Search />
            <input
              placeholder="Find a node…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </label>
          <select value={layout} onChange={(e) => setLayout(e.target.value)}>
            <option value="cose">Force-directed</option>
            <option value="breadthfirst">Hierarchical</option>
            <option value="circle">Grouped circle</option>
            <option value="concentric">Role-centric</option>
            <option value="grid">Grid</option>
          </select>
          <button
            className={`layer-toggle observed ${showObserved ? "on" : ""}`}
            onClick={() => setShowObserved(!showObserved)}
          >
            <span />
            Observed
          </button>
          <button
            className={`layer-toggle policy ${showPolicy ? "on" : ""}`}
            onClick={() => setShowPolicy(!showPolicy)}
          >
            <span />
            Permitted
          </button>
          <button
            className="icon-button"
            onClick={() => cyRef.current?.fit(undefined, 40)}
            title="Fit view"
          >
            <Scan />
          </button>
          <button
            className="icon-button"
            onClick={() => container.current?.requestFullscreen()}
            title="Full screen"
          >
            <Maximize2 />
          </button>
        </div>
      </div>
      <div className="graph-wrap">
        <div className="graph-canvas" ref={container} />
        <div className="graph-legend">
          <strong>Legend</strong>
          <span>
            <i className="node-legend online" /> Online node
          </span>
          <span>
            <i className="node-legend" /> Offline / unknown
          </span>
          <span>
            <i className="edge-legend observed" /> Observed
          </span>
          <span>
            <i className="edge-legend policy" /> Policy-permitted
          </span>
          <small>{query.data?.notice}</small>
        </div>
        {selected && (
          <NodeDrawer device={selected} close={() => setSelected(null)} />
        )}
      </div>
    </div>
  );
}

function NodeDrawer({ device, close }: { device: Device; close: () => void }) {
  const detail = useQuery({
    queryKey: ["device", device.id],
    queryFn: () => request<Device & { flows: any[] }>(`/devices/${device.id}`),
  });
  const d = detail.data ?? device;
  const [tab, setTab] = useState("overview");
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [close]);
  return (
    <>
      <div className="drawer-backdrop" aria-hidden="true" onClick={close} />
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`Device details for ${d.name}`}
      >
      <div className="drawer-head">
        <div className="large-node-icon">{roleIcon(d.primary_role)}</div>
        <div>
          <span className="eyebrow">{d.primary_role.replaceAll("_", " ")}</span>
          <h2>{d.name.split(".")[0]}</h2>
          <Status online={d.online} />
        </div>
        <button
          className="icon-button"
          onClick={close}
          aria-label="Close device details"
        >
          <X />
        </button>
      </div>
      <div className="drawer-tabs">
        {["overview", "networking", "access", "flows", "history"].map((t) => (
          <button
            key={t}
            className={tab === t ? "active" : ""}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="drawer-body">
        {detail.isLoading ? (
          <Loading />
        ) : tab === "overview" ? (
          <>
            <DetailGroup title="Identity">
              <Detail label="Full name" value={d.source_name} />
              <Detail label="Owner" value={d.owner_id ?? "Tagged identity"} />
              <Detail label="Operating system" value={`${d.os} ${d.version}`} />
              <Detail
                label="Last seen"
                value={`${relativeTime(d.last_seen)}${d.last_seen ? ` · ${new Date(d.last_seen).toLocaleString()}` : ""}`}
              />
              <Detail label="Source" value={d.source} />
            </DetailGroup>
            <DetailGroup title="Addresses">
              {d.addresses.map((a) => (
                <button
                  className="copy-row"
                  key={a}
                  onClick={() => navigator.clipboard.writeText(a)}
                >
                  <code>{a}</code>
                  <Copy />
                </button>
              ))}
            </DetailGroup>
            <DetailGroup title="Classification">
              <div className="badge-row">
                {d.roles.map((r) => (
                  <Badge key={r}>{r.replaceAll("_", " ")}</Badge>
                ))}
              </div>
              {d.tags.length > 0 && (
                <div className="badge-row">
                  {d.tags.map((t) => (
                    <Badge tone="purple" key={t}>
                      {t}
                    </Badge>
                  ))}
                </div>
              )}
            </DetailGroup>
          </>
        ) : tab === "networking" ? (
          <>
            <DetailGroup title="Advertised routes">
              {d.advertised_routes.length ? (
                d.advertised_routes.map((r) => (
                  <code className="route" key={r}>
                    {r}
                  </code>
                ))
              ) : (
                <p className="muted">No routes reported.</p>
              )}
            </DetailGroup>
            <DetailGroup title="Approved routes">
              {d.approved_routes.length ? (
                d.approved_routes.map((r) => (
                  <code className="route" key={r}>
                    {r}
                  </code>
                ))
              ) : (
                <p className="muted">No routes approved.</p>
              )}
            </DetailGroup>
          </>
        ) : tab === "access" ? (
          <AccessSummary />
        ) : tab === "flows" ? (
          <FlowSummary flows={(d as any).flows ?? []} />
        ) : (
          <Empty
            title="No historical changes"
            detail="History begins when TailView first synchronizes this device."
            icon={<Clock3 />}
          />
        )}
      </div>
      <div className="drawer-foot">
        <a className="button secondary" href="/flows">
          <List /> Open flows
        </a>
        <a className="button primary" href={`/topology?node=${d.id}`}>
          <Network /> Show in topology
        </a>
      </div>
      </aside>
    </>
  );
}
function AccessSummary() {
  return (
    <>
      <div className="reliability">
        <GitCompareArrows />
        <div>
          <strong>Policy relationship</strong>
          <p>
            Current allow rules are evaluated independently from historical
            observations.
          </p>
        </div>
      </div>
      <DetailGroup title="Evaluation states">
        <div className="access-row">
          <span className="access-icon allow">
            <CheckCircle2 />
          </span>
          <div>
            <strong>Permitted by current policy</strong>
            <p>Matching additive allow rule.</p>
          </div>
        </div>
        <div className="access-row">
          <span className="access-icon incomplete">
            <AlertTriangle />
          </span>
          <div>
            <strong>Evaluation incomplete</strong>
            <p>Unknown selectors are never guessed.</p>
          </div>
        </div>
      </DetailGroup>
    </>
  );
}
function FlowSummary({ flows }: { flows: any[] }) {
  return (
    <DetailGroup title="Recent observed windows">
      {!flows.length ? (
        <p className="muted">No flow windows in this range.</p>
      ) : (
        flows.slice(0, 12).map((f) => (
          <div className="mini-flow" key={f.id}>
            <Activity />
            <div>
              <strong>
                {f.source} → {f.destination}
              </strong>
              <small>
                {f.category} · port {f.destination_port ?? "not logged"}
              </small>
            </div>
            <span>{formatBytes(f.reported_bytes)}</span>
          </div>
        ))
      )}
      <p className="drawer-notice">
        Historical client-reported windows, not active sessions.
      </p>
    </DetailGroup>
  );
}

export function Flows() {
  const [category, setCategory] = useState("");
  const query = useQuery({
    queryKey: ["flows", category],
    queryFn: () => request<Page<any>>(`/flows?category=${category}`),
  });
  const rows = useMemo(() => query.data?.items ?? [], [query.data?.items]);
  const chart = useMemo(() => {
    const buckets = new Map<string, number>();
    rows.forEach((f) => {
      const key = new Date(f.start).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
      buckets.set(key, (buckets.get(key) ?? 0) + f.reported_bytes);
    });
    return [...buckets]
      .reverse()
      .map(([time, bytes]) => ({ time, mb: bytes / 1e6 }));
  }, [rows]);
  return (
    <div className="page">
      <PageHead
        eyebrow="NETWORK FLOW LOGS"
        title="Flow explorer"
        description="Historical, client-reported traffic windows. Not active sessions."
        actions={
          <a className="button secondary" href="/api/v1/flows/export.csv">
            <Download /> Export CSV
          </a>
        }
      />
      <div className="notice-bar">
        <AlertTriangle />
        <span>
          <strong>Interpret with care.</strong> Peer reports can overlap, and
          client-supplied fields are not verified by Tailscale. Only successful
          connections appear.
        </span>
      </div>
      <Card className="chart-card">
        <CardHead
          title="Reported traffic volume"
          detail="TX + RX bytes from retrieved flow windows"
        />
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={chart}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
            <XAxis
              dataKey="time"
              tick={{ fill: "var(--muted)", fontSize: 11 }}
            />
            <YAxis tick={{ fill: "var(--muted)", fontSize: 11 }} unit=" MB" />
            <Tooltip contentStyle={tooltipStyle} />
            <Area dataKey="mb" stroke="#5be7c4" fill="#5be7c433" />
          </AreaChart>
        </ResponsiveContainer>
      </Card>
      <div className="toolbar">
        <div className="filter-chips">
          {["", "virtual", "subnet", "exit", "physical"].map((c) => (
            <button
              key={c}
              className={category === c ? "active" : ""}
              onClick={() => setCategory(c)}
            >
              {c || "All categories"}
            </button>
          ))}
        </div>
        <Button variant="secondary">
          <SlidersHorizontal /> More filters
        </Button>
      </div>
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : (
        <Card className="table-card">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Observed window</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Type</th>
                  <th>Protocol / port</th>
                  <th>Reported volume</th>
                  <th>Reporter</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <strong>{relativeTime(f.start)}</strong>
                      <small className="block">
                        {new Date(f.start).toLocaleString()}
                      </small>
                    </td>
                    <td>
                      <code>{f.source}</code>
                    </td>
                    <td>
                      <code>{f.destination}</code>
                    </td>
                    <td>
                      <Badge tone={f.category}>{f.category}</Badge>
                    </td>
                    <td>
                      {f.protocol === 6
                        ? "TCP"
                        : f.protocol === 17
                          ? "UDP"
                          : (f.protocol ?? "Not logged")}{" "}
                      / {f.destination_port ?? "—"}
                    </td>
                    <td>
                      <strong>{formatBytes(f.reported_bytes)}</strong>
                      <small className="block">
                        {f.reported_packets.toLocaleString()} packets
                      </small>
                    </td>
                    <td>{f.reporting_node}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

export function Policy() {
  const query = useQuery({
    queryKey: ["policy"],
    queryFn: () => request<any>("/policy"),
  });
  const [tab, setTab] = useState("normalized");
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} />;
  if (!query.data.available)
    return <Empty title="Policy unavailable" detail={query.data.status} />;
  const p = query.data;
  const sections = Object.entries(p.normalized as Record<string, unknown>);
  return (
    <div className="page">
      <PageHead
        eyebrow="READ-ONLY POLICY"
        title="Policy explorer"
        description="Explainable current-policy analysis. TailView never writes your policy."
        actions={
          <Badge tone={p.valid ? "success" : "danger"}>
            {p.valid ? (
              <>
                <CheckCircle2 /> Valid snapshot
              </>
            ) : (
              <>
                <AlertTriangle /> Parse error
              </>
            )}
          </Badge>
        }
      />
      <div className="notice-bar blue">
        <ShieldCheck />
        <span>
          <strong>Deny by default.</strong> Multiple matching allow rules are
          additive. Missing permission is “no matching allow rule,” not proof of
          a blocked attempt.
        </span>
      </div>
      <div className="policy-layout">
        <aside className="policy-nav">
          <strong>Policy sections</strong>
          {sections.map(([name, value]) => (
            <a href={`#policy-${name}`} key={name}>
              <span>{name}</span>
              <Badge>
                {Array.isArray(value)
                  ? value.length
                  : Object.keys((value as object) ?? {}).length}
              </Badge>
            </a>
          ))}
          {p.unsupported.length > 0 && (
            <a href="#unsupported">
              <AlertTriangle />
              Unsupported <Badge tone="danger">{p.unsupported.length}</Badge>
            </a>
          )}
        </aside>
        <div className="policy-content">
          <div className="segmented">
            <button
              className={tab === "normalized" ? "active" : ""}
              onClick={() => setTab("normalized")}
            >
              Normalized
            </button>
            <button
              className={tab === "raw" ? "active" : ""}
              onClick={() => setTab("raw")}
            >
              Raw HuJSON
            </button>
          </div>
          {tab === "raw" ? (
            <Card className="code-card">
              <div className="code-head">
                <span>{p.id.slice(0, 12)}…</span>
                <Button
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(p.hujson)}
                >
                  <Copy /> Copy
                </Button>
              </div>
              <pre>{p.hujson}</pre>
            </Card>
          ) : (
            sections.map(([name, value]) => (
              <Card className="policy-section" key={name}>
                <div id={`policy-${name}`}>
                  <span className="eyebrow">{name.toUpperCase()}</span>
                  <h3>{name}</h3>
                </div>
                <pre>{JSON.stringify(value, null, 2)}</pre>
              </Card>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export function InventoryPage({ kind }: { kind: string }) {
  const endpoint =
    kind === "audit" ? "/audit" : kind === "sync" ? "/sync" : `/${kind}`;
  const query = useQuery({
    queryKey: [kind],
    queryFn: () => request<Page<any>>(endpoint),
  });
  const titles: Record<string, string> = {
    users: "Users",
    groups: "Policy groups",
    routes: "Routes",
    services: "Services",
    tags: "Tags",
    audit: "Configuration audit",
    sync: "Synchronization jobs",
  };
  return (
    <div className="page">
      <PageHead
        eyebrow="INVENTORY"
        title={titles[kind] ?? kind}
        description={
          kind === "audit"
            ? "Configuration changes remain distinct from network-flow observations."
            : "Searchable normalized inventory with explicit provenance."
        }
      />
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : !query.data?.items.length ? (
        <Empty
          title={`No ${kind} available`}
          detail="The capability may be unavailable, unsynchronized, or absent from this tailnet."
        />
      ) : (
        <GenericTable rows={query.data.items} />
      )}
    </div>
  );
}
function GenericTable({ rows }: { rows: Record<string, any>[] }) {
  const columns = Object.keys(rows[0] ?? {})
    .filter((k) => !["old", "new", "raw"].includes(k))
    .slice(0, 8);
  return (
    <Card className="table-card">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c}>{c.replaceAll("_", " ")}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={String(row.id ?? row.name ?? i)}>
                {columns.map((c) => (
                  <td key={c}>
                    {typeof row[c] === "object" && row[c] !== null ? (
                      <code>{JSON.stringify(row[c]).slice(0, 100)}</code>
                    ) : typeof row[c] === "boolean" ? (
                      String(row[c])
                    ) : (
                      String(row[c] ?? "—")
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function SettingsPage({ user }: { user: { role: string } }) {
  const query = useQuery({
    queryKey: ["capabilities"],
    queryFn: () => request<Page<any>>("/capabilities"),
  });
  return (
    <div className="page">
      <PageHead
        eyebrow="ADMINISTRATION"
        title="Settings & capabilities"
        description="Every data source is probed independently; optional failures do not stop TailView."
      />
      <div className="settings-grid">
        <Card className="settings-card">
          <CardHead
            title="Application security"
            detail="Local authentication is independent from Tailscale."
          />
          <div className="setting-row">
            <div>
              <strong>Current role</strong>
              <p>Your TailView permission level.</p>
            </div>
            <Badge tone={user.role === "administrator" ? "success" : "neutral"}>
              {user.role}
            </Badge>
          </div>
          <div className="setting-row">
            <div>
              <strong>Session protection</strong>
              <p>HttpOnly session, SameSite cookie, CSRF token.</p>
            </div>
            <Badge tone="success">
              <CheckCircle2 /> Enabled
            </Badge>
          </div>
          <div className="setting-row">
            <div>
              <strong>Integration mode</strong>
              <p>Management API calls are read-only.</p>
            </div>
            <Badge tone="success">
              <Eye /> Read only
            </Badge>
          </div>
        </Card>
        <Card className="settings-card full">
          <CardHead
            title="Data-source capability matrix"
            detail="A missing optional source never becomes an application-wide failure."
          />
          {query.isLoading ? (
            <Loading />
          ) : query.error ? (
            <ErrorState error={query.error} />
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Capability</th>
                    <th>Status</th>
                    <th>Source</th>
                    <th>Requirement</th>
                    <th>Last successful sync</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data?.items.map((c) => (
                    <tr key={c.name}>
                      <td>
                        <strong>{c.name.replaceAll("_", " ")}</strong>
                        <small className="block">{c.detail}</small>
                      </td>
                      <td>
                        <Badge
                          tone={
                            c.status === "available" ? "success" : "warning"
                          }
                        >
                          {statusIcon(c.status)}
                          {c.status.replaceAll("_", " ")}
                        </Badge>
                      </td>
                      <td>{c.source}</td>
                      <td>
                        <code>{c.requirement}</code>
                      </td>
                      <td>
                        {c.last_success
                          ? relativeTime(c.last_success)
                          : "Never"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function PageHead({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}
function CardHead({
  title,
  detail,
  action,
}: {
  title: string;
  detail: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="card-head">
      <div>
        <h3>{title}</h3>
        <p>{detail}</p>
      </div>
      {action}
    </div>
  );
}
function Toolbar({
  search,
  setSearch,
}: {
  search: string;
  setSearch: (s: string) => void;
}) {
  return (
    <div className="toolbar">
      <label className="search-field">
        <Search />
        <input
          placeholder="Search inventory…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </label>
      <div>
        <Button variant="secondary">
          <Filter /> Filters
        </Button>
        <Button variant="secondary">
          <Eye /> Columns
        </Button>
      </div>
    </div>
  );
}
function DetailGroup({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="detail-group">
      <h3>{title}</h3>
      {children}
    </section>
  );
}
function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
const tooltipStyle = {
  background: "var(--surface-strong)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text)",
  fontSize: 12,
};
