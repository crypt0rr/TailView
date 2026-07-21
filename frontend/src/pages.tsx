import { useEffect, useMemo, useRef, useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
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
import { useTimeRange } from "./timeRange";
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
import type {
  AddressInventory,
  Device,
  FlowRecord,
  FlowSummary,
  ObservedPhysicalEndpoint,
  Page,
  ServiceDetail,
  ServiceSummary,
  TopologyData,
} from "./types";

const palette = [
  "#5be7c4",
  "#7b8cff",
  "#f8ba62",
  "#f2749d",
  "#70b7ff",
  "#a689fa",
];

export function Dashboard() {
  const { hours } = useTimeRange();
  const query = useQuery({
    queryKey: ["dashboard", hours],
    queryFn: () => request<Record<string, any>>(`/dashboard?hours=${hours}`),
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
          <TrafficChart data={d.traffic_series ?? []} />
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
                  <EntityLink
                    label={p.source}
                    deviceId={p.source_device_id}
                  />
                  <small>
                    to{" "}
                    <EntityLink
                      label={p.destination}
                      deviceId={p.destination_device_id}
                    />
                  </small>
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

export function TrafficChart({
  data,
}: {
  data: Array<{ bucket_start: string; reported_bytes: number }>;
}) {
  const chartData = trafficChartData(data);
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart
        data={chartData}
        margin={{ top: 12, right: 18, bottom: 8, left: 8 }}
      >
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
          tickFormatter={trafficTimeLabel}
          tickMargin={10}
          minTickGap={48}
          interval="preserveStartEnd"
          padding={{ left: 8, right: 8 }}
          height={38}
        />
        <YAxis
          tick={{ fill: "var(--muted)", fontSize: 11 }}
          tickFormatter={trafficVolumeLabel}
          tickMargin={8}
          width={66}
        />
        <Tooltip
          contentStyle={tooltipStyle}
          labelFormatter={(value) => trafficTimeLabel(String(value))}
          formatter={(value) => [trafficVolumeLabel(Number(value)), "Reported volume"]}
        />
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

export function trafficChartData(
  data: Array<{ bucket_start: string; reported_bytes: number }>,
) {
  return data.map((point) => ({
    time: point.bucket_start,
    reported: point.reported_bytes / 1e6,
  }));
}

export function trafficTimeLabel(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
    .format(date)
    .replace(",", " ·");
}

export function trafficVolumeLabel(value: number) {
  if (value >= 1000) {
    const gigabytes = value / 1000;
    return `${gigabytes >= 10 ? gigabytes.toFixed(0) : gigabytes.toFixed(1)} GB`;
  }
  if (value > 0 && value < 1) return `${value.toFixed(1)} MB`;
  return `${Math.round(value)} MB`;
}

export function Devices({ role = "" }: { role?: string }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedDevice = searchParams.get("device");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const [owner, setOwner] = useState(searchParams.get("owner") ?? "");
  const [showColumns, setShowColumns] = useState(false);
  const [columns, setColumns] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem("tailview.deviceColumns");
      return saved ? (JSON.parse(saved) as Record<string, boolean>) : {};
    } catch {
      return {};
    }
  });
  const [selected, setSelected] = useState<Device | null>(null);
  const deviceParams = useMemo(() => {
    const params = new URLSearchParams({ search, role });
    if (statusFilter) params.set("status", statusFilter);
    if (owner) params.set("owner", owner);
    return params;
  }, [owner, role, search, statusFilter]);
  const query = useInfiniteQuery({
    queryKey: ["devices", search, role, statusFilter, owner],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(deviceParams);
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<Device>>(`/devices?${params}`);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
  const devices = useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data?.pages],
  );
  const requestedDeviceQuery = useQuery({
    queryKey: ["device", requestedDevice],
    queryFn: () => request<Device & { flows: any[] }>(`/devices/${requestedDevice}`),
    enabled: Boolean(requestedDevice),
  });
  useEffect(() => {
    if (!requestedDevice) return;
    const device = devices.find((item) => item.id === requestedDevice);
    if (device) {
      setSelected(device);
    } else if (requestedDeviceQuery.data) {
      setSelected(requestedDeviceQuery.data);
    }
  }, [devices, requestedDevice, requestedDeviceQuery.data]);
  const updateParams = (updates: Record<string, string | null>) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      Object.entries(updates).forEach(([key, value]) => {
        if (value) next.set(key, value);
        else next.delete(key);
      });
      return next;
    });
  };
  const selectDevice = (device: Device) => {
    setSelected(device);
    updateParams({ device: device.id });
  };
  const closeDevice = () => {
    setSelected(null);
    updateParams({ device: null });
  };
  const setDeviceSearch = (value: string) => {
    setSearch(value);
    updateParams({ search: value || null });
  };
  const setDeviceStatus = (value: string) => {
    setStatusFilter(value);
    updateParams({ status: value || null });
  };
  const setDeviceOwner = (value: string) => {
    setOwner(value);
    updateParams({ owner: value || null });
  };
  const toggleColumn = (column: string) => {
    const next = { ...columns, [column]: columns[column] === false };
    setColumns(next);
    localStorage.setItem("tailview.deviceColumns", JSON.stringify(next));
  };
  const exportUrl = `/api/v1/devices/export.csv?${deviceParams}`;
  return (
    <div className="page">
      <PageHead
        eyebrow="INVENTORY"
        title={role ? role.replaceAll("_", " ") : "Devices"}
        description="API-derived device state with local metadata kept visibly separate."
        actions={
          <a className="button secondary" href={exportUrl}>
            <Download /> Export CSV
          </a>
        }
      />
      <div className="toolbar inventory-toolbar">
        <label className="search-field">
          <Search />
          <input
            placeholder="Search devices, owners, or operating systems…"
            value={search}
            onChange={(event) => setDeviceSearch(event.target.value)}
          />
        </label>
        <div className="toolbar-fields">
          <select
            aria-label="Device status filter"
            value={statusFilter}
            onChange={(event) => setDeviceStatus(event.target.value)}
          >
            <option value="">All statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="unknown">Not reported</option>
          </select>
          <input
            aria-label="Device owner filter"
            placeholder="Filter owner…"
            value={owner}
            onChange={(event) => setDeviceOwner(event.target.value)}
          />
          <Button variant="secondary" onClick={() => setShowColumns((value) => !value)}>
            <Eye /> Columns
          </Button>
        </div>
      </div>
      {showColumns && (
        <div className="filter-panel column-picker" aria-label="Device columns">
          {["status", "role", "owner", "os", "addresses", "last_seen"].map((column) => (
            <label key={column}>
              <input
                type="checkbox"
                checked={columns[column] !== false}
                onChange={() => toggleColumn(column)}
              />
              {column.replaceAll("_", " ")}
            </label>
          ))}
        </div>
      )}
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : !devices.length ? (
        <Empty
          title="No devices found"
          detail="Adjust filters or check device synchronization."
        />
      ) : (
        <>
          <DeviceTable devices={devices} onSelect={selectDevice} columns={columns} />
          {query.hasNextPage && (
            <Button
              variant="secondary"
              onClick={() => void query.fetchNextPage()}
              disabled={query.isFetchingNextPage}
            >
              {query.isFetchingNextPage ? "Loading…" : "Load more devices"}
            </Button>
          )}
        </>
      )}
      {selected && (
        <NodeDrawer device={selected} close={closeDevice} />
      )}
    </div>
  );
}
export function DeviceTable({
  devices,
  onSelect,
  columns = {},
}: {
  devices: Device[];
  onSelect: (device: Device) => void;
  columns?: Record<string, boolean>;
}) {
  return (
    <Card className="table-card">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              {columns.status !== false && <th>Status</th>}
              {columns.role !== false && <th>Role</th>}
              {columns.owner !== false && <th>Owner</th>}
              {columns.os !== false && <th>OS / Version</th>}
              {columns.addresses !== false && <th>Addresses</th>}
              {columns.last_seen !== false && <th>Last seen</th>}
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
                {columns.status !== false && <td>
                  {d.stale ? <Badge tone="warning">Last-good / inactive</Badge> : <Status online={d.online} />}
                </td>}
                {columns.role !== false && <td>
                  <Badge>{d.primary_role.replaceAll("_", " ")}</Badge>
                  {d.roles.length > 1 && (
                    <small className="more">+{d.roles.length - 1}</small>
                  )}
                </td>}
                {columns.owner !== false && <td>
                  <OwnerLink device={d} />
                </td>}
                {columns.os !== false && <td>
                  <strong>{d.os}</strong>
                  <small className="block">{d.version || "Not reported"}</small>
                </td>}
                {columns.addresses !== false && <td>
                  <code>{d.addresses[0] ?? "—"}</code>
                </td>}
                {columns.last_seen !== false && <td>{relativeTime(d.last_seen)}</td>}
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
  const { hours } = useTimeRange();
  const [selected, setSelected] = useState<Device | ServiceSummary | null>(null);
  const [showPolicy, setShowPolicy] = useState(false);
  const [showObserved, setShowObserved] = useState(false);
  const [layout, setLayout] = useState("cose");
  const [search, setSearch] = useState("");
  const query = useQuery({
    queryKey: ["topology", hours],
    queryFn: () => request<TopologyData>(`/topology?hours=${hours}`),
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
            (e.kind === "hosting" ||
              (e.kind === "observed" && showObserved) ||
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
          selector: 'edge[kind = "hosting"]',
          style: {
            "line-color": "#f8ba62",
            "target-arrow-color": "#f8ba62",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            width: 2,
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
    cy.on("tap", "node", (e) => setSelected(e.target.data("device") as Device | ServiceSummary));
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
          "kind" in selected && selected.kind === "service" ? (
            <ServiceDrawer service={selected} close={() => setSelected(null)} />
          ) : (
            <NodeDrawer device={selected as Device} close={() => setSelected(null)} />
          )
        )}
      </div>
    </div>
  );
}

function NodeDrawer({ device, close }: { device: Device; close: () => void }) {
  const [addressHours, setAddressHours] = useState<24 | 168 | 720>(168);
  const detail = useQuery({
    queryKey: ["device", device.id, addressHours],
    queryFn: () =>
      request<Device & { flows: any[] }>(
        `/devices/${device.id}?address_hours=${addressHours}`,
      ),
    placeholderData: (previous) => previous,
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
            {d.stale && <div className="notice-bar warning"><AlertTriangle /><span>This device was absent from the last complete upstream listing. Showing its last successful snapshot.</span></div>}
            <DetailGroup title="Identity">
              <Detail label="Full name" value={d.source_name} />
              <Detail label="Owner" value={<OwnerLink device={d} />} />
              <Detail label="Operating system" value={`${d.os} ${d.version}`} />
              <Detail
                label="Last seen"
                value={`${relativeTime(d.last_seen)}${d.last_seen ? ` · ${new Date(d.last_seen).toLocaleString()}` : ""}`}
              />
              <Detail label="Source" value={d.source} />
            </DetailGroup>
            <AddressInventoryView
              inventory={d.address_inventory}
              fallbackAddresses={d.addresses}
              addressHours={addressHours}
              setAddressHours={setAddressHours}
              refreshing={detail.isFetching}
            />
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

export function AddressInventoryView({
  inventory,
  fallbackAddresses,
  addressHours,
  setAddressHours,
  refreshing = false,
}: {
  inventory?: AddressInventory;
  fallbackAddresses: string[];
  addressHours: 24 | 168 | 720;
  setAddressHours: (hours: 24 | 168 | 720) => void;
  refreshing?: boolean;
}) {
  const tailnet =
    inventory?.tailnet ??
    fallbackAddresses.map((address) => ({
      address,
      family: address.includes(":") ? "IPv6" : "IPv4",
    }));
  const groups: Array<{
    title: string;
    detail: string;
    items: ObservedPhysicalEndpoint[];
  }> = [
    {
      title: "Public",
      detail: "Globally routable candidates",
      items: inventory?.observed.filter((item) => item.classification === "public") ?? [],
    },
    {
      title: "Private / internal",
      detail: "RFC1918, ULA, or shared CGNAT candidates",
      items:
        inventory?.observed.filter((item) =>
          ["private", "shared"].includes(item.classification),
        ) ?? [],
    },
    {
      title: "Special",
      detail: "Loopback, link-local, multicast, reserved, or unknown",
      items:
        inventory?.observed.filter(
          (item) => !["public", "private", "shared"].includes(item.classification),
        ) ?? [],
    },
  ];
  return (
    <>
      <DetailGroup title="Tailnet addresses">
        {tailnet.map((item) => (
          <button
            className="copy-row address-row"
            key={item.address}
            aria-label={`Copy Tailnet address ${item.address}`}
            onClick={() => navigator.clipboard.writeText(item.address)}
          >
            <span>
              <code>{item.address}</code>
              <small>{item.family} · Device API</small>
            </span>
            <Copy />
          </button>
        ))}
      </DetailGroup>
      <DetailGroup title="Observed physical endpoints">
        <div className="address-range-row">
          <span>Observation range</span>
          <select
            aria-label="Observed endpoint range"
            value={addressHours}
            onChange={(event) =>
              setAddressHours(Number(event.target.value) as 24 | 168 | 720)
            }
          >
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
            <option value={720}>Last 30 days</option>
          </select>
          {refreshing && <small>Refreshing…</small>}
        </div>
        {!inventory ? (
          <p className="muted">Loading observed endpoint candidates…</p>
        ) : inventory.status === "capability_unavailable" ? (
          <AddressEmpty
            title="Flow logs unavailable"
            detail={`Capability status: ${inventory.capability_status.replaceAll("_", " ")}.`}
          />
        ) : inventory.status === "retention_limited" ? (
          <AddressEmpty
            title="Range exceeds retention"
            detail={`TailView currently retains ${inventory.retention_days} days of flow records.`}
          />
        ) : inventory.status === "no_observations" ? (
          <AddressEmpty
            title="No endpoint candidates observed"
            detail="No attributable physical-flow endpoints were retained in this range."
          />
        ) : (
          groups
            .filter((group) => group.items.length > 0)
            .map((group) => (
              <section className="address-scope" key={group.title}>
                <div className="address-scope-head">
                  <strong>{group.title}</strong>
                  <small>{group.detail}</small>
                </div>
                {group.items.map((item) => (
                  <ObservedEndpointCard endpoint={item} key={item.address} />
                ))}
              </section>
            ))
        )}
        {inventory?.truncated && (
          <p className="address-caveat">
            Results are based on the 20,000 most recent matching flow rows.
          </p>
        )}
        <div className="address-reliability">
          <AlertTriangle />
          <p>
            {inventory?.notice ??
              "Physical endpoints are historical, client-reported candidates—not authoritative device interface addresses."}
          </p>
        </div>
      </DetailGroup>
    </>
  );
}

function ObservedEndpointCard({ endpoint }: { endpoint: ObservedPhysicalEndpoint }) {
  return (
    <div className="observed-address-card">
      <div className="observed-address-head">
        <div>
          <code>{endpoint.address}</code>
          <div className="badge-row">
            <Badge tone={endpoint.classification === "public" ? "warning" : undefined}>
              {endpoint.classification.replaceAll("_", " ")}
            </Badge>
            <Badge>{endpoint.family}</Badge>
          </div>
        </div>
        <button
          className="icon-button"
          aria-label={`Copy observed endpoint ${endpoint.address}`}
          onClick={() => navigator.clipboard.writeText(endpoint.address)}
        >
          <Copy />
        </button>
      </div>
      <dl className="address-facts">
        <div>
          <dt>Ports</dt>
          <dd>{endpoint.ports.length ? endpoint.ports.join(", ") : "Not reported"}</dd>
        </div>
        <div>
          <dt>Last observed</dt>
          <dd>{relativeTime(endpoint.last_observed_at)}</dd>
        </div>
        <div>
          <dt>Observers</dt>
          <dd>{endpoint.observer_count}</dd>
        </div>
        <div>
          <dt>Reported volume</dt>
          <dd>{formatBytes(endpoint.reported_bytes)}</dd>
        </div>
      </dl>
      {endpoint.observers.length > 0 && (
        <small className="address-observers">
          Reported by {endpoint.observers.map((observer) => observer.name).join(", ")}
        </small>
      )}
      <small className="address-provenance">Physical flow logs · unverified</small>
    </div>
  );
}

function AddressEmpty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="address-empty">
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
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
                <EntityLink label={f.source} deviceId={f.source_device_id} /> →{" "}
                <EntityLink
                  label={f.destination}
                  deviceId={f.destination_device_id}
                />
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
  const { hours } = useTimeRange();
  const [searchParams, setSearchParams] = useSearchParams();
  const [category, setCategory] = useState(searchParams.get("category") ?? "");
  const [source, setSource] = useState(searchParams.get("source") ?? "");
  const [destination, setDestination] = useState(searchParams.get("destination") ?? "");
  const [protocol, setProtocol] = useState(searchParams.get("protocol") ?? "");
  const [port, setPort] = useState(searchParams.get("port") ?? "");
  const [resolution, setResolution] = useState(searchParams.get("resolution") ?? "all");
  const [showFilters, setShowFilters] = useState(
    Boolean(source || destination || protocol || port || resolution !== "all"),
  );
  const filterParams = useMemo(() => {
    const params = new URLSearchParams({ hours: String(hours) });
    if (category) params.set("category", category);
    if (source) params.set("source", source);
    if (destination) params.set("destination", destination);
    if (protocol) params.set("protocol", protocol);
    if (port) params.set("port", port);
    if (resolution !== "all") params.set("resolution", resolution);
    return params;
  }, [category, destination, hours, port, protocol, resolution, source]);
  const updateFilter = (key: string, value: string) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (value && value !== "all") next.set(key, value);
      else next.delete(key);
      return next;
    });
  };
  const query = useInfiniteQuery({
    queryKey: ["flows", filterParams.toString()],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(filterParams);
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<FlowRecord>>(`/flows?${params}`);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
  const summary = useQuery({
    queryKey: ["flows-summary", filterParams.toString()],
    queryFn: () => request<FlowSummary>(`/flows/summary?${filterParams}`),
  });
  const rows = useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data?.pages],
  );
  const chart = useMemo(
    () =>
      (summary.data?.series ?? []).map((point) => ({
        time: new Date(point.bucket_start).toLocaleString([], {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        }),
        mb: point.reported_bytes / 1e6,
      })),
    [summary.data?.series],
  );
  const setCategoryFilter = (value: string) => {
    setCategory(value);
    updateFilter("category", value);
  };
  const clearAdvancedFilters = () => {
    setSource("");
    setDestination("");
    setProtocol("");
    setPort("");
    setResolution("all");
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      ["source", "destination", "protocol", "port", "resolution"].forEach((key) =>
        next.delete(key),
      );
      return next;
    });
  };
  return (
    <div className="page">
      <PageHead
        eyebrow="NETWORK FLOW LOGS"
        title="Flow explorer"
        description="Historical, client-reported traffic windows. Not active sessions."
        actions={
          <a className="button secondary" href={`/api/v1/flows/export.csv?${filterParams}`}>
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
          detail={
            summary.data
              ? `${formatBytes(summary.data.reported_bytes)} across ${summary.data.record_count.toLocaleString()} matching records`
              : "TX + RX bytes from matching retrieved flow windows"
          }
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
              onClick={() => setCategoryFilter(c)}
            >
              {c || "All categories"}
            </button>
          ))}
        </div>
        <Button variant="secondary" onClick={() => setShowFilters((value) => !value)}>
          <SlidersHorizontal /> More filters
        </Button>
      </div>
      {showFilters && (
        <div className="filter-panel flow-filters" aria-label="Flow filters">
          <label>
            Source
            <input
              value={source}
              placeholder="Name, ID, or address"
              onChange={(event) => {
                setSource(event.target.value);
                updateFilter("source", event.target.value);
              }}
            />
          </label>
          <label>
            Destination
            <input
              value={destination}
              placeholder="Name, ID, or address"
              onChange={(event) => {
                setDestination(event.target.value);
                updateFilter("destination", event.target.value);
              }}
            />
          </label>
          <label>
            Protocol number
            <input
              type="number"
              min="0"
              max="255"
              value={protocol}
              onChange={(event) => {
                setProtocol(event.target.value);
                updateFilter("protocol", event.target.value);
              }}
            />
          </label>
          <label>
            Port
            <input
              type="number"
              min="1"
              max="65535"
              value={port}
              onChange={(event) => {
                setPort(event.target.value);
                updateFilter("port", event.target.value);
              }}
            />
          </label>
          <label>
            Resolution
            <select
              value={resolution}
              onChange={(event) => {
                setResolution(event.target.value);
                updateFilter("resolution", event.target.value);
              }}
            >
              <option value="all">All records</option>
              <option value="resolved">Both endpoints resolved</option>
              <option value="unresolved">At least one unresolved</option>
            </select>
          </label>
          <Button variant="ghost" onClick={clearAdvancedFilters}>Clear filters</Button>
        </div>
      )}
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : !rows.length ? (
        <Empty title="No flow records found" detail="Adjust the range or filters." />
      ) : (
        <>
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
                      <FlowEndpoint
                        label={f.source}
                        deviceId={f.source_device_id}
                        serviceId={f.source_service_id}
                        raw={f.source_raw}
                      />
                    </td>
                    <td>
                      <FlowEndpoint
                        label={f.destination}
                        deviceId={f.destination_device_id}
                        serviceId={f.destination_service_id}
                        raw={f.destination_raw}
                      />
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
                    <td>
                      <FlowEndpoint
                        label={f.reporting_node}
                        deviceId={f.reporting_node_id}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
              </table>
            </div>
          </Card>
          {query.hasNextPage && (
            <Button
              variant="secondary"
              onClick={() => void query.fetchNextPage()}
              disabled={query.isFetchingNextPage}
            >
              {query.isFetchingNextPage ? "Loading…" : "Load more flows"}
            </Button>
          )}
        </>
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
  const review = useQuery({
    queryKey: ["policy-review", query.data?.id],
    queryFn: () => request<any>("/policy/review"),
    enabled: tab === "review" && Boolean(query.data?.available),
  });
  const securityReview = useQuery({
    queryKey: ["policy-security-review", query.data?.id],
    queryFn: () => request<any>("/policy/security-review"),
    enabled: tab === "security" && Boolean(query.data?.available),
  });
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
            <button
              className={tab === "review" ? "active" : ""}
              onClick={() => setTab("review")}
            >
              Duplicate review
            </button>
            <button
              className={tab === "security" ? "active" : ""}
              onClick={() => setTab("security")}
            >
              Security review
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
          ) : tab === "review" ? (
            <PolicyDuplicateReview query={review} />
          ) : tab === "security" ? (
            <PolicySecurityReview query={securityReview} />
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

export function PolicySecurityReview({ query }: { query: any }) {
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} />;
  if (!query.data?.available) {
    return (
      <Empty
        title="Security review unavailable"
        detail={query.data?.status ?? "No valid policy snapshot is available."}
      />
    );
  }
  const review = query.data;
  const severities = ["critical", "high", "medium", "low", "info"];
  return (
    <div className="review-stack">
      <Card className="review-summary">
        <div>
          <span className="eyebrow">POLICY EXPOSURE REVIEW</span>
          <h3>
            {review.finding_count
              ? `${review.finding_count} potential review ${review.finding_count === 1 ? "item" : "items"}`
              : "No review items found"}
          </h3>
          <p>
            {review.reviewed_rule_count} rules reviewed against the current inventory
            {review.incomplete_rule_count
              ? ` · ${review.incomplete_rule_count} incomplete expansions`
              : ""}
          </p>
        </div>
        <Badge tone={review.counts.critical || review.counts.high ? "danger" : "success"}>
          {review.review_status}
        </Badge>
      </Card>
      <div className="security-summary-grid">
        {severities.map((severity) => (
          <Card className={`security-count ${severity}`} key={severity}>
            <strong>{review.counts[severity] ?? 0}</strong>
            <span>{severity}</span>
          </Card>
        ))}
      </div>
      <div className="notice-bar warning">
        <AlertTriangle />
        <span>
          <strong>Human review required.</strong> {review.notice}
        </span>
      </div>
      {review.findings.length ? (
        <div className="security-findings">
          {review.findings.map((finding: any) => (
            <Card className={`security-finding ${finding.severity}`} key={finding.id}>
              <div className="security-finding-head">
                <div>
                  <Badge tone={finding.severity === "critical" || finding.severity === "high" ? "danger" : "warning"}>
                    {finding.severity}
                  </Badge>
                  <span>{finding.category.replaceAll("_", " ")}</span>
                </div>
                <code>{finding.path}</code>
              </div>
              <h3>{finding.title}</h3>
              <p>{finding.evidence}</p>
              {finding.affected_pair_count != null && (
                <div className="security-impact">
                  <strong>{finding.affected_pair_count.toLocaleString()} device pairs</strong>
                  {finding.sample_sources.length > 0 && (
                    <small>Sources: {finding.sample_sources.join(", ")}</small>
                  )}
                  {finding.sample_destinations.length > 0 && (
                    <small>Destinations: {finding.sample_destinations.join(", ")}</small>
                  )}
                </div>
              )}
              <div className="security-recommendation">
                <ShieldCheck />
                <div>
                  <strong>Suggested review</strong>
                  <span>{finding.recommendation}</span>
                </div>
              </div>
              <small className="security-confidence">Confidence: {finding.confidence}</small>
            </Card>
          ))}
        </div>
      ) : (
        <Empty
          title="No heuristic findings"
          detail="No patterns covered by the current conservative review were detected. This is not a security guarantee."
        />
      )}
      <Card className="security-limitations">
        <CardHead title="Review limitations" detail="What this result cannot establish" />
        <ul>
          {review.limitations.map((limitation: string) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

function PolicyDuplicateReview({ query }: { query: any }) {
  if (query.isLoading) return <Loading />;
  if (query.error) return <ErrorState error={query.error} />;
  if (!query.data?.available) {
    return (
      <Empty
        title="Policy review unavailable"
        detail={query.data?.status ?? "No valid policy snapshot is available."}
      />
    );
  }
  const review = query.data;
  const download = () => {
    const url = URL.createObjectURL(
      new Blob([review.candidate], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `tailview-policy-candidate-${review.candidate_sha256.slice(0, 12)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="review-stack">
      <Card className="review-summary">
        <div>
          <span className="eyebrow">CONSERVATIVE REVIEW</span>
          <h3>
            {review.duplicate_count
              ? `${review.duplicate_count} exact duplicate${review.duplicate_count === 1 ? "" : "s"} found`
              : "No exact duplicates found"}
          </h3>
          <p>{review.review_scope}</p>
        </div>
        <Badge tone={review.changed ? "warning" : "success"}>
          {review.changed ? "Candidate available" : "Already minimal"}
        </Badge>
      </Card>
      <div className="notice-bar blue">
        <ShieldCheck />
        <span>
          <strong>Read-only by design.</strong> TailView never submits this
          candidate. Only canonically identical array entries are removed;
          unknown policy sections remain untouched.
        </span>
      </div>
      {review.changed && (
        <>
          <Card className="review-findings">
            <CardHead
              title="Proven duplicate entries"
              detail="Duplicate indexes are zero-based within each policy array."
            />
            <div className="finding-list">
              {review.findings
                .slice(0, 200)
                .map((finding: any, index: number) => (
                  <div
                    key={`${finding.path}-${finding.duplicate_index}-${index}`}
                  >
                    <CheckCircle2 />
                    <div>
                      <code>{finding.path}</code>
                      <strong>
                        Entry {finding.duplicate_index} duplicates entry {finding.first_index}
                      </strong>
                      <small>{finding.proof}</small>
                    </div>
                  </div>
                ))}
            </div>
          </Card>
          <Card className="code-card candidate-card">
            <div className="code-head">
              <span>
                Suggested strict JSON · {review.candidate_sha256.slice(0, 12)}…
              </span>
              <div>
                <Button variant="ghost" onClick={download}>
                  <Download /> Download
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(review.candidate)}
                >
                  <Copy /> Copy candidate
                </Button>
              </div>
            </div>
            <pre>{review.candidate}</pre>
          </Card>
          <div className="notice-bar warning">
            <AlertTriangle />
            <span>
              <strong>Validate before manual use.</strong> The candidate is valid
              HuJSON-compatible strict JSON, but comments and formatting from the
              original source are not retained. Upstream validation status: {review.validation}.
            </span>
          </div>
        </>
      )}
    </div>
  );
}

export function Services() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const [host, setHost] = useState(searchParams.get("host") ?? "");
  const [selected, setSelected] = useState<ServiceSummary | null>(null);
  const query = useInfiniteQuery({
    queryKey: ["services", search, statusFilter, host],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ search });
      if (statusFilter) params.set("status", statusFilter);
      if (host) params.set("host", host);
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<ServiceSummary>>(`/services?${params}`);
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
  });
  const rows = query.data?.pages.flatMap((page) => page.items) ?? [];
  const updateFilter = (key: string, value: string) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });
  };
  return (
    <div className="page">
      <PageHead eyebrow="TAILSCALE SERVICES" title="Services" description="Read-only Service inventory, hosting devices, endpoints, and policy references." />
      <div className="toolbar inventory-toolbar">
        <label className="search-field"><Search /><input value={search} placeholder="Search Services…" onChange={(event) => { setSearch(event.target.value); updateFilter("search", event.target.value); }} /></label>
        <select aria-label="Service status filter" value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); updateFilter("status", event.target.value); }}>
          <option value="">All statuses</option>
          {['connected', 'offline', 'pending_approval', 'draining', 'pre-approved', 'needs_configuration', 'unknown'].map((value) => <option value={value} key={value}>{value.replaceAll("_", " ")}</option>)}
        </select>
        <input aria-label="Service host filter" value={host} placeholder="Filter hosting device…" onChange={(event) => { setHost(event.target.value); updateFilter("host", event.target.value); }} />
      </div>
      {query.isLoading ? <Loading /> : query.error ? <ErrorState error={query.error} /> : !rows.length ? <Empty title="No Services available" detail="Synchronize the Services source or confirm that this tailnet uses Tailscale Services." /> : <>
        <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Service</th><th>Status</th><th>Addresses</th><th>Ports</th><th>Hosts</th><th>Provenance</th></tr></thead><tbody>
          {rows.map((service) => <tr key={service.id} className="clickable-row" onClick={() => setSelected(service)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelected(service); }}><td><strong>{service.name}</strong>{service.comment && <small className="block">{service.comment}</small>}</td><td><Badge tone={service.status === "connected" ? "success" : service.status === "offline" ? "danger" : "warning"}>{service.status.replaceAll("_", " ")}</Badge>{service.stale && <small className="block">Last-good / stale</small>}</td><td>{service.addresses?.join(", ") || "Not reported"}</td><td>{service.ports?.join(", ") || "Not reported"}</td><td>{service.host_count ?? 0}</td><td>{service.source}</td></tr>)}
        </tbody></table></div></Card>
        {query.hasNextPage && <Button variant="secondary" onClick={() => void query.fetchNextPage()} disabled={query.isFetchingNextPage}>{query.isFetchingNextPage ? "Loading…" : "Load more Services"}</Button>}
      </>}
      {selected && <ServiceDrawer service={selected} close={() => setSelected(null)} />}
    </div>
  );
}

function ServiceDrawer({ service, close }: { service: ServiceSummary; close: () => void }) {
  const serviceId = service.service_id ?? service.id.replace(/^service:/, "");
  const detail = useQuery({ queryKey: ["service", serviceId], queryFn: () => request<ServiceDetail>(`/services/${encodeURIComponent(serviceId)}`), enabled: service.status !== "policy_reference_only" });
  const value = detail.data;
  return <><div className="drawer-backdrop" aria-hidden="true" onClick={close} /><aside className="drawer" role="dialog" aria-modal="true" aria-label={`Service details for ${service.name}`}>
    <div className="drawer-head"><div className="large-node-icon"><GitCompareArrows /></div><div><span className="eyebrow">TAILSCALE SERVICE</span><h2>{service.name}</h2><Badge tone={(value?.status ?? service.status) === "connected" ? "success" : "warning"}>{value?.status ?? service.status}</Badge></div><button className="icon-button" onClick={close} aria-label="Close Service details"><X /></button></div>
    <div className="drawer-body">{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : service.status === "policy_reference_only" ? <Empty title="Policy reference only" detail="No matching Service inventory object has been synchronized." /> : value && <>
      {value.stale && <div className="notice-bar warning"><AlertTriangle /><span>This is the last successful snapshot; the current source is unavailable.</span></div>}
      <DetailGroup title="Service"><Detail label="Name" value={value.name} /><Detail label="Status" value={value.status} /><Detail label="Addresses" value={value.addresses.join(", ") || "Not reported"} /><Detail label="Tags" value={value.tags.join(", ") || "None"} /><Detail label="Ports" value={value.ports.join(", ") || "Not reported"} /><Detail label="Last synchronized" value={relativeTime(value.synced_at ?? null)} /></DetailGroup>
      <DetailGroup title="Hosting devices">{value.hosts.length ? value.hosts.map((host) => <Detail key={host.id} label={host.device_name ?? host.device_id ?? "Unknown host"} value={<span>{host.status} · advertised {String(host.advertised ?? "not reported")} · approved {String(host.approved ?? "not reported")}</span>} />) : <p>No hosts were reported.</p>}</DetailGroup>
      <DetailGroup title="Endpoints">{value.endpoints.length ? value.endpoints.map((endpoint) => <Detail key={endpoint.id} label={endpoint.type} value={`${endpoint.protocol}:${endpoint.port ?? "not reported"}`} />) : <p>No endpoints were reported.</p>}</DetailGroup>
      <DetailGroup title="Policy references"><Detail label="References" value={value.policy_references.length ? value.policy_references.map((reference) => `${reference.section}[${reference.rule_index}]`).join(", ") : "None in current normalized policy"} /><Detail label="Provenance" value={value.provenance} /></DetailGroup>
    </>}</div>
  </aside></>;
}

export function InventoryPage({ kind }: { kind: string }) {
  const [searchParams] = useSearchParams();
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
        <GenericTable
          rows={query.data.items}
          kind={kind}
          focusId={kind === "users" ? searchParams.get("user") : null}
        />
      )}
    </div>
  );
}
function GenericTable({
  rows,
  kind,
  focusId,
}: {
  rows: Record<string, any>[];
  kind: string;
  focusId: string | null;
}) {
  const hasHumanIdentity = Boolean(rows[0]?.display_name || rows[0]?.name || rows[0]?.device);
  const columns = kind === "sync" ? ["kind", "status", "started_at", "finished_at", "attempted", "succeeded", "failed", "details", "error"] : Object.keys(rows[0] ?? {})
    .filter((k) => !["old", "new", "raw"].includes(k))
    .filter((k) => !(hasHumanIdentity && ["id", "device_id"].includes(k)))
    .sort((left, right) => {
      const priority = ["display_name", "name", "device"];
      const leftRank = priority.includes(left) ? priority.indexOf(left) : priority.length;
      const rightRank = priority.includes(right) ? priority.indexOf(right) : priority.length;
      return leftRank - rightRank;
    })
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
              <tr
                key={String(row.id ?? row.name ?? i)}
                className={focusId === String(row.id) ? "focused-row" : undefined}
              >
                {columns.map((c) => (
                  <td key={c}>
                    {kind === "routes" && c === "device" && row.device_id ? (
                      <EntityLink label={String(row[c])} deviceId={row.device_id} />
                    ) : typeof row[c] === "object" && row[c] !== null ? (
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
  const dns = useQuery({
    queryKey: ["settings-dns"],
    queryFn: () => request<any>("/settings/dns"),
    enabled: user.role === "administrator",
  });
  const webhooks = useQuery({
    queryKey: ["settings-webhooks"],
    queryFn: () => request<any>("/settings/webhooks"),
    enabled: user.role === "administrator",
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
        {user.role === "administrator" && <>
          <Card className="settings-card">
            <CardHead title="DNS configuration" detail="Current read-only snapshot from the DNS API." />
            {dns.isLoading ? <Loading /> : dns.error ? <ErrorState error={dns.error} /> : !dns.data?.available ? <Empty title="DNS unavailable" detail={`Capability status: ${dns.data?.status ?? "unknown"}`} /> : <>
              {dns.data.stale && <Badge tone="warning">Last-good snapshot</Badge>}
              <Detail label="MagicDNS" value={String(dns.data.magic_dns ?? "not reported")} />
              <Detail label="Override local DNS" value={String(dns.data.override_local_dns ?? "not reported")} />
              <Detail label="Nameservers" value={dns.data.nameservers?.join(", ") || "None reported"} />
              <Detail label="Search paths" value={dns.data.search_paths?.join(", ") || "None reported"} />
            </>}
          </Card>
          <Card className="settings-card">
            <CardHead title="Webhook inventory" detail="Credentials and query values are removed before storage and display." />
            {webhooks.isLoading ? <Loading /> : webhooks.error ? <ErrorState error={webhooks.error} /> : !webhooks.data?.items?.length ? <Empty title="No webhooks available" detail={`Capability status: ${webhooks.data?.status ?? "unknown"}`} /> : webhooks.data.items.map((webhook: any) => <div className="setting-row" key={webhook.id}><div><strong>{webhook.url}</strong><p>{webhook.subscriptions.join(", ") || "No subscriptions reported"}</p></div><Badge tone={webhook.enabled === false ? "warning" : "success"}>{webhook.enabled === false ? "disabled" : webhook.enabled === true ? "enabled" : "not reported"}</Badge></div>)}
          </Card>
        </>}
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
function Detail({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function OwnerLink({ device }: { device: Device }) {
  if (!device.owner_id) return <span className="muted">Tagged identity</span>;
  const label =
    device.owner_display_name || device.owner_login_name || device.owner_id;
  return (
    <Link
      className="entity-link"
      to={`/users?user=${encodeURIComponent(device.owner_id)}`}
      onClick={(event) => event.stopPropagation()}
      title={device.owner_login_name || device.owner_id}
    >
      {label}
    </Link>
  );
}

function EntityLink({
  label,
  deviceId,
}: {
  label: string;
  deviceId?: string | null;
}) {
  if (!deviceId) return <span>{label}</span>;
  return (
    <Link
      className="entity-link"
      to={`/devices?device=${encodeURIComponent(deviceId)}`}
    >
      {label}
    </Link>
  );
}

function FlowEndpoint({
  label,
  deviceId,
  serviceId,
  raw,
}: {
  label: string;
  deviceId?: string | null;
  serviceId?: string | null;
  raw?: string | null;
}) {
  return (
    <span className="flow-entity">
      <strong>
        {serviceId ? <Link to={`/services?search=${encodeURIComponent(serviceId)}`}>{label}</Link> : <EntityLink label={label} deviceId={deviceId} />}
      </strong>
      {raw && raw !== label && <code>{raw}</code>}
    </span>
  );
}
const tooltipStyle = {
  background: "var(--surface-strong)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text)",
  fontSize: 12,
};
