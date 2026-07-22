import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import cytoscape from "cytoscape";
import {
  Activity,
  AlertTriangle,
  BellRing,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Clock3,
  CalendarClock,
  Copy,
  Download,
  Eye,
  Scan,
  GitCompareArrows,
  KeyRound,
  Laptop,
  List,
  LockKeyhole,
  Maximize2,
  Network,
  RefreshCw,
  FileChartColumn,
  Play,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  UserPlus,
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
import { SavedViews } from "./savedViews";
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
  AppSession,
  Device,
  DnsConfiguration,
  FlowRecord,
  FlowDeviceTraffic,
  FlowSummary,
  FindingRecord,
  FindingSummary,
  NetworkReport,
  ReportOptions,
  ReportSection,
  ReportScheduleRecord,
  SavedViewRecord,
  GovernanceCredential,
  GovernanceSummary,
  ObservedPhysicalEndpoint,
  Page,
  ServiceDetail,
  ServiceSummary,
  SecurityPostureSummary,
  TailViewAccount,
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
  const cards = dashboardMetricCards(d);
  return (
    <div className="page">
      <PageHead
        eyebrow="OPERATIONS"
        title="Tailnet overview"
        description="A concise view of inventory health, reported traffic, and access posture."
      />
      <div className="metric-grid">
        {cards.map(({ label, value, Icon, detail, href }, i) => (
          <Link
            key={label}
            className="metric-link"
            to={href}
            aria-label={`View ${label.toLowerCase()}`}
          >
            <Card className="metric-card">
              <div className={`metric-icon c${i}`}>
                <Icon />
              </div>
              <span>{label}</span>
              <strong>{value}</strong>
              <small>{detail}</small>
              <i className="metric-rule" />
            </Card>
          </Link>
        ))}
      </div>
      <div className="dashboard-grid">
        <Card className="findings-dashboard-card wide">
          <CardHead
            title="Latest network report"
            detail={d.latest_report ? `${new Date(d.latest_report.range_start).toLocaleDateString()} – ${new Date(d.latest_report.range_end).toLocaleDateString()}` : "No generated reports yet"}
            action={<Link to="/reports">Open reports <ChevronRight /></Link>}
          />
          {d.latest_report ? <div className="findings-dashboard-summary"><strong>{formatBytes(d.latest_report.reported_bytes)}</strong><span>reported volume</span><Badge tone={d.latest_report.coverage_complete ? "success" : "warning"}>{d.latest_report.coverage_complete ? "complete coverage" : "partial coverage"}</Badge></div> : <p className="muted">Administrators can generate repeatable reports from saved Flow views.</p>}
        </Card>
        <Card className="findings-dashboard-card wide">
          <CardHead
            title="Findings"
            detail="Durable security and operational signals"
            action={<Link to="/findings">Open workspace <ChevronRight /></Link>}
          />
          <div className="findings-dashboard-summary">
            <strong>{d.findings?.open ?? 0}</strong>
            <span>active</span>
            <Badge tone={(d.findings?.critical ?? 0) > 0 ? "danger" : "neutral"}>
              {d.findings?.critical ?? 0} critical
            </Badge>
            <Badge tone={(d.findings?.high ?? 0) > 0 ? "warning" : "neutral"}>
              {d.findings?.high ?? 0} high
            </Badge>
          </div>
        </Card>
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

type FindingsUser = { id: string; username: string; role: "administrator" | "viewer" };
type NotificationEndpointView = {
  id: string; name: string; url: string; minimum_severity: string; sources: string[];
  include_resolved: boolean; enabled: boolean; created_at: string; updated_at: string;
};
type NotificationDeliveryView = {
  id: string; endpoint_id: string; event_type: string; status: string;
  attempt_count: number; http_status: number | null; error_class: string;
  created_at: string; delivered_at: string | null;
};

export function Findings({ user }: { user: FindingsUser }) {
  const [params, setParams] = useSearchParams();
  const [selectedId, setSelectedId] = useState(params.get("finding") ?? "");
  const [tab, setTab] = useState<"findings" | "notifications">("findings");
  const [endpointForm, setEndpointForm] = useState({
    name: "", url: "", minimum_severity: "high", sources: "", include_resolved: false,
  });
  const [newSecret, setNewSecret] = useState("");
  const [suppressionDuration, setSuppressionDuration] = useState("24h");
  const queryClient = useQueryClient();
  const filterKeys = useMemo(
    () => ["status", "severity", "source", "category", "subject", "assigned_to", "search"] as const,
    [],
  );
  const filters = Object.fromEntries(filterKeys.map((key) => [key, params.get(key) ?? ""]));
  const findingViewState = useMemo(() => ({
    status: filters.status, severity: filters.severity, source: filters.source,
    category: filters.category, subject: filters.subject,
    assigned_to: filters.assigned_to, search: filters.search,
  }), [filters.assigned_to, filters.category, filters.search, filters.severity, filters.source, filters.status, filters.subject]);
  const applyFindingView = useCallback((state: Record<string, unknown>) => {
    setSelectedId("");
    setParams((current) => {
      const next = new URLSearchParams(current);
      filterKeys.forEach((key) => {
        const value = String(state[key] ?? "");
        if (value) next.set(key, value); else next.delete(key);
      });
      next.delete("finding");
      return next;
    });
  }, [filterKeys, setParams]);
  const findingHasExplicitState = filterKeys.some((key) => params.has(key));
  const setFilter = (key: string, value: string) => setParams((current) => {
    const next = new URLSearchParams(current);
    if (value) next.set(key, value); else next.delete(key);
    next.delete("finding");
    return next;
  });
  const queryString = new URLSearchParams(
    Object.entries(filters).filter(([, value]) => Boolean(value)),
  ).toString();
  const summary = useQuery({
    queryKey: ["findings-summary"],
    queryFn: () => request<FindingSummary>("/findings/summary"),
    refetchInterval: 60_000,
  });
  const findings = useInfiniteQuery({
    queryKey: ["findings", filters],
    queryFn: ({ pageParam }) => {
      const next = new URLSearchParams(queryString);
      if (pageParam) next.set("cursor", pageParam);
      return request<Page<FindingRecord>>(`/findings?${next}`);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const detail = useQuery({
    queryKey: ["finding", selectedId],
    queryFn: () => request<FindingRecord>(`/findings/${selectedId}`),
    enabled: Boolean(selectedId),
  });
  const endpoints = useQuery({
    queryKey: ["finding-endpoints"],
    queryFn: () => request<{ items: NotificationEndpointView[] }>("/findings/notification-endpoints"),
    enabled: user.role === "administrator" && tab === "notifications",
  });
  const deliveries = useQuery({
    queryKey: ["finding-deliveries"],
    queryFn: () => request<{ items: NotificationDeliveryView[] }>("/findings/notification-deliveries"),
    enabled: user.role === "administrator" && tab === "notifications",
  });
  const assignees = useQuery({
    queryKey: ["finding-assignees"],
    queryFn: () => request<{ items: Array<{ id: string; username: string; role: string }> }>("/findings/assignees"),
    enabled: user.role === "administrator",
  });
  const refresh = () => Promise.all([
    queryClient.invalidateQueries({ queryKey: ["findings"] }),
    queryClient.invalidateQueries({ queryKey: ["finding"] }),
    queryClient.invalidateQueries({ queryKey: ["findings-summary"] }),
  ]);
  const action = useMutation({
    mutationFn: ({ path, body }: { path: string; body: Record<string, unknown> }) =>
      request(`/findings/${selectedId}/${path}`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: refresh,
  });
  const createEndpoint = useMutation({
    mutationFn: () => request<{ signing_secret: string }>("/findings/notification-endpoints", {
      method: "POST",
      body: JSON.stringify({
        ...endpointForm,
        sources: endpointForm.sources.split(",").map((value) => value.trim()).filter(Boolean),
        enabled: true,
      }),
    }),
    onSuccess: (created) => {
      setNewSecret(created.signing_secret);
      setEndpointForm({ name: "", url: "", minimum_severity: "high", sources: "", include_resolved: false });
      queryClient.invalidateQueries({ queryKey: ["finding-endpoints"] });
    },
  });
  const endpointAction = useMutation({
    mutationFn: ({ id, operation }: { id: string; operation: "test" | "disable" }) =>
      request(`/findings/notification-endpoints/${id}${operation === "test" ? "/test" : ""}`, {
        method: operation === "test" ? "POST" : "DELETE",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["finding-endpoints"] });
      queryClient.invalidateQueries({ queryKey: ["finding-deliveries"] });
    },
  });
  const rows = findings.data?.pages.flatMap((page) => page.items) ?? [];
  if (summary.isLoading) return <Loading />;
  if (summary.error) return <ErrorState error={summary.error} />;
  const totals = summary.data!;
  const openFinding = (id: string) => {
    setSelectedId(id);
    setParams((current) => { const next = new URLSearchParams(current); next.set("finding", id); return next; });
  };
  const closeFinding = () => {
    setSelectedId("");
    setParams((current) => { const next = new URLSearchParams(current); next.delete("finding"); return next; });
  };
  const promptReason = (label: string) => window.prompt(`${label} reason (optional)`, "") ?? null;
  return <div className="page findings-page">
    <PageHead eyebrow="SECURITY & OPERATIONS" title="Findings" description="Durable signals with recurrence, acknowledgement, suppression, and resolution history." actions={<Badge tone={totals.open ? "warning" : "success"}>{totals.open} active</Badge>} />
    <SavedViews page="findings" state={findingViewState} builtIn={{ status: "", severity: "", source: "", category: "", subject: "", assigned_to: "", search: "" }} apply={applyFindingView} hasExplicitState={findingHasExplicitState} />
    {user.role === "administrator" && <div className="tabs" role="tablist" aria-label="Findings workspace"><button className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>Findings</button><button className={tab === "notifications" ? "active" : ""} onClick={() => setTab("notifications")}>Notifications</button></div>}
    {tab === "findings" && <>
      <div className="posture-metrics findings-metrics">
        {(["open", "acknowledged", "suppressed", "resolved"] as const).map((status) => <Card className="posture-metric" key={status}><span>{status}</span><strong>{totals.by_status[status] ?? 0}</strong></Card>)}
        <Card className="posture-metric urgent"><span>Critical / high</span><strong>{(totals.by_severity.critical ?? 0) + (totals.by_severity.high ?? 0)}</strong></Card>
      </div>
      <div className="filters-bar governance-filters">
        <label className="search-field"><Search /><input aria-label="Search findings" placeholder="Search findings…" value={filters.search} onChange={(event) => setFilter("search", event.target.value)} /></label>
        <select aria-label="Finding status" value={filters.status} onChange={(event) => setFilter("status", event.target.value)}><option value="">All statuses</option>{["open", "acknowledged", "suppressed", "resolved"].map((value) => <option key={value}>{value}</option>)}</select>
        <select aria-label="Finding severity" value={filters.severity} onChange={(event) => setFilter("severity", event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((value) => <option key={value}>{value}</option>)}</select>
        <select aria-label="Finding source" value={filters.source} onChange={(event) => setFilter("source", event.target.value)}><option value="">All sources</option>{Object.keys(totals.by_source).map((value) => <option key={value}>{value}</option>)}</select>
        <input aria-label="Finding category" placeholder="Category" value={filters.category} onChange={(event) => setFilter("category", event.target.value)} />
        <input aria-label="Finding subject" placeholder="Subject" value={filters.subject} onChange={(event) => setFilter("subject", event.target.value)} />
        {user.role === "administrator" && <select aria-label="Finding assignment" value={filters.assigned_to} onChange={(event) => setFilter("assigned_to", event.target.value)}><option value="">All assignments</option><option value="unassigned">Unassigned</option>{assignees.data?.items.map((assignee) => <option key={assignee.id} value={assignee.id}>{assignee.username}</option>)}</select>}
      </div>
      <Card className="table-card">
        <div className="table-scroll"><table><thead><tr><th>Severity</th><th>Finding</th><th>Subject</th><th>Source</th><th>Status</th><th>Last seen</th><th>Recurrences</th></tr></thead><tbody>{rows.map((finding) => <tr key={finding.id} className="clickable-row" onClick={() => openFinding(finding.id)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") openFinding(finding.id); }}><td><Badge tone={finding.severity === "critical" || finding.severity === "high" ? "danger" : finding.severity === "medium" ? "warning" : "neutral"}>{finding.severity}</Badge></td><td><strong>{finding.title}</strong>{finding.stale && <small className="block">stale evaluation</small>}</td><td>{finding.subject_display}</td><td>{finding.source.replaceAll("_", " ")}</td><td><Badge tone={finding.status === "open" ? "warning" : finding.status === "resolved" ? "success" : "neutral"}>{finding.status}</Badge></td><td>{relativeTime(finding.last_seen)}</td><td>{finding.occurrence_count}</td></tr>)}</tbody></table></div>
        {!findings.isLoading && !rows.length && <Empty title="No findings" detail="No signals match these filters. Zero active findings is a meaningful healthy state." icon={<ShieldCheck />} />}
        {findings.hasNextPage && <div className="load-more"><Button variant="secondary" onClick={() => findings.fetchNextPage()} disabled={findings.isFetchingNextPage}>{findings.isFetchingNextPage ? "Loading…" : "Load more"}</Button></div>}
      </Card>
    </>}
    {tab === "notifications" && user.role === "administrator" && <div className="notification-grid">
      <Card className="notification-form-card"><CardHead title="Signed webhook" detail="Public HTTPS by default; secrets are shown once." />
        {newSecret && <div className="notice-bar warning"><AlertTriangle /><span>Copy this signing secret now: <code>{newSecret}</code></span></div>}
        <form className="settings-form" onSubmit={(event) => { event.preventDefault(); createEndpoint.mutate(); }}>
          <label>Name<input required value={endpointForm.name} onChange={(event) => setEndpointForm({ ...endpointForm, name: event.target.value })} /></label>
          <label>HTTPS URL<input required type="url" value={endpointForm.url} onChange={(event) => setEndpointForm({ ...endpointForm, url: event.target.value })} /></label>
          <label>Minimum severity<select value={endpointForm.minimum_severity} onChange={(event) => setEndpointForm({ ...endpointForm, minimum_severity: event.target.value })}>{["critical", "high", "medium", "low", "info"].map((value) => <option key={value}>{value}</option>)}</select></label>
          <label>Source filters (comma-separated)<input placeholder="policy, posture" value={endpointForm.sources} onChange={(event) => setEndpointForm({ ...endpointForm, sources: event.target.value })} /></label>
          <label className="checkbox"><input type="checkbox" checked={endpointForm.include_resolved} onChange={(event) => setEndpointForm({ ...endpointForm, include_resolved: event.target.checked })} /> Include resolved events</label>
          {createEndpoint.error && <ErrorState error={createEndpoint.error} />}
          <Button disabled={createEndpoint.isPending}>{createEndpoint.isPending ? "Validating…" : "Create endpoint"}</Button>
        </form>
      </Card>
      <Card className="table-card"><CardHead title="Endpoints" detail="URLs are sanitized after storage." /><div className="compact-list">{endpoints.data?.items.map((endpoint) => <div key={endpoint.id}><span><strong>{endpoint.name}</strong><small className="block"><code>{endpoint.url}</code> · {endpoint.minimum_severity}+{endpoint.sources.length ? ` · ${endpoint.sources.join(", ")}` : ""}</small></span><Badge tone={endpoint.enabled ? "success" : "neutral"}>{endpoint.enabled ? "enabled" : "disabled"}</Badge><Button variant="ghost" onClick={() => endpointAction.mutate({ id: endpoint.id, operation: "test" })} disabled={!endpoint.enabled}>Test</Button>{endpoint.enabled && <Button variant="ghost" onClick={() => endpointAction.mutate({ id: endpoint.id, operation: "disable" })}>Disable</Button>}</div>)}</div>{!endpoints.isLoading && !endpoints.data?.items.length && <Empty title="No notification endpoints" detail="In-app findings remain available without outbound delivery." />}</Card>
      <Card className="table-card notification-history"><CardHead title="Delivery history" detail="Response bodies and credentials are never stored." /><div className="table-scroll"><table><thead><tr><th>Event</th><th>Status</th><th>Attempts</th><th>HTTP</th><th>Created</th></tr></thead><tbody>{deliveries.data?.items.map((delivery) => <tr key={delivery.id}><td>{delivery.event_type}</td><td><Badge tone={delivery.status === "delivered" ? "success" : delivery.status === "failed" ? "danger" : "neutral"}>{delivery.status}</Badge></td><td>{delivery.attempt_count}</td><td>{delivery.http_status ?? delivery.error_class ?? "—"}</td><td>{relativeTime(delivery.created_at)}</td></tr>)}</tbody></table></div></Card>
    </div>}
    {selectedId && <><button className="drawer-backdrop" aria-label="Close finding details" onClick={closeFinding} /><aside className="drawer finding-drawer" aria-label="Finding details">{detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : detail.data && <><div className="drawer-head"><div className="large-node-icon"><BellRing /></div><div><small>{detail.data.severity} finding</small><h2>{detail.data.title}</h2><Badge tone={detail.data.status === "open" ? "warning" : detail.data.status === "resolved" ? "success" : "neutral"}>{detail.data.status}</Badge></div><button className="icon-button" aria-label="Close" onClick={closeFinding}><X /></button></div><div className="drawer-body">
      <section className="detail-group"><h3>Summary</h3><p>{detail.data.summary}</p><div className="detail-row"><span>Subject</span><strong>{detail.data.subject_display}</strong></div><div className="detail-row"><span>Source</span><strong>{detail.data.source.replaceAll("_", " ")}</strong></div><div className="detail-row"><span>First / last seen</span><strong>{relativeTime(detail.data.first_seen)} / {relativeTime(detail.data.last_seen)}</strong></div>{detail.data.stale && <div className="notice-bar warning"><Clock3 /><span>The latest source evaluation was incomplete; this finding was retained as stale.</span></div>}</section>
      <section className="detail-group"><h3>Remediation</h3><p>{detail.data.remediation}</p>{detail.data.link_path && <Link to={detail.data.link_path}>Open related record <ChevronRight /></Link>}</section>
      <section className="detail-group"><h3>Safe evidence</h3><pre className="evidence-block">{JSON.stringify(detail.data.evidence, null, 2)}</pre></section>
      <section className="detail-group"><h3>Lifecycle</h3><div className="finding-timeline">{detail.data.transitions?.map((transition) => <div key={transition.id}><i /><span><strong>{transition.from_status ?? "created"} → {transition.to_status}</strong><small className="block">{relativeTime(transition.occurred_at)}{transition.reason ? ` · ${transition.reason}` : ""}</small></span></div>)}</div></section>
      {user.role === "administrator" && <section className="detail-group"><h3>Actions</h3><label className="assignment-field">Assignment<select aria-label="Assign finding" value={detail.data.assigned_to ?? ""} onChange={(event) => action.mutate({ path: "assign", body: { user_id: event.target.value || null } })}><option value="">Unassigned</option>{assignees.data?.items.map((assignee) => <option key={assignee.id} value={assignee.id}>{assignee.username}</option>)}</select></label><div className="finding-actions">{detail.data.status !== "resolved" && <Button variant="secondary" onClick={() => { const reason = promptReason("Acknowledge"); if (reason !== null) action.mutate({ path: "acknowledge", body: { reason } }); }}>Acknowledge</Button>}{detail.data.status === "resolved" && <Button variant="secondary" onClick={() => { const reason = promptReason("Reopen"); if (reason !== null) action.mutate({ path: "reopen", body: { reason } }); }}>Reopen</Button>}{detail.data.status === "suppressed" ? <Button variant="secondary" onClick={() => action.mutate({ path: "unsuppress", body: { reason: "Unsuppressed by administrator" } })}>Unsuppress</Button> : detail.data.status !== "resolved" && <><select aria-label="Suppression duration" value={suppressionDuration} onChange={(event) => setSuppressionDuration(event.target.value)}>{["1h", "24h", "7d", "30d", "indefinite"].map((duration) => <option key={duration} value={duration}>{duration === "indefinite" ? "Indefinitely" : duration}</option>)}</select><Button variant="secondary" onClick={() => { const reason = window.prompt("Suppression reason"); if (reason) action.mutate({ path: "suppress", body: { duration: suppressionDuration, reason } }); }}>Suppress</Button></>}</div>{action.error && <ErrorState error={action.error} />}</section>}
    </div></>}</aside></>}
  </div>;
}

export function dashboardMetricCards(d: Record<string, any>) {
  return [
    { label: "Total nodes", value: d.devices, Icon: Network, detail: "All registered devices", href: "/devices" },
    { label: "Online", value: d.online, Icon: Zap, detail: "API-reported state", href: "/devices?status=online" },
    { label: "Users", value: d.users, Icon: Users, detail: "Tailnet identities", href: "/users" },
    { label: "Expiring keys", value: d.expiring_keys, Icon: KeyRound, detail: "Within 14 days", href: "/devices?key_expiry=within_14_days" },
  ];
}

export function TrafficChart({
  data,
  height = 260,
}: {
  data: Array<{ bucket_start: string; reported_bytes: number }>;
  height?: number;
}) {
  const chartData = trafficChartData(data);
  return (
    <ResponsiveContainer width="100%" height={height}>
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

type GovernanceInvite = {
  id: string; device_id: string; device_name: string; inviter_name: string | null;
  recipient: string; status: string; created_at: string | null; expires_at: string | null;
  stale: boolean;
};
type GovernanceContact = {
  type: string; value: string; verified: boolean | null; stale: boolean; synced_at: string;
};
type GovernanceStream = {
  log_type: string; enabled: boolean | null; destination_type: string; destination: string;
  status: string; stale: boolean; synced_at: string;
};

export function AccessGovernance() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<"credentials" | "invites" | "contacts" | "streams">((searchParams.get("tab") as "credentials" | "invites" | "contacts" | "streams") ?? "credentials");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const [typeFilter, setTypeFilter] = useState(searchParams.get("credential_type") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const governanceViewState = useMemo(() => ({ tab, search, credential_type: typeFilter, status: statusFilter }), [search, statusFilter, tab, typeFilter]);
  const applyGovernanceView = useCallback((state: Record<string, unknown>) => {
    const nextTab = String(state.tab ?? "credentials") as "credentials" | "invites" | "contacts" | "streams";
    const values = { search: String(state.search ?? ""), credential_type: String(state.credential_type ?? ""), status: String(state.status ?? "") };
    setTab(nextTab); setSearch(values.search); setTypeFilter(values.credential_type); setStatusFilter(values.status);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (nextTab !== "credentials") next.set("tab", nextTab); else next.delete("tab");
      Object.entries(values).forEach(([key, value]) => { if (value) next.set(key, value); else next.delete(key); });
      return next;
    });
  }, [setSearchParams]);
  const governanceHasExplicitState = ["tab", "search", "credential_type", "status"].some((key) => searchParams.has(key));
  const setGovernanceFilter = (key: string, value: string) => setSearchParams((current) => {
    const next = new URLSearchParams(current); if (value) next.set(key, value); else next.delete(key); return next;
  });
  const summary = useQuery({
    queryKey: ["access-governance"],
    queryFn: () => request<GovernanceSummary>("/security/governance"),
  });
  const credentials = useInfiniteQuery({
    queryKey: ["governance-credentials", search, typeFilter, statusFilter],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (typeFilter) params.set("credential_type", typeFilter);
      if (statusFilter) params.set("status", statusFilter);
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<GovernanceCredential>>(`/security/governance/credentials?${params}`);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const invites = useQuery({
    queryKey: ["governance-invites"],
    queryFn: () => request<{ items: GovernanceInvite[] }>("/security/governance/invites"),
  });
  const contacts = useQuery({
    queryKey: ["governance-contacts"],
    queryFn: () => request<{ items: GovernanceContact[] }>("/security/governance/contacts"),
  });
  const streams = useQuery({
    queryKey: ["governance-streams"],
    queryFn: () => request<{ items: GovernanceStream[] }>("/security/governance/log-streaming"),
  });
  if (summary.isLoading) return <Loading />;
  if (summary.error) return <ErrorState error={summary.error} />;
  const data = summary.data!;
  const capabilityStatus = (name: string) => data.capabilities[name]?.status ?? "unknown";
  const credentialRows = credentials.data?.pages.flatMap((page) => page.items) ?? [];
  const metrics = [
    ["Credentials", data.counts.credentials], ["Active", data.counts.active_credentials],
    ["Expiring ≤30d", data.counts.expiring_credentials], ["Pending invites", data.counts.pending_invites],
    ["Verified contacts", data.counts.verified_contacts], ["Enabled streams", data.counts.enabled_streams],
  ];
  return <div className="page">
    <PageHead eyebrow="SECURITY" title="Access governance" description="Read-only credential, invitation, contact, and log-stream metadata. Secret values are never requested." actions={<Badge tone={data.findings.some((item) => item.severity === "high") ? "danger" : "success"}>{data.findings.length} findings</Badge>} />
    <SavedViews page="access_governance" state={governanceViewState} builtIn={{ tab: "credentials", search: "", credential_type: "", status: "" }} apply={applyGovernanceView} hasExplicitState={governanceHasExplicitState} />
    <div className="posture-metrics">{metrics.map(([label, value]) => <Card className="posture-metric" key={String(label)}><span>{label}</span><strong>{value}</strong></Card>)}</div>
    <div className="notice-bar warning"><AlertTriangle /><span>{data.limitations.join(" ")}</span></div>
    <Card className="table-card posture-findings">
      <CardHead title="Conservative findings" detail="Reported metadata requiring administrator review" />
      {data.findings.length ? <div className="security-findings governance-findings">{data.findings.map((finding) => <div className={`security-finding ${finding.severity}`} key={finding.id}><div className="security-finding-head"><div><Badge tone={finding.severity === "high" ? "danger" : "warning"}>{finding.severity}</Badge><span>{finding.kind.replaceAll("_", " ")}</span></div><code>{finding.label}</code></div><strong>{finding.message}</strong><p>{finding.remediation}</p></div>)}</div> : <Empty title="No governance findings" detail="No patterns covered by the conservative review were reported." />}
    </Card>
    <div className="tabs" role="tablist" aria-label="Governance inventory">{(["credentials", "invites", "contacts", "streams"] as const).map((value) => <button key={value} role="tab" aria-selected={tab === value} className={tab === value ? "active" : ""} onClick={() => { setTab(value); setGovernanceFilter("tab", value === "credentials" ? "" : value); }}>{value === "streams" ? "Log streaming" : value}</button>)}</div>
    {tab === "credentials" && <>
      <div className="filters-bar governance-filters">
        <label className="search-field"><Search /><input aria-label="Search credentials" placeholder="Search description, creator, scope…" value={search} onChange={(event) => { setSearch(event.target.value); setGovernanceFilter("search", event.target.value); }} /></label>
        <select aria-label="Credential type" value={typeFilter} onChange={(event) => { setTypeFilter(event.target.value); setGovernanceFilter("credential_type", event.target.value); }}><option value="">All types</option><option value="auth_key">Auth keys</option><option value="api_access_token">API access tokens</option><option value="oauth_credential">OAuth credentials</option><option value="federated_credential">Federated credentials</option></select>
        <select aria-label="Credential status" value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value); setGovernanceFilter("status", event.target.value); }}><option value="">All statuses</option><option value="active">Active</option><option value="expired">Expired</option><option value="revoked">Revoked</option><option value="stale">Stale</option><option value="inactive">Inactive</option></select>
      </div>
      <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Credential</th><th>Type</th><th>Status</th><th>Scopes / tags</th><th>Expires</th><th>Properties</th></tr></thead><tbody>{credentialRows.map((row) => <tr key={row.id}><td><strong>{row.description || "Unnamed credential"}</strong><small className="block"><code>{row.display_id}</code>{row.creator_id ? ` · ${row.creator_id}` : ""}</small></td><td>{row.type.replaceAll("_", " ")}</td><td><Badge tone={row.status === "active" ? "success" : row.status === "expired" || row.status === "revoked" ? "danger" : "warning"}>{row.status}</Badge></td><td><div className="tag-list">{[...row.scopes, ...row.tags].map((value) => <code key={value}>{value}</code>)}</div></td><td>{row.expires_at ? <><strong>{new Date(row.expires_at).toLocaleDateString()}</strong><small className="block">{relativeTime(row.expires_at)}</small></> : "Not reported"}</td><td><div className="tag-list">{row.reusable === true && <Badge tone="warning">reusable</Badge>}{row.ephemeral === true && <Badge>ephemeral</Badge>}{row.preapproved === true && <Badge>pre-approved</Badge>}</div></td></tr>)}</tbody></table></div>{!credentials.isLoading && !credentialRows.length && <Empty title="No credentials reported" detail={`Capability: ${capabilityStatus("credentials")}`} />}{credentials.hasNextPage && <div className="load-more"><Button variant="secondary" onClick={() => credentials.fetchNextPage()} disabled={credentials.isFetchingNextPage}>{credentials.isFetchingNextPage ? "Loading…" : "Load more"}</Button></div>}</Card>
    </>}
    {tab === "invites" && <GovernanceInvites rows={invites.data?.items ?? []} status={capabilityStatus("invites")} />}
    {tab === "contacts" && <GovernanceContacts rows={contacts.data?.items ?? []} status={capabilityStatus("contacts")} />}
    {tab === "streams" && <GovernanceStreams rows={streams.data?.items ?? []} status={capabilityStatus("log_streaming")} />}
    <Card className="security-limitations source-coverage-card"><CardHead title="Source coverage" detail="Each read surface synchronizes independently" /><div className="compact-list source-coverage-list">{Object.entries(data.capabilities).map(([name, capability]) => <div key={name}><span><strong>{name.replaceAll("_", " ")}</strong><small className="block">{capability.required_scope}</small></span><Badge tone={capability.status === "available" ? "success" : "warning"}>{capability.status.replaceAll("_", " ")}</Badge></div>)}</div></Card>
  </div>;
}

function GovernanceInvites({ rows, status }: { rows: GovernanceInvite[]; status: string }) {
  return <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Recipient</th><th>Device</th><th>Inviter</th><th>Status</th><th>Created</th><th>Expires</th></tr></thead><tbody>{rows.map((row) => <tr key={row.id}><td>{row.recipient || "Not reported"}</td><td><Link to={`/devices?device=${encodeURIComponent(row.device_id)}`}>{row.device_name}</Link></td><td>{row.inviter_name || "Not reported"}</td><td><Badge tone={row.status === "pending" ? "warning" : "neutral"}>{row.status}</Badge>{row.stale && <small className="block">stale snapshot</small>}</td><td>{row.created_at ? relativeTime(row.created_at) : "Not reported"}</td><td>{row.expires_at ? new Date(row.expires_at).toLocaleDateString() : "Not reported"}</td></tr>)}</tbody></table></div>{!rows.length && <Empty title="No device invites" detail={`Capability: ${status}`} />}</Card>;
}
function GovernanceContacts({ rows, status }: { rows: GovernanceContact[]; status: string }) {
  return <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Contact type</th><th>Value</th><th>Verification</th><th>Freshness</th></tr></thead><tbody>{rows.map((row) => <tr key={row.type}><td><strong>{row.type.replaceAll("_", " ")}</strong></td><td>{row.value || "Not reported"}</td><td><Badge tone={row.verified === true ? "success" : row.verified === false ? "warning" : "neutral"}>{row.verified === true ? "verified" : row.verified === false ? "unverified" : "not reported"}</Badge></td><td>{row.stale ? "Stale snapshot" : relativeTime(row.synced_at)}</td></tr>)}</tbody></table></div>{!rows.length && <Empty title="No contacts reported" detail={`Capability: ${status}`} />}</Card>;
}
function GovernanceStreams({ rows, status }: { rows: GovernanceStream[]; status: string }) {
  return <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Log type</th><th>Enabled</th><th>Status</th><th>Destination type</th><th>Sanitized destination</th><th>Freshness</th></tr></thead><tbody>{rows.map((row) => <tr key={row.log_type}><td><strong>{row.log_type}</strong></td><td><Badge tone={row.enabled === true ? "success" : "neutral"}>{row.enabled === true ? "enabled" : row.enabled === false ? "disabled" : "not reported"}</Badge></td><td>{row.status}</td><td>{row.destination_type}</td><td><code>{row.destination || "Not reported"}</code></td><td>{row.stale ? "Stale snapshot" : relativeTime(row.synced_at)}</td></tr>)}</tbody></table></div>{!rows.length && <Empty title="No log-stream configuration" detail={`Capability: ${status}`} />}</Card>;
}

export function SecurityPosture() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [resultFilter, setResultFilter] = useState(searchParams.get("result") ?? "");
  const [attributeFilter, setAttributeFilter] = useState(searchParams.get("attribute") ?? "");
  const [postureNameFilter, setPostureNameFilter] = useState(searchParams.get("posture") ?? "");
  const [ownerFilter, setOwnerFilter] = useState(searchParams.get("owner") ?? "");
  const [osFilter, setOsFilter] = useState(searchParams.get("os") ?? "");
  const [expiryFilter, setExpiryFilter] = useState(searchParams.get("expiry") ?? "");
  const [staleFilter, setStaleFilter] = useState(searchParams.get("stale") ?? "");
  const postureViewState = useMemo(() => ({
    result: resultFilter, posture: postureNameFilter, attribute: attributeFilter,
    owner: ownerFilter, os: osFilter, expiry: expiryFilter, stale: staleFilter,
  }), [attributeFilter, expiryFilter, osFilter, ownerFilter, postureNameFilter, resultFilter, staleFilter]);
  const applyPostureView = useCallback((state: Record<string, unknown>) => {
    const values = {
      result: String(state.result ?? ""), posture: String(state.posture ?? ""),
      attribute: String(state.attribute ?? ""), owner: String(state.owner ?? ""),
      os: String(state.os ?? ""), expiry: String(state.expiry ?? ""),
      stale: String(state.stale ?? ""),
    };
    setResultFilter(values.result); setPostureNameFilter(values.posture);
    setAttributeFilter(values.attribute); setOwnerFilter(values.owner);
    setOsFilter(values.os); setExpiryFilter(values.expiry); setStaleFilter(values.stale);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      Object.entries(values).forEach(([key, value]) => { if (value) next.set(key, value); else next.delete(key); });
      return next;
    });
  }, [setSearchParams]);
  const postureHasExplicitState = ["result", "posture", "attribute", "owner", "os", "expiry", "stale"].some((key) => searchParams.has(key));
  const updateFilter = (key: string, value: string) => {
    if (key === "result") setResultFilter(value);
    if (key === "attribute") setAttributeFilter(value);
    if (key === "posture") setPostureNameFilter(value);
    if (key === "owner") setOwnerFilter(value);
    if (key === "os") setOsFilter(value);
    if (key === "expiry") setExpiryFilter(value);
    if (key === "stale") setStaleFilter(value);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });
  };
  const summary = useQuery({
    queryKey: ["security-posture"],
    queryFn: () => request<SecurityPostureSummary>("/security/posture"),
  });
  const integrations = useQuery({
    queryKey: ["security-posture-integrations"],
    queryFn: () => request<{ items: Array<{ id: string; name: string; provider: string; status: string; synced_at: string }>; capability_status: string }>("/security/posture/integrations"),
  });
  const settings = useQuery({
    queryKey: ["security-settings"],
    queryFn: () => request<{ available: boolean; values: Record<string, unknown>; synced_at: string | null; capability_status: string }>("/security/settings"),
  });
  const deviceParams = new URLSearchParams();
  if (resultFilter) deviceParams.set("result", resultFilter);
  if (attributeFilter) deviceParams.set("attribute", attributeFilter);
  if (postureNameFilter) deviceParams.set("posture", postureNameFilter);
  if (ownerFilter) deviceParams.set("owner", ownerFilter);
  if (osFilter) deviceParams.set("os", osFilter);
  if (expiryFilter) deviceParams.set("expiry", expiryFilter);
  if (staleFilter) deviceParams.set("stale", staleFilter);
  const devices = useInfiniteQuery({
    queryKey: ["security-posture-devices", resultFilter, attributeFilter, postureNameFilter, ownerFilter, osFilter, expiryFilter, staleFilter],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(deviceParams);
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<Device>>(`/security/posture/devices?${params}`);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  if (summary.isLoading) return <Loading />;
  if (summary.error) return <ErrorState error={summary.error} />;
  const data = summary.data!;
  const rows = devices.data?.pages.flatMap((page) => page.items) ?? [];
  const metrics = [
    ["Passing", data.counts.pass],
    ["Failing", data.counts.fail],
    ["Incomplete", data.counts.incomplete],
    ["Stale", data.counts.stale],
    ["Pending approval", data.counts.pending_approval],
    ["Expiring attributes", data.counts.expiring_attributes],
  ];
  return (
    <div className="page">
      <PageHead
        eyebrow="SECURITY"
        title="Security posture"
        description="Current policy evaluated against typed, device-reported posture evidence."
        actions={<Badge tone={data.capability.status === "available" ? "success" : "warning"}>{data.capability.status.replaceAll("_", " ")}</Badge>}
      />
      <SavedViews page="security_posture" state={postureViewState} builtIn={{ result: "", posture: "", attribute: "", owner: "", os: "", expiry: "", stale: "" }} apply={applyPostureView} hasExplicitState={postureHasExplicitState} />
      <div className="posture-metrics">
        {metrics.map(([label, value]) => (
          <Card className="posture-metric" key={String(label)}>
            <span>{label}</span><strong>{value}</strong>
          </Card>
        ))}
      </div>
      <div className="notice-bar warning">
        <AlertTriangle />
        <span>{data.limitations.join(" ")}</span>
      </div>
      <div className="dashboard-grid posture-overview-grid">
        <Card className="chart-card">
          <CardHead title="Evidence coverage" detail={`${data.coverage.devices_with_fresh_evidence} of ${data.counts.devices} devices`} />
          <strong className="coverage-number">{data.coverage.percent}%</strong>
          <div className="coverage-bar"><i style={{ width: `${data.coverage.percent}%` }} /></div>
        </Card>
        <Card className="chart-card">
          <CardHead title="Attribute coverage" detail="Devices reporting each typed attribute" />
          <div className="compact-list">
            {data.attribute_coverage.slice(0, 8).map((item) => (
              <div key={item.key}><code>{item.key}</code><span>{item.device_count} · {item.percent}%</span></div>
            ))}
            {!data.attribute_coverage.length && <p className="muted">No posture attributes synchronized.</p>}
          </div>
        </Card>
        <Card className="chart-card">
          <CardHead title="Tailnet security settings" detail={settings.data?.synced_at ? `Synchronized ${relativeTime(settings.data.synced_at)}` : "Not synchronized"} />
          <div className="compact-list">
            {Object.entries(settings.data?.values ?? {}).map(([key, value]) => <div key={key}><code>{key}</code><strong>{String(value)}</strong></div>)}
            {!settings.data?.available && <p className="muted">Unavailable · {settings.data?.capability_status ?? "loading"}</p>}
          </div>
        </Card>
        <Card className="chart-card">
          <CardHead title="Posture integrations" detail={`Capability: ${integrations.data?.capability_status ?? "loading"}`} />
          <div className="compact-list">
            {integrations.data?.items.map((item) => <div key={item.id}><span><strong>{item.name}</strong><small className="block">{item.provider}</small></span><Badge>{item.status}</Badge></div>)}
            {integrations.data && !integrations.data.items.length && <p className="muted">No integrations reported.</p>}
          </div>
        </Card>
      </div>
      <Card className="table-card posture-findings">
        <CardHead title="Conservative findings" detail="Review signals, not vulnerability claims" />
        {data.findings.length ? (
          <div className="compact-list">
            {data.findings.slice(0, 20).map((finding, index) => (
              <Link to={`/devices?device=${encodeURIComponent(finding.device_id)}`} key={`${finding.kind}-${finding.device_id}-${index}`}>
                <Badge tone={finding.severity === "high" ? "danger" : "warning"}>{finding.severity}</Badge>
                <strong>{finding.device}</strong><span>{finding.message}</span>
              </Link>
            ))}
          </div>
        ) : <Empty title="No findings" detail="No conservative findings were produced from current evidence." />}
      </Card>
      <div className="toolbar inventory-toolbar">
        <select aria-label="Posture result filter" value={resultFilter} onChange={(event) => updateFilter("result", event.target.value)}>
          <option value="">All posture results</option>
          <option value="pass">Passing</option>
          <option value="fail">Failing</option>
          <option value="incomplete_data">Incomplete evidence</option>
          <option value="not_applicable">Not applicable</option>
        </select>
        <input aria-label="Posture attribute filter" placeholder="Filter attribute…" value={attributeFilter} onChange={(event) => updateFilter("attribute", event.target.value)} />
        <input aria-label="Posture name filter" placeholder="Filter posture…" value={postureNameFilter} onChange={(event) => updateFilter("posture", event.target.value)} />
        <input aria-label="Posture owner filter" placeholder="Filter owner…" value={ownerFilter} onChange={(event) => updateFilter("owner", event.target.value)} />
        <input aria-label="Posture OS filter" placeholder="Filter OS…" value={osFilter} onChange={(event) => updateFilter("os", event.target.value)} />
        <select aria-label="Attribute expiry filter" value={expiryFilter} onChange={(event) => updateFilter("expiry", event.target.value)}>
          <option value="">All attribute expiry states</option><option value="active">Active</option><option value="expiring">Expiring</option><option value="expired">Expired</option>
        </select>
        <select aria-label="Posture staleness filter" value={staleFilter} onChange={(event) => updateFilter("stale", event.target.value)}>
          <option value="">Fresh and stale</option><option value="true">Stale evidence</option><option value="false">Fresh evidence</option>
        </select>
      </div>
      {devices.isLoading ? <Loading /> : devices.error ? <ErrorState error={devices.error} /> : !rows.length ? (
        <Empty title="No matching devices" detail="Adjust posture filters or check synchronization." />
      ) : (
        <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Device</th><th>Owner</th><th>OS</th><th>Posture</th><th>Evidence</th><th>Attributes</th></tr></thead><tbody>
          {rows.map((device) => <tr key={device.id}><td><Link to={`/devices?device=${encodeURIComponent(device.id)}`}><strong>{device.name}</strong></Link></td><td><OwnerLink device={device} /></td><td>{device.os}</td><td><PostureBadge value={device.posture?.status ?? "incomplete_data"} /></td><td>{device.posture?.stale ? "Stale" : relativeTime(device.posture?.checked_at ?? null)}</td><td>{device.posture?.attributes.length ?? 0}</td></tr>)}
        </tbody></table></div></Card>
      )}
      {devices.hasNextPage && <Button variant="secondary" onClick={() => void devices.fetchNextPage()} disabled={devices.isFetchingNextPage}>{devices.isFetchingNextPage ? "Loading…" : "Load more devices"}</Button>}
    </div>
  );
}

function PostureBadge({ value }: { value: string }) {
  const tone = value === "pass" ? "success" : value === "fail" ? "danger" : value === "not_applicable" ? "neutral" : "warning";
  return <Badge tone={tone}>{value.replaceAll("_", " ")}</Badge>;
}

export function Devices({ role = "" }: { role?: string }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedDevice = searchParams.get("device");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const [owner, setOwner] = useState(searchParams.get("owner") ?? "");
  const [keyExpiryFilter, setKeyExpiryFilter] = useState(searchParams.get("key_expiry") ?? "");
  const [postureFilter, setPostureFilter] = useState(searchParams.get("posture") ?? "");
  const [showColumns, setShowColumns] = useState(false);
  const [columns, setColumns] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem("tailview.deviceColumns");
      return saved ? (JSON.parse(saved) as Record<string, boolean>) : {};
    } catch {
      return {};
    }
  });
  const builtInColumns = useRef(columns);
  const [selected, setSelected] = useState<Device | null>(null);
  const deviceViewPage = role === "exit_node" ? "exit_nodes" : role === "subnet_router" ? "subnet_routers" : "devices";
  const deviceViewState = useMemo(() => ({
    search, status: statusFilter, owner, key_expiry: keyExpiryFilter,
    posture: postureFilter, columns,
  }), [columns, keyExpiryFilter, owner, postureFilter, search, statusFilter]);
  const applyDeviceView = useCallback((state: Record<string, unknown>) => {
    const values = {
      search: String(state.search ?? ""), status: String(state.status ?? ""),
      owner: String(state.owner ?? ""), key_expiry: String(state.key_expiry ?? ""),
      posture: String(state.posture ?? ""),
    };
    setSearch(values.search); setStatusFilter(values.status); setOwner(values.owner);
    setKeyExpiryFilter(values.key_expiry); setPostureFilter(values.posture);
    setColumns((state.columns as Record<string, boolean> | undefined) ?? builtInColumns.current);
    setSelected(null);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      Object.entries(values).forEach(([key, value]) => { if (value) next.set(key, value); else next.delete(key); });
      next.delete("device");
      return next;
    });
  }, [setSearchParams]);
  const deviceHasExplicitState = ["search", "status", "owner", "key_expiry", "posture"].some((key) => searchParams.has(key));
  const deviceParams = useMemo(() => {
    const params = new URLSearchParams({ search, role });
    if (statusFilter) params.set("status", statusFilter);
    if (owner) params.set("owner", owner);
    if (keyExpiryFilter) params.set("key_expiry", keyExpiryFilter);
    if (postureFilter) params.set("posture_result", postureFilter);
    return params;
  }, [keyExpiryFilter, owner, postureFilter, role, search, statusFilter]);
  const query = useInfiniteQuery({
    queryKey: ["devices", search, role, statusFilter, owner, keyExpiryFilter, postureFilter],
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
  const setDeviceKeyExpiry = (value: string) => {
    setKeyExpiryFilter(value);
    updateParams({ key_expiry: value || null });
  };
  const setDevicePosture = (value: string) => {
    setPostureFilter(value);
    updateParams({ posture: value || null });
  };
  const toggleColumn = (column: string) => {
    const next = { ...columns, [column]: columns[column] === false };
    setColumns(next);
    if (!searchParams.get("view") || searchParams.get("view") === "builtin") {
      localStorage.setItem("tailview.deviceColumns", JSON.stringify(next));
      builtInColumns.current = next;
    }
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
      <SavedViews page={deviceViewPage} state={deviceViewState} builtIn={{ search: "", status: "", owner: "", key_expiry: "", posture: "", columns: builtInColumns.current }} apply={applyDeviceView} hasExplicitState={deviceHasExplicitState} />
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
          <select aria-label="Device posture filter" value={postureFilter} onChange={(event) => setDevicePosture(event.target.value)}>
            <option value="">All posture results</option>
            <option value="pass">Passing</option>
            <option value="fail">Failing</option>
            <option value="incomplete_data">Incomplete evidence</option>
            <option value="not_applicable">Not applicable</option>
          </select>
          <select
            aria-label="Device key expiry filter"
            value={keyExpiryFilter}
            onChange={(event) => setDeviceKeyExpiry(event.target.value)}
          >
            <option value="">All key expiry states</option>
            <option value="within_14_days">Expiring within 14 days</option>
            <option value="expired">Already expired</option>
            <option value="valid">Valid beyond 14 days</option>
            <option value="disabled">Expiry disabled</option>
            <option value="not_reported">Expiry not reported</option>
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
          {["status", "role", "owner", "os", "posture", "addresses", "key_expiry", "last_seen"].map((column) => (
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
              {columns.posture !== false && <th>Posture</th>}
              {columns.addresses !== false && <th>Addresses</th>}
              {columns.key_expiry !== false && <th>Key expiry</th>}
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
                {columns.posture !== false && <td>
                  <PostureBadge value={d.posture?.status ?? "incomplete_data"} />
                  {d.posture?.stale && <small className="block">Stale evidence</small>}
                </td>}
                {columns.addresses !== false && <td>
                  <code>{d.addresses[0] ?? "—"}</code>
                </td>}
                {columns.key_expiry !== false && <td><KeyExpiryCell value={d.key_expiry} disabled={d.key_expiry_disabled} /></td>}
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

export function keyExpiryState(
  value: string | null,
  disabled: boolean | null,
  now = Date.now(),
): "disabled" | "not_reported" | "expired" | "expiring" | "valid" {
  if (disabled === true) return "disabled";
  if (disabled !== false || !value) return "not_reported";
  const expiry = new Date(value).getTime();
  if (!Number.isFinite(expiry)) return "not_reported";
  if (expiry < now) return "expired";
  if (expiry <= now + 14 * 24 * 60 * 60 * 1000) return "expiring";
  return "valid";
}

function KeyExpiryCell({ value, disabled }: { value: string | null; disabled: boolean | null }) {
  const state = keyExpiryState(value, disabled);
  if (state === "disabled") {
    return <><Badge tone="success">Expiry disabled</Badge><small className="block">No active deadline</small></>;
  }
  if (state === "not_reported") return <span className="muted">Not reported</span>;
  const expiry = new Date(value!);
  const date = expiry.toLocaleDateString();
  if (state === "expired") {
    return <><Badge tone="danger">Expired</Badge><small className="block">{date}</small></>;
  }
  if (state === "expiring") {
    const days = Math.max(0, Math.ceil((expiry.getTime() - Date.now()) / 86_400_000));
    return <><Badge tone="warning">Expires in {days}d</Badge><small className="block">{date}</small></>;
  }
  return <><span>{date}</span><small className="block">Beyond 14 days</small></>;
}

export function Topology() {
  const { hours, range, setRange } = useTimeRange();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selected, setSelected] = useState<Device | ServiceSummary | null>(null);
  const [showPolicy, setShowPolicy] = useState(searchParams.get("permitted") === "true");
  const [showObserved, setShowObserved] = useState(searchParams.get("observed") === "true");
  const [layout, setLayout] = useState(searchParams.get("layout") ?? "cose");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const topologyViewState = useMemo(() => ({
    range, layout, search, observed: showObserved, permitted: showPolicy,
  }), [layout, range, search, showObserved, showPolicy]);
  const applyTopologyView = useCallback((state: Record<string, unknown>) => {
    const nextRange = String(state.range ?? "24h") as "1h" | "24h" | "7d" | "30d";
    const nextLayout = String(state.layout ?? "cose");
    const nextSearch = String(state.search ?? "");
    setRange(nextRange); setLayout(nextLayout); setSearch(nextSearch);
    setShowObserved(Boolean(state.observed)); setShowPolicy(Boolean(state.permitted));
    setSelected(null);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("range", nextRange); next.set("layout", nextLayout);
      if (nextSearch) next.set("search", nextSearch); else next.delete("search");
      if (state.observed) next.set("observed", "true"); else next.delete("observed");
      if (state.permitted) next.set("permitted", "true"); else next.delete("permitted");
      next.delete("node");
      return next;
    });
  }, [setRange, setSearchParams]);
  const topologyHasExplicitState = ["range", "layout", "search", "observed", "permitted"].some((key) => searchParams.has(key));
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
        <SavedViews page="topology" state={topologyViewState} builtIn={{ range: "24h", layout: "cose", search: "", observed: false, permitted: false }} apply={applyTopologyView} hasExplicitState={topologyHasExplicitState} />
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
        {["overview", "networking", "posture", "access", "flows", "history"].map((t) => (
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
              <Detail label="Authorization" value={d.authorized === null ? "Not reported" : d.authorized ? "Authorized" : "Pending approval / unauthorized"} />
              <Detail label="External/shared" value={d.inventory_details?.isExternal === undefined ? "Not reported" : d.inventory_details.isExternal ? "Yes" : "No"} />
              <Detail label="Update available" value={d.inventory_details?.updateAvailable === undefined ? "Not reported" : d.inventory_details.updateAvailable ? "Reported available" : "No update reported"} />
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
            <ConnectivityView connectivity={d.connectivity} />
          </>
        ) : tab === "posture" ? (
          <DevicePostureView posture={d.posture} />
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

function DevicePostureView({ posture }: { posture?: Device["posture"] }) {
  if (!posture) {
    return <Empty title="Posture not synchronized" detail="Run the posture source or check its capability state." />;
  }
  return (
    <>
      <div className={`notice-bar ${posture.stale ? "warning" : ""}`}>
        {posture.stale ? <AlertTriangle /> : <ShieldCheck />}
        <span>{posture.notice} Evidence checked {relativeTime(posture.checked_at)}.</span>
      </div>
      <DetailGroup title="Policy posture results">
        {!posture.evaluations.length ? <p className="muted">The current policy defines no posture rules.</p> : posture.evaluations.map((evaluation) => (
          <div className="posture-evaluation" key={evaluation.name}>
            <div><strong>{evaluation.name}</strong><PostureBadge value={evaluation.status} /></div>
            {evaluation.assertions.map((assertion) => (
              <div className="assertion-row" key={assertion.condition}>
                <code>{assertion.condition}</code>
                <PostureBadge value={assertion.status} />
                <small>Actual: {assertion.actual === null || assertion.actual === undefined ? "not present" : String(assertion.actual)}</small>
              </div>
            ))}
            {evaluation.policy_uses.map((usage) => (
              <small className="block" key={usage.policy_path}>{usage.policy_path} affects {usage.affected_destinations.join(", ") || "unspecified destinations"}</small>
            ))}
          </div>
        ))}
      </DetailGroup>
      <DetailGroup title="Typed attributes">
        {!posture.attributes.length ? <p className="muted">No attributes were reported.</p> : posture.attributes.map((attribute) => (
          <div className="attribute-row" key={attribute.key}>
            <span><code>{attribute.key}</code><small>{attribute.namespace} · {attribute.value_type}</small></span>
            <span><strong>{String(attribute.value)}</strong>{attribute.expiry && <small>{attribute.expiry_state} · {new Date(attribute.expiry).toLocaleString()}</small>}</span>
          </div>
        ))}
      </DetailGroup>
      <DetailGroup title="Policy access affected">
        {!posture.rule_impacts.length ? <p className="muted">No current access rule requires a posture.</p> : posture.rule_impacts.map((impact) => (
          <div className="posture-evaluation" key={impact.policy_path}>
            <div><code>{impact.policy_path}</code><PostureBadge value={impact.status} /></div>
            <small className="block">Any of: {impact.required_postures.join(", ")}</small>
            <small className="block">Destinations: {impact.affected_destinations.join(", ") || "not reported"}</small>
          </div>
        ))}
      </DetailGroup>
    </>
  );
}

function ConnectivityView({ connectivity }: { connectivity?: Device["connectivity"] }) {
  return (
    <DetailGroup title="Device-reported connectivity">
      {!connectivity || connectivity.status === "not_reported" ? (
        <p className="muted">Client connectivity was not supplied by the device API.</p>
      ) : (
        <>
          <div className="notice-bar warning"><AlertTriangle /><span>{connectivity.notice}</span></div>
          <Detail label="Retrieved" value={relativeTime(connectivity.retrieved_at)} />
          <Detail label="DERP" value={connectivity.derp || "Not reported"} />
          <Detail label="Mapping varies by destination" value={connectivity.mapping_varies_by_dest_ip === null || connectivity.mapping_varies_by_dest_ip === undefined ? "Not reported" : connectivity.mapping_varies_by_dest_ip ? "Yes" : "No"} />
          <div className="connectivity-values"><strong>Endpoints</strong><pre>{JSON.stringify(connectivity.endpoints ?? [], null, 2)}</pre></div>
          <div className="connectivity-values"><strong>Latency</strong><pre>{JSON.stringify(connectivity.latency ?? {}, null, 2)}</pre></div>
          <div className="connectivity-values"><strong>Client-supported features</strong><pre>{JSON.stringify(connectivity.client_supports ?? {}, null, 2)}</pre></div>
        </>
      )}
    </DetailGroup>
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
  const { hours, range, setRange } = useTimeRange();
  const [searchParams, setSearchParams] = useSearchParams();
  const [category, setCategory] = useState(searchParams.get("category") ?? "");
  const [source, setSource] = useState(searchParams.get("source") ?? "");
  const [destination, setDestination] = useState(searchParams.get("destination") ?? "");
  const [protocol, setProtocol] = useState(searchParams.get("protocol") ?? "");
  const [port, setPort] = useState(searchParams.get("port") ?? "");
  const [resolution, setResolution] = useState(searchParams.get("resolution") ?? "all");
  const [rankingLimit, setRankingLimit] = useState(10);
  const [showFilters, setShowFilters] = useState(
    Boolean(source || destination || protocol || port || resolution !== "all"),
  );
  const flowViewState = useMemo(() => ({
    range, category, source, destination, protocol, port, resolution,
    ranking_limit: rankingLimit,
  }), [category, destination, port, protocol, range, rankingLimit, resolution, source]);
  const applyFlowView = useCallback((state: Record<string, unknown>) => {
    const values = {
      category: String(state.category ?? ""), source: String(state.source ?? ""),
      destination: String(state.destination ?? ""), protocol: String(state.protocol ?? ""),
      port: String(state.port ?? ""), resolution: String(state.resolution ?? "all"),
    };
    const nextRange = String(state.range ?? "24h") as "1h" | "24h" | "7d" | "30d";
    setRange(nextRange); setCategory(values.category); setSource(values.source);
    setDestination(values.destination); setProtocol(values.protocol); setPort(values.port);
    setResolution(values.resolution); setRankingLimit(Number(state.ranking_limit ?? 10));
    setShowFilters(Boolean(values.source || values.destination || values.protocol || values.port || values.resolution !== "all"));
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("range", nextRange);
      Object.entries(values).forEach(([key, value]) => {
        if (value && value !== "all") next.set(key, value); else next.delete(key);
      });
      return next;
    });
  }, [setRange, setSearchParams]);
  const flowHasExplicitState = ["range", "category", "source", "destination", "protocol", "port", "resolution"].some((key) => searchParams.has(key));
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
      <SavedViews page="flows" state={flowViewState} builtIn={{ range: "24h", category: "", source: "", destination: "", protocol: "", port: "", resolution: "all", ranking_limit: 10 }} apply={applyFlowView} hasExplicitState={flowHasExplicitState} />
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
        <TrafficChart data={summary.data?.series ?? []} height={220} />
      </Card>
      <DeviceTrafficRanking
        devices={summary.data?.top_devices ?? []}
        limit={rankingLimit}
        setLimit={setRankingLimit}
        loading={summary.isLoading}
      />
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

export function DeviceTrafficRanking({
  devices,
  limit,
  setLimit,
  loading = false,
}: {
  devices: FlowDeviceTraffic[];
  limit: number;
  setLimit: (limit: number) => void;
  loading?: boolean;
}) {
  const visible = [...devices]
    .sort((left, right) => right.reported_bytes - left.reported_bytes)
    .slice(0, limit);
  const maximum = visible[0]?.reported_bytes ?? 0;
  return (
    <Card className="traffic-ranking-card">
      <CardHead
        title="Devices by reported traffic"
        detail="Resolved endpoint involvement across the selected range and active filters"
        action={
          <select
            aria-label="Number of traffic-ranked devices"
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
          >
            <option value={10}>Top 10</option>
            <option value={25}>Top 25</option>
            <option value={50}>Top 50</option>
          </select>
        }
      />
      {loading ? (
        <p className="muted">Loading device ranking…</p>
      ) : visible.length === 0 ? (
        <p className="muted">No resolved devices match this range and filter set.</p>
      ) : (
        <div className="traffic-ranking" role="list" aria-label="Devices ranked by traffic">
          {visible.map((device, index) => (
            <div key={device.device_id} role="listitem" className="traffic-ranking-row">
              <span className="rank">{String(index + 1).padStart(2, "0")}</span>
              <div className="traffic-ranking-identity">
                <EntityLink label={device.name} deviceId={device.device_id} />
                <small>{device.record_count.toLocaleString()} matching windows</small>
              </div>
              <span className="flow-line" aria-hidden="true">
                <i
                  style={{
                    width: `${maximum ? Math.max(3, (device.reported_bytes / maximum) * 100) : 0}%`,
                  }}
                />
              </span>
              <div className="traffic-ranking-volume">
                <strong>{formatBytes(device.reported_bytes)}</strong>
                <small>{device.reported_packets.toLocaleString()} packets</small>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="ranking-notice">
        Reported volume can overlap when both peers report the same connection. A flow involving
        two resolved devices contributes to each device’s involvement total.
      </p>
    </Card>
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
  const serviceViewState = useMemo(() => ({ search, status: statusFilter, host }), [host, search, statusFilter]);
  const applyServiceView = useCallback((state: Record<string, unknown>) => {
    const values = { search: String(state.search ?? ""), status: String(state.status ?? ""), host: String(state.host ?? "") };
    setSearch(values.search); setStatusFilter(values.status); setHost(values.host); setSelected(null);
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      Object.entries(values).forEach(([key, value]) => { if (value) next.set(key, value); else next.delete(key); });
      return next;
    });
  }, [setSearchParams]);
  const serviceHasExplicitState = ["search", "status", "host"].some((key) => searchParams.has(key));
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
      <SavedViews page="services" state={serviceViewState} builtIn={{ search: "", status: "", host: "" }} apply={applyServiceView} hasExplicitState={serviceHasExplicitState} />
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

function dnsValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "Not reported";
  if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
  if (typeof value === "string" || typeof value === "number") return String(value);
  return JSON.stringify(value);
}

export function dnsConfigurationEntries(
  value: Record<string, unknown> | undefined,
): Array<[string, unknown]> {
  if (!value) return [];
  return Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
}

function DnsConfigurationRows({ value }: { value: Record<string, unknown> }) {
  return (
    <div className="dns-config-rows">
      {dnsConfigurationEntries(value).map(([key, item]) => (
        <div className="dns-config-row" key={key}>
          <strong>{key.replaceAll("_", " ")}</strong>
          {item && typeof item === "object" && !Array.isArray(item) ? (
            <DnsConfigurationRows value={item as Record<string, unknown>} />
          ) : (
            <code>{Array.isArray(item) ? item.map(dnsValue).join(", ") : dnsValue(item)}</code>
          )}
        </div>
      ))}
    </div>
  );
}

function ReportedSetting({ label, value }: { label: string; value: boolean | null | undefined }) {
  const reported = value !== null && value !== undefined;
  return (
    <div className="setting-row">
      <div>
        <strong>{label}</strong>
        <p>Reported by the Tailscale DNS preferences API.</p>
      </div>
      <Badge tone={!reported ? "neutral" : value ? "success" : "warning"}>
        {!reported ? "Not reported" : value ? "Enabled" : "Disabled"}
      </Badge>
    </div>
  );
}

export function DnsSettings() {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: ["settings-dns"],
    queryFn: () => request<DnsConfiguration>("/settings/dns"),
  });
  const synchronize = useMutation({
    mutationFn: () => request("/sync/dns", { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings-dns"] }),
  });
  const dns = query.data;
  const splitEntries = dnsConfigurationEntries(dns?.split_dns);
  return (
    <div className="page">
      <PageHead
        eyebrow="TAILNET CONFIGURATION"
        title="DNS settings"
        description="Read-only DNS configuration synchronized from every documented Tailscale DNS read endpoint."
        actions={
          <Button
            variant="secondary"
            onClick={() => synchronize.mutate()}
            disabled={synchronize.isPending}
          >
            <RefreshCw size={16} /> {synchronize.isPending ? "Synchronizing…" : "Sync DNS"}
          </Button>
        }
      />
      {query.isLoading ? (
        <Loading />
      ) : query.error ? (
        <ErrorState error={query.error} />
      ) : !dns?.available ? (
        <Empty
          title="DNS configuration unavailable"
          detail={`Capability status: ${dns?.status?.replaceAll("_", " ") ?? "unknown"}. OAuth requires dns:read or all:read.`}
        />
      ) : (
        <>
          <Card className="settings-card dns-provenance">
            <div>
              <Badge tone={dns.stale ? "warning" : "success"}>
                {dns.stale ? "Last-good snapshot" : "Current snapshot"}
              </Badge>
              <p>
                Configuration only. DNS queries, answers, URLs, and per-device resolver state are not supplied by these management endpoints.
              </p>
            </div>
            <div>
              <Detail label="Source" value={dns.source || "Tailscale DNS API"} />
              <Detail label="Required scope" value={dns.required_scope || "dns:read"} />
              <Detail label="Synchronized" value={relativeTime(dns.synced_at ?? null)} />
              <Detail label="Capability checked" value={relativeTime(dns.checked_at)} />
            </div>
          </Card>
          {synchronize.error && <ErrorState error={synchronize.error} />}
          <div className="dns-grid">
            <Card className="settings-card">
              <CardHead title="Preferences" detail="Tailnet-wide resolver behavior." />
              <ReportedSetting label="MagicDNS" value={dns.magic_dns} />
              <ReportedSetting label="Override local DNS" value={dns.override_local_dns} />
            </Card>
            <Card className="settings-card">
              <CardHead title="Search domains" detail="Suffixes appended to non-fully-qualified names." />
              {dns.search_paths?.length ? (
                <div className="dns-chip-list">
                  {dns.search_paths.map((path) => <code key={path}>{path}</code>)}
                </div>
              ) : (
                <Empty title="No search domains" detail="None were reported by the API." />
              )}
            </Card>
            <Card className="settings-card full">
              <CardHead title="Nameservers" detail="Global and structured resolver entries exactly as reported." />
              {dns.nameservers?.length ? (
                <div className="dns-list">
                  {dns.nameservers.map((server, index) => (
                    <div className="dns-list-item" key={`${dnsValue(server)}-${index}`}>
                      <span>{index + 1}</span>
                      {server && typeof server === "object" && !Array.isArray(server) ? (
                        <DnsConfigurationRows value={server as Record<string, unknown>} />
                      ) : (
                        <code>{dnsValue(server)}</code>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <Empty title="No nameservers" detail="No custom nameservers were reported." />
              )}
            </Card>
            <Card className="settings-card full">
              <CardHead title="Split DNS" detail="Restricted domains and their resolver routing configuration." />
              {splitEntries.length ? (
                <DnsConfigurationRows value={dns.split_dns ?? {}} />
              ) : (
                <Empty title="No split DNS configuration" detail="No restricted-domain routes were reported." />
              )}
            </Card>
            <Card className="settings-card full">
              <CardHead title="API coverage" detail="The complete documented read surface used by TailView." />
              <div className="dns-endpoints">
                {[
                  ["Preferences", "GET …/dns/preferences"],
                  ["Nameservers", "GET …/dns/nameservers"],
                  ["Search paths", "GET …/dns/searchpaths"],
                  ["Split DNS", "GET …/dns/split-dns"],
                ].map(([label, endpoint]) => (
                  <div className="setting-row" key={endpoint}>
                    <strong>{label}</strong><code>{endpoint}</code>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

export function AccountSecurity({ user }: { user: { username: string; role: string; mfa_enabled: boolean; mfa_required: boolean } }) {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ["own-sessions"],
    queryFn: () => request<{ items: AppSession[] }>("/auth/sessions"),
  });
  const [passwords, setPasswords] = useState({ current: "", next: "" });
  const [mfaPassword, setMfaPassword] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const run = async (operation: () => Promise<unknown>, success: string) => {
    setError(""); setMessage("");
    try { await operation(); setMessage(success); await qc.invalidateQueries(); }
    catch (err) { setError(err instanceof Error ? err.message : "Request failed"); }
  };
  const changePassword = (event: React.FormEvent) => {
    event.preventDefault();
    void run(() => request("/auth/password", { method: "POST", body: JSON.stringify({ current_password: passwords.current, new_password: passwords.next }) }), "Password updated and other sessions revoked.");
    setPasswords({ current: "", next: "" });
  };
  const revoke = async (session: AppSession) => {
    if (!window.confirm(session.current ? "Revoke this session and sign out?" : "Revoke this session?")) return;
    const result = await request<{ logged_out: boolean }>(`/auth/sessions/${session.id}`, { method: "DELETE" });
    if (result.logged_out) window.location.assign("/");
    else await sessions.refetch();
  };
  const startMfa = (event: React.FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const result = await request<{ secret: string }>("/auth/mfa/enroll", { method: "POST", body: JSON.stringify({ password: mfaPassword }) });
      setMfaSecret(result.secret); setMfaPassword("");
    }, "Add the secret to your authenticator, then confirm a code.");
  };
  const confirmMfa = (event: React.FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const result = await request<{ recovery_codes: string[] }>("/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code: mfaCode }) });
      setRecoveryCodes(result.recovery_codes); setMfaCode(""); setMfaSecret("");
    }, "Multi-factor authentication enabled.");
  };
  const disableMfa = (event: React.FormEvent) => {
    event.preventDefault();
    if (!window.confirm("Disable multi-factor authentication for this account?")) return;
    void run(() => request("/auth/mfa/disable", { method: "POST", body: JSON.stringify({ password: mfaPassword }) }), "Multi-factor authentication disabled.");
    setMfaPassword("");
  };
  return <div className="page">
    <PageHead eyebrow="TAILVIEW ACCESS" title="Account security" description="Manage your local TailView password, multi-factor authentication, and signed-in sessions." />
    {(message || error) && <div className={`notice ${error ? "warning" : "success"}`}>{error || message}</div>}
    <div className="settings-grid">
      <Card className="settings-card">
        <CardHead title="Password" detail="Changing it revokes every other session." />
        <form className="stack-form" onSubmit={changePassword}>
          <label>Current password<input type="password" autoComplete="current-password" value={passwords.current} onChange={(e) => setPasswords({ ...passwords, current: e.target.value })} required /></label>
          <label>New password<input type="password" autoComplete="new-password" minLength={12} value={passwords.next} onChange={(e) => setPasswords({ ...passwords, next: e.target.value })} required /></label>
          <Button type="submit"><LockKeyhole /> Change password</Button>
        </form>
      </Card>
      <Card className="settings-card">
        <CardHead title="Multi-factor authentication" detail={user.mfa_required ? "Required for your role." : "Optional authenticator protection."} />
        <div className="setting-row"><strong>Status</strong><Badge tone={user.mfa_enabled ? "success" : user.mfa_required ? "warning" : "neutral"}>{user.mfa_enabled ? "Enabled" : "Not enabled"}</Badge></div>
        {!user.mfa_enabled && !mfaSecret && <form className="stack-form" onSubmit={startMfa}><label>Current password<input type="password" value={mfaPassword} onChange={(e) => setMfaPassword(e.target.value)} required /></label><Button type="submit"><ShieldCheck /> Enroll authenticator</Button></form>}
        {mfaSecret && <form className="stack-form" onSubmit={confirmMfa}><p>Add this secret to your authenticator:</p><code className="enrollment-secret">{mfaSecret}</code><label>Authenticator code<input autoComplete="one-time-code" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} required /></label><Button type="submit">Confirm enrollment</Button></form>}
        {user.mfa_enabled && <form className="stack-form" onSubmit={disableMfa}><label>Current password<input type="password" value={mfaPassword} onChange={(e) => setMfaPassword(e.target.value)} required /></label><Button className="danger" type="submit">Disable MFA</Button></form>}
        {user.mfa_enabled && <Button className="secondary" onClick={() => void run(async () => {
          const result = await request<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { method: "POST", body: JSON.stringify({ password: mfaPassword }) });
          setRecoveryCodes(result.recovery_codes); setMfaPassword("");
        }, "New recovery codes generated; previous codes are no longer valid.")}>Generate new recovery codes</Button>}
        {recoveryCodes.length > 0 && <div className="recovery-panel"><strong>Save these recovery codes now</strong><p>Each code works once and cannot be shown again.</p><div className="recovery-codes">{recoveryCodes.map((code) => <code key={code}>{code}</code>)}</div><Button className="secondary" onClick={() => setRecoveryCodes([])}>I saved them</Button></div>}
      </Card>
      <Card className="settings-card full">
        <CardHead title="Your sessions" detail="Source addresses and browser descriptions are security evidence, not identity claims." action={<Button className="secondary" onClick={() => void run(() => request("/auth/sessions/revoke-others", { method: "POST" }), "Other sessions revoked.")}>Revoke other sessions</Button>} />
        {sessions.isLoading ? <Loading /> : sessions.error ? <ErrorState error={sessions.error} /> : <div className="session-list">{sessions.data?.items.map((session) => <div className="session-row" key={session.id}><Laptop /><div><strong>{session.user_agent}</strong><p>{session.last_ip} · Last active {relativeTime(session.last_seen_at)}</p><small>Expires {new Date(session.expires_at).toLocaleString()}</small></div><div>{session.current && <Badge tone="success">Current</Badge>}{session.revoked_at ? <Badge tone="neutral">Revoked</Badge> : <Button className="ghost" onClick={() => void revoke(session)}>Revoke</Button>}</div></div>)}</div>}
      </Card>
    </div>
  </div>;
}

export function TailViewAccess() {
  const qc = useQueryClient();
  const [accountSearch, setAccountSearch] = useState("");
  const [sessionSearch, setSessionSearch] = useState("");
  const accounts = useInfiniteQuery({
    queryKey: ["app-users", accountSearch], initialPageParam: "",
    queryFn: ({ pageParam }) => request<Page<TailViewAccount>>(`/settings/app-users?search=${encodeURIComponent(accountSearch)}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const sessions = useInfiniteQuery({
    queryKey: ["app-sessions", sessionSearch], initialPageParam: "",
    queryFn: ({ pageParam }) => request<Page<AppSession>>(`/settings/app-sessions?active=true&search=${encodeURIComponent(sessionSearch)}${pageParam ? `&cursor=${encodeURIComponent(pageParam)}` : ""}`),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const policy = useQuery({ queryKey: ["auth-policy"], queryFn: () => request<{ required_roles: string[] }>("/settings/auth-policy") });
  const events = useQuery({ queryKey: ["auth-events"], queryFn: () => request<Page<any>>("/settings/auth-events?limit=25") });
  const [form, setForm] = useState({ username: "", display_name: "", role: "viewer", temporary_password: "" });
  const [error, setError] = useState("");
  const mutate = async (path: string, options: RequestInit, confirmation?: string) => {
    if (confirmation && !window.confirm(confirmation)) return;
    setError("");
    try { const result = await request<{ logged_out?: boolean }>(path, options); await qc.invalidateQueries(); if (result.logged_out) window.location.assign("/"); }
    catch (err) { setError(err instanceof Error ? err.message : "Request failed"); }
  };
  const createAccount = (event: React.FormEvent) => {
    event.preventDefault();
    void mutate("/settings/app-users", { method: "POST", body: JSON.stringify(form) }).then(() => setForm({ username: "", display_name: "", role: "viewer", temporary_password: "" }));
  };
  const resetPassword = (account: TailViewAccount) => {
    const password = window.prompt(`Enter a temporary password for ${account.username} (minimum 12 characters):`);
    if (password) void mutate(`/settings/app-users/${account.id}/reset-password`, { method: "POST", body: JSON.stringify({ temporary_password: password }) });
  };
  const required = policy.data?.required_roles ?? [];
  const accountItems = accounts.data?.pages.flatMap((page) => page.items) ?? [];
  const sessionItems = sessions.data?.pages.flatMap((page) => page.items) ?? [];
  const toggleRequiredRole = (role: string) => {
    const roles = required.includes(role) ? required.filter((item) => item !== role) : [...required, role];
    void mutate("/settings/auth-policy", { method: "PUT", body: JSON.stringify({ required_roles: roles }) }, "Changing MFA requirements may restrict active accounts until they enroll. Continue?");
  };
  return <div className="page">
    <PageHead eyebrow="ADMINISTRATION" title="TailView access" description="Manage local application accounts and sessions. These are separate from synchronized Tailscale users." />
    {error && <div className="notice warning">{error}</div>}
    <div className="settings-grid">
      <Card className="settings-card">
        <CardHead title="Create TailView account" detail="The temporary password must be replaced at first sign-in." />
        <form className="stack-form" onSubmit={createAccount}>
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required /></label>
          <label>Display name<input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></label>
          <label>Role<select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}><option value="viewer">Viewer</option><option value="administrator">Administrator</option></select></label>
          <label>Temporary password<input type="password" autoComplete="new-password" minLength={12} value={form.temporary_password} onChange={(e) => setForm({ ...form, temporary_password: e.target.value })} required /></label>
          <Button type="submit"><UserPlus /> Create account</Button>
        </form>
      </Card>
      <Card className="settings-card">
        <CardHead title="MFA policy" detail="Optional by default; require enrollment by TailView role." />
        {(["administrator", "viewer"] as const).map((role) => <label className="check-row" key={role}><input type="checkbox" checked={required.includes(role)} onChange={() => toggleRequiredRole(role)} /><span><strong>Require for {role}s</strong><small>Accounts without MFA enter restricted enrollment.</small></span></label>)}
      </Card>
      <Card className="settings-card full">
        <CardHead title="TailView accounts" detail="Deactivate accounts instead of deleting their audit identity." action={<input aria-label="Search TailView accounts" placeholder="Search accounts…" value={accountSearch} onChange={(e) => setAccountSearch(e.target.value)} />} />
        {accounts.isLoading ? <Loading /> : accounts.error ? <ErrorState error={accounts.error} /> : <><div className="table-scroll"><table><thead><tr><th>Account</th><th>Role</th><th>Status</th><th>MFA</th><th>Sessions</th><th>Last login</th><th>Actions</th></tr></thead><tbody>{accountItems.map((account) => <tr key={account.id}><td><strong>{account.display_name || account.username}</strong><small className="block">{account.username}</small>{account.must_change_password && <Badge tone="warning">Password change required</Badge>}</td><td><Badge tone={account.role === "administrator" ? "success" : "neutral"}>{account.role}</Badge></td><td><Badge tone={account.active ? "success" : "neutral"}>{account.active ? "Active" : "Inactive"}</Badge></td><td>{account.mfa_enabled ? "Enabled" : "Not enabled"}</td><td>{account.session_count}</td><td>{account.last_login_at ? relativeTime(account.last_login_at) : "Never"}</td><td><div className="table-actions"><Button className="ghost" onClick={() => void mutate(`/settings/app-users/${account.id}`, { method: "PATCH", body: JSON.stringify({ role: account.role === "administrator" ? "viewer" : "administrator" }) }, `Change ${account.username}'s role?`)}>Change role</Button><Button className="ghost" onClick={() => void mutate(`/settings/app-users/${account.id}`, { method: "PATCH", body: JSON.stringify({ active: !account.active }) }, `${account.active ? "Deactivate" : "Reactivate"} ${account.username}?`)}>{account.active ? "Deactivate" : "Reactivate"}</Button><Button className="ghost" onClick={() => resetPassword(account)}>Reset password</Button><Button className="ghost" onClick={() => void mutate(`/settings/app-users/${account.id}/revoke-sessions`, { method: "POST" }, `Revoke every session for ${account.username}?`)}>Revoke sessions</Button>{account.mfa_enabled && <Button className="ghost" onClick={() => void mutate(`/settings/app-users/${account.id}/reset-mfa`, { method: "POST" }, `Reset MFA for ${account.username}?`)}>Reset MFA</Button>}</div></td></tr>)}</tbody></table></div>{accounts.hasNextPage && <Button className="secondary" onClick={() => void accounts.fetchNextPage()}>Load more accounts</Button>}</>}
      </Card>
      <Card className="settings-card full"><CardHead title="Active sessions" detail="Revocation takes effect on the next request." action={<input aria-label="Search active sessions" placeholder="Search username…" value={sessionSearch} onChange={(e) => setSessionSearch(e.target.value)} />} />{sessions.isLoading ? <Loading /> : <><div className="session-list">{sessionItems.map((session) => <div className="session-row" key={session.id}><Laptop /><div><strong>{session.username}</strong><p>{session.user_agent}</p><small>{session.last_ip} · {relativeTime(session.last_seen_at)}</small></div><Button className="ghost" onClick={() => void mutate(`/settings/app-sessions/${session.id}`, { method: "DELETE" }, `Revoke ${session.username}'s session?`)}>Revoke</Button></div>)}</div>{sessions.hasNextPage && <Button className="secondary" onClick={() => void sessions.fetchNextPage()}>Load more sessions</Button>}</>}</Card>
      <Card className="settings-card full"><CardHead title="Local security history" detail="Immutable TailView authentication and administration events." />{events.isLoading ? <Loading /> : <div className="table-scroll"><table><thead><tr><th>Event</th><th>Result</th><th>Source</th><th>When</th><th>Correlation ID</th></tr></thead><tbody>{events.data?.items.map((event) => <tr key={event.id}><td>{event.event.replaceAll("_", " ")}</td><td><Badge tone={event.result === "success" ? "success" : "warning"}>{event.result}</Badge></td><td><code>{event.source_address}</code></td><td>{relativeTime(event.occurred_at)}</td><td><code>{event.correlation_id || "Not reported"}</code></td></tr>)}</tbody></table></div>}</Card>
    </div>
  </div>;
}

export function SettingsPage({ user }: { user: { role: string } }) {
  const query = useQuery({
    queryKey: ["capabilities"],
    queryFn: () => request<Page<any>>("/capabilities"),
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
            <CardHead title="TailView access" detail="Local application accounts, sessions, MFA policy, and security history." />
            <p className="settings-link-copy">TailView accounts are independent from synchronized tailnet users.</p>
            <Link className="button secondary" to="/settings/access">Manage TailView access</Link>
          </Card>
          <Card className="settings-card">
            <CardHead title="DNS configuration" detail="Preferences, resolvers, search domains, split DNS, and provenance." />
            <p className="settings-link-copy">The full read-only DNS inventory now has a dedicated administrator page.</p>
            <Link className="button secondary" to="/dns">Open DNS settings</Link>
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

type ReportsUser = { role: "administrator" | "viewer" };

const REPORT_SECTION_LABELS: Record<ReportSection, string> = {
  trends: "Traffic trend",
  devices: "Top devices",
  pairs: "Top device pairs",
  services: "Top Services",
  protocols: "Protocols",
  ports: "Destination ports",
  categories: "Traffic categories",
  resolution: "Resolution coverage",
  fleet_context: "Current fleet context",
};

const DEFAULT_REPORT_OPTIONS: ReportOptions = {
  description: "",
  ranking_limit: 10,
  include_previous_period: true,
  sections: Object.keys(REPORT_SECTION_LABELS) as ReportSection[],
};

function ReportOptionsFields({ value, onChange }: { value: ReportOptions; onChange: (value: ReportOptions) => void }) {
  const toggleSection = (section: ReportSection) => {
    const sections = value.sections.includes(section)
      ? value.sections.filter((item) => item !== section)
      : [...value.sections, section];
    if (sections.length) onChange({ ...value, sections });
  };
  return <fieldset className="report-options"><legend>Report contents</legend>
    <label className="report-description">Description<textarea maxLength={500} rows={2} value={value.description} onChange={(event) => onChange({ ...value, description: event.target.value })} placeholder="Optional context shown in the report" /></label>
    <label>Ranking size<select value={value.ranking_limit} onChange={(event) => onChange({ ...value, ranking_limit: Number(event.target.value) as 5 | 10 | 20 })}><option value={5}>Top 5</option><option value={10}>Top 10</option><option value={20}>Top 20</option></select></label>
    <label className="checkbox-label"><input type="checkbox" checked={value.include_previous_period} onChange={(event) => onChange({ ...value, include_previous_period: event.target.checked })} /> Compare with previous period</label>
    <div className="report-section-grid">{(Object.entries(REPORT_SECTION_LABELS) as Array<[ReportSection, string]>).map(([section, label]) => <label className="checkbox-label" key={section}><input type="checkbox" checked={value.sections.includes(section)} onChange={() => toggleSection(section)} /> {label}</label>)}</div>
  </fieldset>;
}

function comparisonLabel(value: any): string {
  if (!value || value.change_percent === null || value.change_percent === undefined) return "Previous period unavailable";
  const change = Number(value.change_percent);
  if (change === 0) return "No change";
  return `${Math.abs(change).toLocaleString()}% ${change > 0 ? "increase" : "decrease"}`;
}

export function Reports({ user }: { user: ReportsUser }) {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedId, setSelectedId] = useState(searchParams.get("report") ?? "");
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") ?? "");
  const [scheduleFilter, setScheduleFilter] = useState(searchParams.get("schedule") ?? "");
  const [viewFilter, setViewFilter] = useState(searchParams.get("saved_view") ?? "");
  const [dateFrom, setDateFrom] = useState(searchParams.get("from") ?? "");
  const [dateTo, setDateTo] = useState(searchParams.get("to") ?? "");
  const [tab, setTab] = useState<"reports" | "schedules">("reports");
  const [editingSchedule, setEditingSchedule] = useState<ReportScheduleRecord | null>(null);
  const [generateForm, setGenerateForm] = useState({ saved_view_id: "", range: "30d", title: "", report_options: { ...DEFAULT_REPORT_OPTIONS } });
  const [scheduleForm, setScheduleForm] = useState({
    name: "", saved_view_id: "", frequency: "weekly", timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    local_time: "08:00", weekday: 1, month_day: 1, enabled: true, report_options: { ...DEFAULT_REPORT_OPTIONS },
  });
  useEffect(() => {
    const next = new URLSearchParams();
    if (selectedId) next.set("report", selectedId);
    if (statusFilter) next.set("status", statusFilter);
    if (scheduleFilter) next.set("schedule", scheduleFilter);
    if (viewFilter) next.set("saved_view", viewFilter);
    if (dateFrom) next.set("from", dateFrom);
    if (dateTo) next.set("to", dateTo);
    setSearchParams(next, { replace: true });
  }, [selectedId, statusFilter, scheduleFilter, viewFilter, dateFrom, dateTo, setSearchParams]);
  const summary = useQuery({
    queryKey: ["reports-summary"],
    queryFn: () => request<{ counts: Record<string, number>; latest: (NetworkReport & { trend?: any[]; totals?: Record<string, number>; comparison?: Record<string, any> | null }) | null; aggregate_coverage: Record<string, { coverage_start: string | null; coverage_end: string | null; last_success: string | null; last_error: string; retention_days: number }> }>("/reports/summary"),
    refetchInterval: 30_000,
  });
  const reports = useInfiniteQuery({
    queryKey: ["reports", statusFilter, scheduleFilter, viewFilter, dateFrom, dateTo],
    initialPageParam: "",
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ limit: "50" });
      if (statusFilter) params.set("status", statusFilter);
      if (scheduleFilter) params.set("schedule_id", scheduleFilter);
      if (viewFilter) params.set("saved_view_id", viewFilter);
      if (dateFrom) params.set("date_from", new Date(`${dateFrom}T00:00:00`).toISOString());
      if (dateTo) params.set("date_to", new Date(`${dateTo}T23:59:59.999`).toISOString());
      if (pageParam) params.set("cursor", pageParam);
      return request<Page<NetworkReport>>(`/reports?${params}`);
    },
    getNextPageParam: (page) => page.next_cursor ?? undefined,
    refetchInterval: 30_000,
  });
  const detail = useQuery({
    queryKey: ["report", selectedId],
    queryFn: () => request<NetworkReport>(`/reports/${selectedId}`),
    enabled: Boolean(selectedId),
    refetchInterval: (query) => ["queued", "running"].includes((query.state.data as NetworkReport | undefined)?.status ?? "") ? 5_000 : false,
  });
  const schedules = useQuery({
    queryKey: ["report-schedules"],
    queryFn: () => request<{ items: ReportScheduleRecord[] }>("/report-schedules"),
    enabled: user.role === "administrator",
  });
  const savedViews = useQuery({
    queryKey: ["saved-views", "reporting"],
    queryFn: () => request<{ items: SavedViewRecord[] }>("/saved-views?page=flows"),
    enabled: user.role === "administrator",
  });
  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["reports"] }),
      queryClient.invalidateQueries({ queryKey: ["reports-summary"] }),
      queryClient.invalidateQueries({ queryKey: ["report-schedules"] }),
    ]);
  };
  const action = useMutation({
    mutationFn: ({ path, method = "POST", body }: { path: string; method?: string; body?: unknown }) => request(path, { method, body: body === undefined ? undefined : JSON.stringify(body) }),
    onSuccess: async (data: any, variables) => {
      if (variables.path.endsWith("/retry") && data?.id) setSelectedId(data.id);
      if (variables.path.startsWith("/report-schedules") && variables.method === "PUT") setEditingSchedule(null);
      await refresh();
    },
  });
  const reportRows = reports.data?.pages.flatMap((page) => page.items) ?? [];
  const report = detail.data;
  const snapshot = report?.snapshot as any;
  const reportOptions: ReportOptions = snapshot?.report_options ?? report?.report_options ?? DEFAULT_REPORT_OPTIONS;
  const submitGenerate = (event: React.FormEvent) => {
    event.preventDefault();
    action.mutate({ path: "/reports/generate", body: generateForm });
  };
  const submitSchedule = (event: React.FormEvent) => {
    event.preventDefault();
    action.mutate({
      path: editingSchedule ? `/report-schedules/${editingSchedule.id}` : "/report-schedules",
      method: editingSchedule ? "PUT" : "POST",
      body: scheduleForm,
    });
  };
  const editSchedule = (schedule: ReportScheduleRecord) => {
    setEditingSchedule(schedule);
    setScheduleForm({
      name: schedule.name,
      saved_view_id: schedule.saved_view_id ?? "",
      frequency: schedule.frequency,
      timezone: schedule.timezone,
      local_time: schedule.local_time,
      weekday: schedule.weekday ?? 1,
      month_day: schedule.month_day ?? 1,
      enabled: schedule.enabled,
      report_options: schedule.report_options,
    });
  };
  return <div className="page reports-page">
    <PageHead eyebrow="NETWORK REPORTING" title="Reports" description="Durable reported-traffic trends with authenticated PDF, JSON, and CSV evidence." actions={<Badge tone="success"><FileChartColumn /> 13-month history</Badge>} />
    <div className="report-summary-grid">
      <Card><span>Completed</span><strong>{(summary.data?.counts.completed ?? 0) + (summary.data?.counts.partial ?? 0)}</strong><small>Shared with signed-in users</small></Card>
      <Card><span>Queued / running</span><strong>{(summary.data?.counts.queued ?? 0) + (summary.data?.counts.running ?? 0)}</strong><small>Generated by the reporting worker</small></Card>
      <Card><span>Failed</span><strong>{summary.data?.counts.failed ?? 0}</strong><small>Administrators can retry</small></Card>
    </div>
    {summary.data?.latest && <Card className="report-latest-card">
      <CardHead title="Latest report trend" detail={`${new Date(summary.data.latest.range_start).toLocaleDateString()} – ${new Date(summary.data.latest.range_end).toLocaleDateString()}`} action={<Button variant="ghost" onClick={() => setSelectedId(summary.data!.latest!.id)}>Open report <ChevronRight /></Button>} />
      <div className="report-detail-metrics">
        <div><span>Reported volume</span><strong>{formatBytes(summary.data.latest.totals?.reported_bytes ?? 0)}</strong><small>{comparisonLabel(summary.data.latest.comparison?.reported_bytes)}</small></div>
        <div><span>Packets</span><strong>{Number(summary.data.latest.totals?.reported_packets ?? 0).toLocaleString()}</strong><small>{comparisonLabel(summary.data.latest.comparison?.reported_packets)}</small></div>
        <div><span>Flow records</span><strong>{Number(summary.data.latest.totals?.record_count ?? 0).toLocaleString()}</strong><small>{comparisonLabel(summary.data.latest.comparison?.record_count)}</small></div>
      </div>
      {(summary.data.latest.trend?.length ?? 0) > 0 && <ResponsiveContainer width="100%" height={240}><AreaChart data={summary.data.latest.trend}><CartesianGrid strokeDasharray="3 3" stroke="var(--border)" /><XAxis dataKey="bucket_start" tickFormatter={(value) => new Date(value).toLocaleDateString()} /><YAxis tickFormatter={(value) => formatBytes(value)} /><Tooltip formatter={(value) => formatBytes(Number(value))} /><Area type="monotone" dataKey="reported_bytes" stroke="#5be7c4" fill="#5be7c433" /></AreaChart></ResponsiveContainer>}
      <div className="aggregate-coverage-row">{Object.entries(summary.data.aggregate_coverage).map(([granularity, coverage]) => <div key={granularity}><Badge tone={coverage.last_error ? "warning" : "success"}>{granularity}</Badge><span>{coverage.coverage_start ? `${new Date(coverage.coverage_start).toLocaleDateString()} – ${new Date(coverage.coverage_end!).toLocaleDateString()}` : "Collection not started"}</span><small>{coverage.last_success ? `Updated ${relativeTime(coverage.last_success)} · ${coverage.retention_days}d retained` : coverage.last_error || "Waiting for aggregation"}</small></div>)}</div>
    </Card>}
    {user.role === "administrator" && <div className="tabs" role="tablist" aria-label="Report workspace"><button className={tab === "reports" ? "active" : ""} onClick={() => setTab("reports")}>Reports</button><button className={tab === "schedules" ? "active" : ""} onClick={() => setTab("schedules")}>Schedules</button></div>}
    {tab === "reports" ? <>
      {user.role === "administrator" && <Card className="report-builder"><CardHead title="Generate network report" detail="The current revision of the selected saved Flow view supplies the filters." /><form onSubmit={submitGenerate} className="report-form">
        <label>Saved Flow view<select aria-label="Report saved Flow view" value={generateForm.saved_view_id} onChange={(event) => setGenerateForm({ ...generateForm, saved_view_id: event.target.value })} required><option value="">Select a view…</option>{(savedViews.data?.items ?? []).filter((view) => view.compatible).map((view) => <option value={view.id} key={view.id}>{view.name} · {view.owner.username}</option>)}</select></label>
        <label>Range<select value={generateForm.range} onChange={(event) => setGenerateForm({ ...generateForm, range: event.target.value })}><option value="24h">24 hours</option><option value="7d">7 days</option><option value="30d">30 days</option><option value="90d">90 days</option><option value="13mo">13 months</option></select></label>
        <label>Title<input value={generateForm.title} placeholder="Optional report title" maxLength={255} onChange={(event) => setGenerateForm({ ...generateForm, title: event.target.value })} /></label>
        <ReportOptionsFields value={generateForm.report_options} onChange={(report_options) => setGenerateForm({ ...generateForm, report_options })} />
        <Button type="submit" disabled={!generateForm.saved_view_id || action.isPending}><Play /> Queue report</Button>
      </form>{action.error && <p className="form-error">{action.error.message}</p>}</Card>}
      <div className="report-list-head"><h2>Report history</h2><div className="report-history-filters"><select aria-label="Report status" value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="">All statuses</option>{["queued", "running", "completed", "partial", "failed"].map((value) => <option value={value} key={value}>{value}</option>)}</select>{user.role === "administrator" && <><select aria-label="Report schedule filter" value={scheduleFilter} onChange={(event) => setScheduleFilter(event.target.value)}><option value="">All schedules</option>{schedules.data?.items.map((schedule) => <option value={schedule.id} key={schedule.id}>{schedule.name}</option>)}</select><select aria-label="Report saved view filter" value={viewFilter} onChange={(event) => setViewFilter(event.target.value)}><option value="">All saved views</option>{savedViews.data?.items.map((view) => <option value={view.id} key={view.id}>{view.name}</option>)}</select></>}<label>From<input aria-label="Reports from date" type="date" value={dateFrom} onChange={(event) => setDateFrom(event.target.value)} /></label><label>To<input aria-label="Reports to date" type="date" value={dateTo} onChange={(event) => setDateTo(event.target.value)} /></label>{(statusFilter || scheduleFilter || viewFilter || dateFrom || dateTo) && <Button variant="ghost" onClick={() => { setStatusFilter(""); setScheduleFilter(""); setViewFilter(""); setDateFrom(""); setDateTo(""); }}>Clear filters</Button>}</div></div>
      {reports.isLoading ? <Loading /> : reports.error ? <ErrorState error={reports.error} /> : reportRows.length === 0 ? <Empty title="No matching reports" detail={(statusFilter || scheduleFilter || viewFilter || dateFrom || dateTo) ? "Adjust the report filters to see other runs." : "An Administrator can generate a report from a saved Flow view."} /> : <Card className="table-card"><div className="table-scroll"><table><thead><tr><th>Report</th><th>Range</th><th>Status</th><th>Coverage</th><th>Generated</th><th>Formats</th></tr></thead><tbody>{reportRows.map((row) => <tr key={row.id} className="clickable-row" onClick={() => setSelectedId(row.id)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") setSelectedId(row.id); }}><td><strong>{row.title}</strong><small className="block">{row.retry_of_id ? "Retry run" : row.saved_view_revision ? `Saved view revision ${row.saved_view_revision}` : "Saved view unavailable"}</small></td><td>{new Date(row.range_start).toLocaleDateString()} – {new Date(row.range_end).toLocaleDateString()}</td><td><Badge tone={row.status === "completed" ? "success" : row.status === "failed" ? "danger" : "warning"}>{row.status}</Badge>{["queued", "running"].includes(row.status) && <small className="block">{row.generation_stage} · {row.progress}%</small>}</td><td>{row.coverage.complete ? "Complete" : "Partial"}</td><td>{relativeTime(row.completed_at ?? row.created_at)}</td><td>{row.artifacts.map((artifact) => artifact.format.toUpperCase()).join(" · ") || "Pending"}</td></tr>)}</tbody></table></div>{reports.hasNextPage && <Button variant="secondary" onClick={() => void reports.fetchNextPage()}>Load more</Button>}</Card>}
    </> : <>
      <Card className="report-builder"><CardHead title={editingSchedule ? `Edit ${editingSchedule.name}` : "New report schedule"} detail="Daily, weekly, and monthly schedules use the selected IANA timezone." action={editingSchedule ? <Button variant="ghost" onClick={() => setEditingSchedule(null)}>Cancel edit</Button> : undefined} /><form onSubmit={submitSchedule} className="report-form schedule-form">
        <label>Name<input value={scheduleForm.name} maxLength={128} onChange={(event) => setScheduleForm({ ...scheduleForm, name: event.target.value })} required /></label>
        <label>Saved Flow view<select value={scheduleForm.saved_view_id} onChange={(event) => setScheduleForm({ ...scheduleForm, saved_view_id: event.target.value })} required><option value="">Select a view…</option>{(savedViews.data?.items ?? []).filter((view) => view.compatible).map((view) => <option value={view.id} key={view.id}>{view.name}</option>)}</select></label>
        <label>Frequency<select value={scheduleForm.frequency} onChange={(event) => setScheduleForm({ ...scheduleForm, frequency: event.target.value })}><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></label>
        <label>Timezone<input value={scheduleForm.timezone} onChange={(event) => setScheduleForm({ ...scheduleForm, timezone: event.target.value })} required /></label>
        <label>Time<input type="time" value={scheduleForm.local_time} onChange={(event) => setScheduleForm({ ...scheduleForm, local_time: event.target.value })} required /></label>
        {scheduleForm.frequency === "weekly" && <label>Weekday<select value={scheduleForm.weekday} onChange={(event) => setScheduleForm({ ...scheduleForm, weekday: Number(event.target.value) })}>{["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"].map((day, index) => <option value={index} key={day}>{day}</option>)}</select></label>}
        {scheduleForm.frequency === "monthly" && <label>Month day<input type="number" min={1} max={28} value={scheduleForm.month_day} onChange={(event) => setScheduleForm({ ...scheduleForm, month_day: Number(event.target.value) })} /></label>}
        <ReportOptionsFields value={scheduleForm.report_options} onChange={(report_options) => setScheduleForm({ ...scheduleForm, report_options })} />
        <Button type="submit" disabled={!scheduleForm.name || !scheduleForm.saved_view_id || action.isPending}><CalendarClock /> {editingSchedule ? "Save schedule" : "Create schedule"}</Button>
      </form>{action.error && <p className="form-error">{action.error.message}</p>}</Card>
      {!schedules.data?.items.length ? <Empty title="No report schedules" detail="Create a schedule to retain consistent daily, weekly, or monthly evidence." /> : <div className="schedule-list">{schedules.data?.items.map((schedule) => <Card key={schedule.id}><div className="schedule-main"><strong>{schedule.name}</strong><p>{schedule.frequency} at {schedule.local_time} · {schedule.timezone}</p><small>{schedule.last_error || (schedule.next_run_at ? `Next ${relativeTime(schedule.next_run_at)}` : "Paused")}</small><small className="block">Top {schedule.report_options.ranking_limit} · {schedule.report_options.sections.length} sections · {schedule.report_options.include_previous_period ? "comparison enabled" : "no comparison"}</small>{schedule.recent_runs?.length ? <div className="schedule-runs"><span>Recent runs</span>{schedule.recent_runs.map((run) => <button key={run.id} onClick={() => { setSelectedId(run.id); setTab("reports"); }}><Badge tone={run.status === "completed" ? "success" : run.status === "failed" ? "danger" : "warning"}>{run.status}</Badge>{relativeTime(run.completed_at ?? run.created_at)}</button>)}</div> : <small className="block">No runs yet</small>}</div><Badge tone={schedule.enabled ? "success" : "neutral"}>{schedule.enabled ? "enabled" : "paused"}</Badge><Button variant="ghost" onClick={() => editSchedule(schedule)}>Edit</Button><Button variant="ghost" onClick={() => action.mutate({ path: `/report-schedules/${schedule.id}/run` })}>Run now</Button><Button variant="ghost" onClick={() => action.mutate({ path: `/report-schedules/${schedule.id}`, method: "PUT", body: { name: schedule.name, saved_view_id: schedule.saved_view_id, frequency: schedule.frequency, timezone: schedule.timezone, local_time: schedule.local_time, weekday: schedule.weekday, month_day: schedule.month_day, enabled: !schedule.enabled, report_options: schedule.report_options } })}>{schedule.enabled ? "Pause" : "Resume"}</Button><Button variant="ghost" onClick={() => { if (window.confirm(`Delete report schedule “${schedule.name}”?`)) action.mutate({ path: `/report-schedules/${schedule.id}`, method: "DELETE" }); }}>Delete</Button></Card>)}</div>}
    </>}
    {selectedId && <div className="drawer-backdrop" onMouseDown={() => setSelectedId("")}>
      <aside className="details-drawer report-drawer" onMouseDown={(event) => event.stopPropagation()} aria-label="Report details">
        <button className="drawer-close" aria-label="Close report" onClick={() => setSelectedId("")}><X /></button>
        {detail.isLoading ? <Loading /> : detail.error ? <ErrorState error={detail.error} /> : report ? <>
          <p className="eyebrow">NETWORK REPORT</p>
          <h2>{report.title}</h2>
          <Badge tone={report.status === "completed" ? "success" : report.status === "failed" ? "danger" : "warning"}>{report.status}</Badge>
          <Button variant="ghost" onClick={() => void navigator.clipboard.writeText(window.location.href)}><Copy /> Copy authenticated link</Button>
          {["queued", "running"].includes(report.status) && <div className="report-progress"><div><span>{report.generation_stage.replaceAll("_", " ")}</span><strong>{report.progress}%</strong></div><progress max={100} value={report.progress} /></div>}
          {report.error && <p className="form-error">{report.error}</p>}
          {snapshot && <>
            {snapshot.description && <p className="report-description-copy">{snapshot.description}</p>}
            <div className="report-detail-metrics">
              <div><span>Reported volume</span><strong>{formatBytes(snapshot.traffic.totals.reported_bytes)}</strong><small>{comparisonLabel(snapshot.comparison?.reported_bytes)}</small></div>
              <div><span>Packets</span><strong>{Number(snapshot.traffic.totals.reported_packets).toLocaleString()}</strong><small>{comparisonLabel(snapshot.comparison?.reported_packets)}</small></div>
              <div><span>Records</span><strong>{Number(snapshot.traffic.totals.record_count).toLocaleString()}</strong><small>{comparisonLabel(snapshot.comparison?.record_count)}</small></div>
            </div>
            <p className="reliability-notice">{snapshot.notice}</p>
            <div className={`coverage-detail ${snapshot.coverage.complete ? "complete" : "partial"}`}><strong>{snapshot.coverage.complete ? "Complete requested coverage" : "Partial requested coverage"}</strong><span>{snapshot.coverage.coverage_start ? `${new Date(snapshot.coverage.coverage_start).toLocaleString()} – ${new Date(snapshot.coverage.coverage_end).toLocaleString()}` : "Aggregate collection has not covered this period."}</span><small>{snapshot.coverage.granularity} data · hourly {snapshot.retention?.hourly_days}d / daily {snapshot.retention?.daily_days}d retained</small></div>
            {reportOptions.sections.includes("trends") && snapshot.traffic.series.length > 0 && <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={snapshot.traffic.series}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="bucket_start" tickFormatter={(value) => new Date(value).toLocaleDateString()} />
                <YAxis tickFormatter={(value) => formatBytes(value)} />
                <Tooltip formatter={(value) => formatBytes(Number(value))} />
                <Area type="monotone" dataKey="reported_bytes" stroke="#5be7c4" fill="#5be7c433" />
              </AreaChart>
            </ResponsiveContainer>}
            {reportOptions.sections.includes("devices") && <><h3>Top devices</h3>{snapshot.traffic.top_devices.map((item: any) => <div className="report-rank" key={item.id}><span>{item.name}</span><strong>{formatBytes(item.reported_bytes)}</strong></div>)}</>}
            {reportOptions.sections.includes("pairs") && <><h3>Top device pairs</h3>{snapshot.traffic.top_pairs.map((item: any) => <div className="report-rank" key={item.id}><span>{item.name}</span><strong>{formatBytes(item.reported_bytes)}</strong></div>)}</>}
            {reportOptions.sections.includes("services") && <><h3>Top Services</h3>{snapshot.traffic.top_services.length ? snapshot.traffic.top_services.map((item: any) => <div className="report-rank" key={item.id}><span>{item.name}</span><strong>{formatBytes(item.reported_bytes)}</strong></div>) : <p className="muted">No traffic was attributed to a Service.</p>}</>}
            <div className="report-distribution-grid">{(["protocols", "ports", "categories", "resolution"] as const).map((key) => reportOptions.sections.includes(key) && <Card key={key}><h3>{REPORT_SECTION_LABELS[key]}</h3>{snapshot.traffic.distributions[key].map((item: any) => <div className="report-rank" key={item.id}><span>{item.name}</span><strong>{formatBytes(item.reported_bytes)}</strong></div>)}</Card>)}</div>
            {reportOptions.sections.includes("fleet_context") && <><h3>Current fleet context</h3><div className="fleet-context-grid">{["devices", "online", "users", "routes", "services"].map((key) => <div key={key}><span>{key}</span><strong>{Number(snapshot.fleet[key]).toLocaleString()}</strong></div>)}</div><small className="block">{snapshot.fleet.basis} · latest source synchronization {snapshot.fleet.last_synchronization ? relativeTime(snapshot.fleet.last_synchronization) : "not available"}</small></>}
            <DetailGroup title="Reproducibility"><Detail label="Snapshot schema" value={`Version ${report.snapshot_schema_version}`} /><Detail label="Saved view revision" value={report.saved_view_revision ? String(report.saved_view_revision) : "Unavailable"} /><Detail label="Evidence SHA-256" value={<code>{snapshot.evidence_sha256 || "Not recorded for schema v1"}</code>} /><Detail label="Selected sections" value={reportOptions.sections.map((section: ReportSection) => REPORT_SECTION_LABELS[section]).join(", ")} /></DetailGroup>
          </>}
          <div className="report-downloads">{report.artifacts.map((artifact) => <a className="button secondary" href={`/api/v1/reports/${report.id}/download?format=${artifact.format}`} key={artifact.format}><Download /> {artifact.format.toUpperCase()} <small>{formatBytes(artifact.size)} · {artifact.content_hash.slice(0, 12)}…</small></a>)}</div>
          {user.role === "administrator" && report.status === "failed" && <Button onClick={() => action.mutate({ path: `/reports/${report.id}/retry` })}><RefreshCw /> Retry report</Button>}
        </> : null}
      </aside>
    </div>}
  </div>;
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
