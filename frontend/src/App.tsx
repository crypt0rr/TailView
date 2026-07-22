import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  Activity,
  Boxes,
  ChevronRight,
  CircleUserRound,
  FileKey2,
  Gauge,
  GitBranch,
  Globe2,
  LayoutDashboard,
  KeyRound,
  LogOut,
  Menu,
  Moon,
  Network,
  PanelLeftClose,
  RefreshCw,
  Route as RouteIcon,
  Search,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
  Tags,
  Users,
  X,
} from "lucide-react";
import { api, ApiError, request } from "./api";
import { Button, Loading } from "./components";
import { useTimeRange } from "./timeRange";
import {
  Dashboard,
  Devices,
  DnsSettings,
  Flows,
  InventoryPage,
  Policy,
  SettingsPage,
  Services,
  SecurityPosture,
  AccessGovernance,
  Topology,
} from "./pages";

type CurrentUser = {
  id: string;
  username: string;
  role: "administrator" | "viewer";
};
export const nav = [
  ["Dashboard", "/", LayoutDashboard],
  ["Topology", "/topology", Network],
  ["Flows", "/flows", Activity],
  ["Devices", "/devices", Server],
  ["Users", "/users", Users],
  ["Groups", "/groups", Boxes],
  ["Routes", "/routes", RouteIcon],
  ["Services", "/services", GitBranch],
  ["Exit nodes", "/exit-nodes", Gauge],
  ["Subnet routers", "/subnet-routers", Network],
  ["Tags", "/tags", Tags],
  ["Policy", "/policy", FileKey2],
  ["Security posture", "/security/posture", ShieldCheck],
  ["Access governance", "/security/governance", KeyRound],
  ["Audit", "/audit", Shield],
  ["Sync jobs", "/sync", RefreshCw],
  ["DNS", "/dns", Globe2],
  ["Settings", "/settings", Settings],
] as const;

type CapabilityResult = {
  name: string;
  status: string;
  requirement: string;
  detail: string;
  last_success: string | null;
};

type NavigationUsage = {
  count: number;
  evaluated: boolean;
  in_use: boolean;
  status: "active" | "not_configured";
  detail: string;
  checked_at: string | null;
};

const navigationCapabilities: Record<string, string> = {
  "/flows": "network_flow_logs",
  "/devices": "device_inventory",
  "/users": "user_inventory",
  "/groups": "policy",
  "/routes": "routes",
  "/services": "services",
  "/exit-nodes": "routes",
  "/subnet-routers": "routes",
  "/tags": "device_inventory",
  "/policy": "policy",
  "/security/posture": "device_posture",
  "/security/governance": "access_governance",
  "/audit": "configuration_audit_logs",
  "/dns": "dns",
};

const unavailableCapabilityStates = new Set([
  "permission_denied",
  "feature_disabled",
  "plan_unavailable",
  "unsupported",
]);

export function partitionNavigation(
  items: ReadonlyArray<(typeof nav)[number]>,
  capabilities: CapabilityResult[],
  usage: Record<string, NavigationUsage> = {},
) {
  const byName = new Map(capabilities.map((capability) => [capability.name, capability]));
  const active: Array<(typeof nav)[number]> = [];
  const inactive: Array<{ item: (typeof nav)[number]; capability: CapabilityResult }> = [];
  for (const item of items) {
    const capabilityName = navigationCapabilities[item[1]];
    const capability = capabilityName ? byName.get(capabilityName) : undefined;
    const usageResult = usage[item[1]];
    if (capability && unavailableCapabilityStates.has(capability.status)) {
      inactive.push({ item, capability });
    } else if (usageResult?.evaluated && !usageResult.in_use) {
      inactive.push({
        item,
        capability: {
          name: capabilityName ?? item[1],
          status: usageResult.status,
          requirement: "",
          detail: usageResult.detail,
          last_success: usageResult.checked_at,
        },
      });
    } else {
      active.push(item);
    }
  }
  return { active, inactive };
}

function Setup({ onDone }: { onDone: () => void }) {
  const [form, setForm] = useState({
    setup_token: "",
    username: "admin",
    password: "",
  });
  const [error, setError] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api.setup(form);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed");
    }
  };
  return (
    <AuthFrame
      title="Create your administrator"
      subtitle="Enter the one-time setup token from your environment. The token is invalid after this account is created."
    >
      <form onSubmit={submit} className="auth-form">
        <label>
          Setup token
          <input
            type="password"
            autoComplete="one-time-code"
            value={form.setup_token}
            onChange={(e) => setForm({ ...form, setup_token: e.target.value })}
            required
          />
        </label>
        <label>
          Username
          <input
            autoComplete="username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            minLength={3}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            minLength={12}
            required
          />
        </label>
        <p className="hint">
          Use at least 12 characters. TailView hashes passwords with Argon2id.
        </p>
        {error && <p className="form-error">{error}</p>}
        <Button type="submit">
          Create administrator <ChevronRight size={16} />
        </Button>
      </form>
    </AuthFrame>
  );
}
function Login({ onDone }: { onDone: () => void }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api.login(form);
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    }
  };
  return (
    <AuthFrame title="Welcome back" subtitle="Sign in to inspect your tailnet.">
      <form onSubmit={submit} className="auth-form">
        <label>
          Username
          <input
            autoFocus
            autoComplete="username"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autoComplete="current-password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />
        </label>
        {error && <p className="form-error">{error}</p>}
        <Button type="submit">
          Sign in <ChevronRight size={16} />
        </Button>
      </form>
    </AuthFrame>
  );
}
function AuthFrame({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <main className="auth-page">
      <div className="auth-art">
        <Logo />
        <div>
          <BadgeText />
          <h1>
            Your tailnet,
            <br />
            <em>made legible.</em>
          </h1>
          <p>
            Inventory, access policy, and observed traffic—kept distinct and
            explained.
          </p>
        </div>
        <small>Read-only by design · Self-hosted</small>
      </div>
      <section className="auth-panel">
        <div className="auth-card">
          <span className="eyebrow">TAILVIEW ACCESS</span>
          <h2>{title}</h2>
          <p>{subtitle}</p>
          {children}
        </div>
      </section>
    </main>
  );
}
function BadgeText() {
  return (
    <span className="signal">
      <i /> Tailnet observability
    </span>
  );
}
function Logo() {
  return (
    <div className="logo">
      <span>
        <i />
        <i />
        <i />
        <i />
      </span>
      <strong>TailView</strong>
    </div>
  );
}

export function Shell({
  user,
  onLogout,
}: {
  user: CurrentUser;
  onLogout: () => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [dark, setDark] = useState(() => localStorage.theme !== "light");
  const [showInactive, setShowInactive] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { range, setRange } = useTimeRange();
  const roleNav =
    user.role === "administrator"
      ? nav
      : nav.filter(([label]) => !["DNS", "Access governance"].includes(label));
  const capabilities = useQuery({
    queryKey: ["navigation-capabilities"],
    queryFn: () => request<{
      items: CapabilityResult[];
      navigation: Record<string, NavigationUsage>;
    }>("/capabilities"),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const partitionedNav = partitionNavigation(
    roleNav,
    capabilities.data?.items ?? [],
    capabilities.data?.navigation ?? {},
  );
  const visibleNav = partitionedNav.active;
  const inactiveOpen = showInactive
    || partitionedNav.inactive.some(({ item }) => item[1] === location.pathname);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.theme = dark ? "dark" : "light";
  }, [dark]);
  const logout = async () => {
    try {
      await api.logout();
    } catch (error) {
      // An expired/revoked session is already logged out from the server's
      // perspective, so it should still complete the local sign-out flow.
      if (!(error instanceof ApiError && error.status === 401)) throw error;
    }
    qc.clear();
    onLogout();
    navigate("/", { replace: true });
  };
  const active =
    nav.find(([, path]) => path === location.pathname)?.[0] ?? "TailView";
  return (
    <div className={`app-shell ${collapsed ? "collapsed" : ""}`}>
      <aside className={mobile ? "mobile-open" : ""}>
        <div className="aside-head">
          <Logo />
          <button
            className="icon-button desktop-only"
            onClick={() => setCollapsed(!collapsed)}
            aria-label="Toggle sidebar"
          >
            <PanelLeftClose />
          </button>
          <button
            className="icon-button mobile-only"
            onClick={() => setMobile(false)}
          >
            <X />
          </button>
        </div>
        <nav aria-label="Primary">
          {visibleNav.map(([label, path, Icon]) => (
            <button
              key={path}
              className={location.pathname === path ? "active" : ""}
              onClick={() => {
                navigate(path);
                setMobile(false);
              }}
              title={label}
            >
              <Icon />
              <span>{label}</span>
            </button>
          ))}
          {partitionedNav.inactive.length > 0 && (
            <div className="inactive-nav-section">
              <button
                type="button"
                className="inactive-nav-toggle"
                aria-expanded={inactiveOpen}
                onClick={() => setShowInactive((value) => !value)}
                title="Not in use"
              >
                <ChevronRight className={inactiveOpen ? "expanded" : ""} />
                <span>Not in use ({partitionedNav.inactive.length})</span>
              </button>
              {inactiveOpen && partitionedNav.inactive.map(({ item: [label, path, Icon], capability }) => (
                <button
                  key={path}
                  className={`inactive-nav-item ${location.pathname === path ? "active" : ""}`}
                  onClick={() => {
                    navigate(path);
                    setMobile(false);
                  }}
                  title={`${label}: ${capability.status.replaceAll("_", " ")}. ${capability.detail || capability.requirement}`}
                >
                  <Icon />
                  <span><strong>{label}</strong><small>{capability.status.replaceAll("_", " ")}</small></span>
                </button>
              ))}
            </div>
          )}
        </nav>
        <div className="aside-user">
          <CircleUserRound />
          <div>
            <strong>{user.username}</strong>
            <small>{user.role}</small>
          </div>
          <button onClick={logout} className="icon-button" title="Log out">
            <LogOut />
          </button>
        </div>
      </aside>
      {mobile && (
        <button
          className="scrim"
          onClick={() => setMobile(false)}
          aria-label="Close navigation"
        />
      )}
      <div className="workspace">
        <header>
          <button
            className="icon-button mobile-only"
            onClick={() => setMobile(true)}
          >
            <Menu />
          </button>
          <div>
            <span className="breadcrumb">TailView /</span>
            <strong>{active}</strong>
          </div>
          <div className="header-actions">
            <button
              className="search-button"
              onClick={() =>
                document.dispatchEvent(
                  new KeyboardEvent("keydown", { key: "k", metaKey: true }),
                )
              }
            >
              <Search />
              <span>Search</span>
              <kbd>⌘ K</kbd>
            </button>
            <select
              aria-label="Global time range"
              value={range}
              onChange={(event) =>
                setRange(event.target.value as "1h" | "24h" | "7d" | "30d")
              }
            >
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
              <option value="30d">Last 30 days</option>
            </select>
            <button
              className="icon-button"
              onClick={() => setDark(!dark)}
              aria-label="Toggle theme"
            >
              {dark ? <Sun /> : <Moon />}
            </button>
          </div>
        </header>
        <CommandPalette items={visibleNav} />
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/users" element={<InventoryPage kind="users" />} />
            <Route path="/groups" element={<InventoryPage kind="groups" />} />
            <Route path="/routes" element={<InventoryPage kind="routes" />} />
            <Route path="/services" element={<Services />} />
            <Route path="/exit-nodes" element={<Devices role="exit_node" />} />
            <Route
              path="/subnet-routers"
              element={<Devices role="subnet_router" />}
            />
            <Route path="/tags" element={<InventoryPage kind="tags" />} />
            <Route path="/policy" element={<Policy />} />
            <Route path="/security/posture" element={<SecurityPosture />} />
            <Route
              path="/security/governance"
              element={
                user.role === "administrator" ? (
                  <AccessGovernance />
                ) : (
                  <Navigate to="/" replace />
                )
              }
            />
            <Route path="/audit" element={<InventoryPage kind="audit" />} />
            <Route path="/sync" element={<InventoryPage kind="sync" />} />
            <Route
              path="/dns"
              element={
                user.role === "administrator" ? (
                  <DnsSettings />
                ) : (
                  <Navigate to="/" replace />
                )
              }
            />
            <Route path="/settings" element={<SettingsPage user={user} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
function CommandPalette({
  items,
}: {
  items: ReadonlyArray<(typeof nav)[number]>;
}) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((v) => !v);
      }
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, []);
  if (!open) return null;
  return (
    <div className="dialog-backdrop" onMouseDown={() => setOpen(false)}>
      <div
        className="command-dialog"
        onMouseDown={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div>
          <Search />
          <input autoFocus placeholder="Jump to a page…" />
        </div>
        {items.map(([label, path, Icon]) => (
          <button
            key={path}
            onClick={() => {
              navigate(path);
              setOpen(false);
            }}
          >
            <Icon />
            {label}
            <ChevronRight />
          </button>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [loggedOut, setLoggedOut] = useState(false);
  const setup = useQuery({ queryKey: ["setup"], queryFn: api.setupStatus });
  const me = useQuery({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
    enabled: setup.data?.required === false,
  });
  const qc = useQueryClient();
  if (setup.isLoading) return <Loading />;
  if (setup.error)
    return (
      <div className="fatal">
        Cannot reach the TailView backend.<small>{setup.error.message}</small>
      </div>
    );
  if (setup.data?.required)
    return (
      <Setup
        onDone={() => {
          void qc.invalidateQueries({ queryKey: ["setup"] });
          void qc.invalidateQueries({ queryKey: ["me"] });
        }}
      />
    );
  if (me.isLoading) return <Loading />;
  if (loggedOut || (me.error instanceof ApiError && me.error.status === 401))
    return (
      <Login
        onDone={() => {
          void qc
            .fetchQuery({ queryKey: ["me"], queryFn: api.me })
            .then(() => setLoggedOut(false));
        }}
      />
    );
  if (me.error)
    return (
      <div className="fatal">
        Unable to load your session.<small>{me.error.message}</small>
      </div>
    );
  return <Shell user={me.data!} onLogout={() => setLoggedOut(true)} />;
}
