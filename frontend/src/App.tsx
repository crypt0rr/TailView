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
  LayoutDashboard,
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
  Sun,
  Tags,
  Users,
  X,
} from "lucide-react";
import { api, ApiError } from "./api";
import { Button, Loading } from "./components";
import { useTimeRange } from "./timeRange";
import {
  Dashboard,
  Devices,
  Flows,
  InventoryPage,
  Policy,
  SettingsPage,
  Topology,
} from "./pages";

type CurrentUser = {
  id: string;
  username: string;
  role: "administrator" | "viewer";
};
const nav = [
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
  ["Audit", "/audit", Shield],
  ["Sync jobs", "/sync", RefreshCw],
  ["Settings", "/settings", Settings],
] as const;

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

function Shell({ user }: { user: CurrentUser }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [dark, setDark] = useState(() => localStorage.theme !== "light");
  const location = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { range, setRange } = useTimeRange();
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.theme = dark ? "dark" : "light";
  }, [dark]);
  const logout = async () => {
    await api.logout();
    qc.clear();
    navigate("/");
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
          {nav.map(([label, path, Icon]) => (
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
        <CommandPalette />
        <main className="content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/topology" element={<Topology />} />
            <Route path="/flows" element={<Flows />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/users" element={<InventoryPage kind="users" />} />
            <Route path="/groups" element={<InventoryPage kind="groups" />} />
            <Route path="/routes" element={<InventoryPage kind="routes" />} />
            <Route
              path="/services"
              element={<InventoryPage kind="services" />}
            />
            <Route path="/exit-nodes" element={<Devices role="exit_node" />} />
            <Route
              path="/subnet-routers"
              element={<Devices role="subnet_router" />}
            />
            <Route path="/tags" element={<InventoryPage kind="tags" />} />
            <Route path="/policy" element={<Policy />} />
            <Route path="/audit" element={<InventoryPage kind="audit" />} />
            <Route path="/sync" element={<InventoryPage kind="sync" />} />
            <Route path="/settings" element={<SettingsPage user={user} />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
function CommandPalette() {
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
        {nav.map(([label, path, Icon]) => (
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
  if (me.error instanceof ApiError && me.error.status === 401)
    return (
      <Login onDone={() => void qc.invalidateQueries({ queryKey: ["me"] })} />
    );
  if (me.error)
    return (
      <div className="fatal">
        Unable to load your session.<small>{me.error.message}</small>
      </div>
    );
  return <Shell user={me.data!} />;
}
