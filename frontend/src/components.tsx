import type { PropsWithChildren, ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleOff,
  Clock3,
  Database,
  Server,
  ShieldCheck,
  Wifi,
  WifiOff,
} from "lucide-react";

export function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}: PropsWithChildren<
  React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant?: "primary" | "secondary" | "ghost" | "danger";
  }
>) {
  const classes = className.split(/\s+/).filter(Boolean);
  const legacyVariant = classes.find((value) =>
    ["primary", "secondary", "ghost", "danger"].includes(value),
  );
  const appearance = legacyVariant ?? variant;
  const extraClasses = classes.filter((value) => value !== legacyVariant);
  return (
    <button className={["button", appearance, ...extraClasses].join(" ")} {...props}>
      {children}
    </button>
  );
}
export function Card({
  children,
  className = "",
}: PropsWithChildren<{ className?: string }>) {
  return <section className={`card ${className}`}>{children}</section>;
}
export function Badge({
  children,
  tone = "neutral",
}: PropsWithChildren<{ tone?: string }>) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function Status({ online }: { online: boolean | null }) {
  return online === true ? (
    <span className="status online">
      <Wifi size={14} /> Online
    </span>
  ) : online === false ? (
    <span className="status offline">
      <WifiOff size={14} /> Offline
    </span>
  ) : (
    <span className="status unknown">
      <Clock3 size={14} /> Last seen only
    </span>
  );
}
export function Empty({
  title,
  detail,
  icon,
}: {
  title: string;
  detail: string;
  icon?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon ?? <CircleOff />}
      <h3>{title}</h3>
      <p>{detail}</p>
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span />
      <span />
      <span />
      <span />
      <span />
      <span />
      <span />
      <span />
      <span />
    </div>
  );
}
export function ErrorState({ error }: { error: Error }) {
  return (
    <div className="error-state">
      <AlertTriangle />
      <div>
        <strong>Something went wrong</strong>
        <p>{error.message}</p>
      </div>
    </div>
  );
}
export const roleIcon = (role: string) =>
  role.includes("router") ? (
    <Wifi />
  ) : role.includes("service") ? (
    <Database />
  ) : role.includes("server") || role.includes("infrastructure") ? (
    <Server />
  ) : (
    <ShieldCheck />
  );
export const statusIcon = (status: string) =>
  status === "available" ? (
    <CheckCircle2 />
  ) : status === "unknown" ? (
    <Clock3 />
  ) : (
    <AlertTriangle />
  );
export function formatBytes(value: number): string {
  if (!Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = value;
  while (n >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}
export function relativeTime(value: string | null): string {
  if (!value) return "Not reported";
  const seconds = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
