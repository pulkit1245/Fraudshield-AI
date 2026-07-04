// Shared formatting helpers (severity colors, time, status labels). Owner: Member D.
import type { SeverityBand, SubmissionStatus } from "../types";

export const BAND_COLOR: Record<SeverityBand, string> = {
  low: "#2a9e65",
  medium: "#c0872a",
  high: "#c0672a",
  critical: "#b91c1c",
};

export const BAND_BADGE: Record<SeverityBand, string> = {
  low: "bg-green-100 text-green-800",
  medium: "bg-amber-100 text-amber-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export const STATUS_LABEL: Record<SubmissionStatus, string> = {
  queued: "Queued",
  static_running: "Static analysis",
  dynamic_running: "Dynamic sandbox",
  scoring: "Scoring",
  completed: "Completed",
  failed: "Failed",
};

export function shortHash(sha256: string, n = 10): string {
  return sha256 ? `${sha256.slice(0, n)}…` : "";
}

export function formatRelativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}
