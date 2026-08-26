// Submission queue table: filterable + paginated, live status via the parent's
// polling. Presentational — data + handlers come in as props. Owner: Member D.
import type { SeverityBand, SubmissionStatus, SubmissionSummary } from "../../types";
import { formatRelativeTime, shortHash, STATUS_LABEL } from "../../utils/format";

export interface QueueTableProps {
  items: SubmissionSummary[];
  total: number;
  page: number;
  pageSize: number;
  statusFilter: string;
  onStatusFilterChange: (status: string) => void;
  onPageChange: (page: number) => void;
  onRowClick: (id: string) => void;
  isLoading?: boolean;
}

const STATUSES: SubmissionStatus[] = [
  "queued", "static_running", "dynamic_running", "scoring", "completed", "failed",
];

// Stitch severity pill styles
const BAND_PILL: Record<SeverityBand, React.CSSProperties> = {
  low:      { background: "rgba(42,158,101,0.12)",  color: "#4ADE80", border: "1px solid rgba(42,158,101,0.25)" },
  medium:   { background: "rgba(192,135,42,0.12)",  color: "#FBBF24", border: "1px solid rgba(192,135,42,0.25)" },
  high:     { background: "rgba(192,103,42,0.12)",  color: "#FB923C", border: "1px solid rgba(192,103,42,0.25)" },
  critical: { background: "rgba(185,28,28,0.15)",   color: "#FF4D67", border: "1px solid rgba(185,28,28,0.30)" },
};

// Stitch status text colors
const STATUS_COLOR: Record<string, string> = {
  queued:          "#9A9DA3",
  static_running:  "#50d8e9",
  dynamic_running: "#50d8e9",
  scoring:         "#bec2ff",
  completed:       "#4ADE80",
  failed:          "#FF4D67",
};

const glassPanel: React.CSSProperties = {
  background: "rgba(255,255,255,0.04)",
  backdropFilter: "blur(20px)",
  WebkitBackdropFilter: "blur(20px)",
  border: "1px solid rgba(255,255,255,0.09)",
  boxShadow: "inset 0 1px 0 0 rgba(255,255,255,0.08)",
};

function SeverityBadge({ band }: { band?: SeverityBand | null }) {
  if (!band) return <span style={{ color: "rgba(154,157,163,0.40)" }}>—</span>;
  return (
    <span
      className="px-2 py-0.5 rounded-full text-[10px] font-medium uppercase font-sans"
      style={BAND_PILL[band]}
    >
      {band}
    </span>
  );
}

export default function QueueTable(props: QueueTableProps) {
  const { items, total, page, pageSize, statusFilter, onStatusFilterChange,
    onPageChange, onRowClick, isLoading } = props;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className="rounded-xl overflow-hidden" style={glassPanel}>
      {/* Header */}
      <div
        className="flex items-center justify-between px-5 py-3"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}
      >
        <h2 className="text-[11px] font-sans uppercase tracking-[0.2em]" style={{ color: "rgba(154,157,163,0.70)" }}>
          Submission queue
        </h2>
        <label className="flex items-center gap-2 text-[11px] font-sans" style={{ color: "#9A9DA3" }}>
          Status
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => onStatusFilterChange(e.target.value)}
            className="rounded px-2 py-1 text-[11px] font-sans outline-none"
            style={{
              background: "#101112",
              border: "1px solid rgba(255,255,255,0.10)",
              color: "#e5e2e3",
            }}
          >
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
        </label>
      </div>

      {/* Table */}
      <table className="w-full text-left">
        <thead>
          <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
            {["File", "SHA-256", "Status", "Severity", "Score", "Submitted"].map((h) => (
              <th
                key={h}
                className="px-5 py-2.5 font-sans text-[9px] uppercase tracking-[0.2em] font-normal"
                style={{ color: "rgba(154,157,163,0.60)" }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {isLoading && (
            <tr>
              <td colSpan={6} className="px-5 py-8 text-center font-sans text-[12px]" style={{ color: "rgba(154,157,163,0.40)" }}>
                Loading…
              </td>
            </tr>
          )}
          {!isLoading && items.length === 0 && (
            <tr>
              <td colSpan={6} className="px-5 py-8 text-center font-sans text-[12px]" style={{ color: "rgba(154,157,163,0.40)" }}>
                No submissions
              </td>
            </tr>
          )}
          {items.map((s) => (
            <tr
              key={s.id}
              onClick={() => onRowClick(s.id)}
              className="cursor-pointer transition-colors duration-150"
              style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.035)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
            >
              {/* Filename */}
              <td className="px-5 py-3 font-sans text-[12px] max-w-[260px] truncate" style={{ color: "#e5e2e3" }}>
                {s.original_filename}
              </td>
              {/* Hash */}
              <td className="px-5 py-3 font-mono text-[11px]" style={{ color: "#9A9DA3" }}>
                {shortHash(s.sha256_hash)}
              </td>
              {/* Status */}
              <td className="px-5 py-3 font-sans text-[11px]" style={{ color: STATUS_COLOR[s.status] ?? "#9A9DA3" }}>
                {STATUS_LABEL[s.status]}
              </td>
              {/* Severity */}
              <td className="px-5 py-3">
                <SeverityBadge band={s.severity_band} />
              </td>
              {/* Score */}
              <td className="px-5 py-3 font-sans text-[13px] font-bold" style={{ color: "#e5e2e3" }}>
                {s.final_risk_score ?? "—"}
              </td>
              {/* Submitted */}
              <td className="px-5 py-3 font-sans text-[11px]" style={{ color: "#9A9DA3" }}>
                {formatRelativeTime(s.submitted_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Pagination */}
      <div
        className="flex items-center justify-between px-5 py-3"
        style={{ borderTop: "1px solid rgba(255,255,255,0.08)" }}
      >
        <span className="font-sans text-[11px]" style={{ color: "rgba(154,157,163,0.60)" }}>
          {total} total
        </span>
        <div className="flex items-center gap-2">
          <button
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            className="px-3 py-1 rounded text-[11px] font-sans transition-colors duration-150 disabled:opacity-30"
            style={{
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.10)",
              color: "#e5e2e3",
            }}
          >
            Prev
          </button>
          <span className="font-sans text-[11px]" style={{ color: "#9A9DA3" }}>
            Page {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            className="px-3 py-1 rounded text-[11px] font-sans transition-colors duration-150 disabled:opacity-30"
            style={{
              background: "rgba(255,255,255,0.05)",
              border: "1px solid rgba(255,255,255,0.10)",
              color: "#e5e2e3",
            }}
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
