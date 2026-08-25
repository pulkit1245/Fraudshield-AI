// Submission queue table: filterable + paginated, live status via the parent's
// polling. Presentational — data + handlers come in as props. Owner: Member D.
import type { SeverityBand, SubmissionStatus, SubmissionSummary } from "../../types";
import { BAND_BADGE, formatRelativeTime, shortHash, STATUS_LABEL } from "../../utils/format";

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

function SeverityBadge({ band }: { band?: SeverityBand | null }) {
  if (!band) return <span className="text-text-muted/50">—</span>;
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${BAND_BADGE[band]}`}>
      {band}
    </span>
  );
}

export default function QueueTable(props: QueueTableProps) {
  const { items, total, page, pageSize, statusFilter, onStatusFilterChange,
    onPageChange, onRowClick, isLoading } = props;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <section className="rounded-xl border border-border bg-background-elevated">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text">Submission queue</h2>
        <label className="flex items-center gap-2 text-xs text-text-muted">
          Status
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(e) => onStatusFilterChange(e.target.value)}
            className="rounded-md border border-border px-2 py-1 text-xs"
          >
            <option value="">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{STATUS_LABEL[s]}</option>
            ))}
          </select>
        </label>
      </div>

      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase tracking-wide text-text-muted">
          <tr>
            <th className="px-4 py-2 font-medium">File</th>
            <th className="px-4 py-2 font-medium">SHA-256</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Severity</th>
            <th className="px-4 py-2 font-medium">Score</th>
            <th className="px-4 py-2 font-medium">Submitted</th>
          </tr>
        </thead>
        <tbody>
          {isLoading && (
            <tr><td colSpan={6} className="px-4 py-6 text-center text-text-muted/50">Loading…</td></tr>
          )}
          {!isLoading && items.length === 0 && (
            <tr><td colSpan={6} className="px-4 py-6 text-center text-text-muted/50">No submissions</td></tr>
          )}
          {items.map((s) => (
            <tr
              key={s.id}
              onClick={() => onRowClick(s.id)}
              className="cursor-pointer border-t border-border hover:bg-background-surface"
            >
              <td className="px-4 py-2 font-medium text-text-bright">{s.original_filename}</td>
              <td className="px-4 py-2 font-mono text-xs text-text-muted">{shortHash(s.sha256_hash)}</td>
              <td className="px-4 py-2 text-text-muted">{STATUS_LABEL[s.status]}</td>
              <td className="px-4 py-2"><SeverityBadge band={s.severity_band} /></td>
              <td className="px-4 py-2 font-semibold text-text-bright">
                {s.final_risk_score ?? "—"}
              </td>
              <td className="px-4 py-2 text-text-muted">{formatRelativeTime(s.submitted_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex items-center justify-between px-4 py-3 text-xs text-text-muted">
        <span>{total} total</span>
        <div className="flex items-center gap-2">
          <button
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            className="rounded border border-border px-2 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <span>Page {page} / {totalPages}</span>
          <button
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            className="rounded border border-border px-2 py-1 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>
    </section>
  );
}
