// TI Pipeline Fallback Panel
// Shows analysts exactly where the ingestion pipeline had to deviate from its
// primary strategy — which source failed, what was missing, what was used instead.
// Owner: Member D.
import { usePipelineFallbacks } from "../../hooks/usePipelineFallbacks";
import type { FallbackEvent } from "../../services/threatIntelligence";

// ── Source label mapping ────────────────────────────────────────────────────
const SOURCE_LABELS: Record<string, string> = {
  mitre_attack:      "MITRE ATT&CK",
  malwarebazaar:     "MalwareBazaar",
  otx:               "AlienVault OTX",
  misp:              "MISP",
  opencti:           "OpenCTI",
  cert_in:           "CERT-In",
  android_bulletin:  "Android Security Bulletin",
};

// ── Stage badge colours ─────────────────────────────────────────────────────
const STAGE_STYLES: Record<string, string> = {
  fetcher:       "bg-orange-100 text-orange-700 border-status-warning/20",
  normalizer:    "bg-blue-100 text-primary-cyan border-primary-blue/20",
  deduplicator:  "bg-purple-100 text-purple-700 border-purple-200",
};

// ── Helpers ─────────────────────────────────────────────────────────────────
function formatTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "2-digit", month: "short", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    }) + " IST";
  } catch {
    return iso;
  }
}

// ── Single event row ────────────────────────────────────────────────────────
function FallbackRow({ event }: { event: FallbackEvent }) {
  const sourceLabel = SOURCE_LABELS[event.source] ?? event.source;
  const stageStyle  = STAGE_STYLES[event.stage]   ?? "bg-background-surface text-text-muted border-border";

  return (
    <div className="flex flex-col gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
      {/* Header row: source + stage badge + timestamp */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1 font-semibold text-amber-900 text-sm">
          <span>⚠</span>
          <span>{sourceLabel}</span>
        </span>
        <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${stageStyle}`}>
          {event.stage}
        </span>
        <span className="ml-auto text-xs text-text-muted/50 whitespace-nowrap">
          {formatTs(event.ts)}
        </span>
      </div>

      {/* Original → Fallback */}
      <div className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-xs">
        <span className="text-text-muted font-medium pt-0.5">Intended:</span>
        <span className="text-text line-through decoration-red-400">{event.original}</span>

        <span className="text-text-muted font-medium pt-0.5">Used instead:</span>
        <span className="text-status-success font-medium">{event.fallback}</span>

        <span className="text-text-muted font-medium pt-0.5">Reason:</span>
        <span className="text-text-muted break-words">{event.reason}</span>
      </div>
    </div>
  );
}

// ── Main panel ──────────────────────────────────────────────────────────────
export default function TIPipelinePanel() {
  const { data: events = [], isLoading, isError } = usePipelineFallbacks();

  return (
    <section className="rounded-xl border border-border bg-background-elevated p-4">
      {/* Panel header */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-text">
            TI Pipeline — Fallback Events
          </h2>
          {events.length > 0 && (
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 border border-amber-200">
              {events.length}
            </span>
          )}
        </div>
        <span className="text-xs text-text-muted/50">Refreshes every 60s</span>
      </div>

      {/* Loading state */}
      {isLoading && (
        <p className="text-xs text-text-muted/50 py-4 text-center">Loading pipeline events…</p>
      )}

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-status-threat/20 bg-status-threat/10 px-3 py-2 text-xs text-status-threat">
          Could not load pipeline events. Check that the backend is reachable.
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && events.length === 0 && (
        <div className="flex flex-col items-center gap-1 py-6 text-center">
          <span className="text-2xl">✅</span>
          <p className="text-sm font-medium text-text-muted">All sources running normally</p>
          <p className="text-xs text-text-muted/50">No fallbacks or skipped sources in the last 100 runs</p>
        </div>
      )}

      {/* Event list */}
      {!isLoading && !isError && events.length > 0 && (
        <div className="flex flex-col gap-2 max-h-80 overflow-y-auto pr-1">
          {events.map((ev, i) => (
            <FallbackRow key={`${ev.source}-${ev.ts}-${i}`} event={ev} />
          ))}
        </div>
      )}

      {/* Legend */}
      {events.length > 0 && (
        <p className="mt-3 text-xs text-text-muted/50 border-t border-border pt-2">
          Showing newest {events.length} fallback event{events.length !== 1 ? "s" : ""}. 
          Events are auto-cleared after 100 entries. Resolve missing credentials in <code className="bg-background-surface px-1 rounded">.env</code>.
        </p>
      )}
    </section>
  );
}
