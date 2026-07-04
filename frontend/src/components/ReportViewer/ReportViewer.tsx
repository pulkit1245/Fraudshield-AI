// Report viewer: plain-English summary, risk gauge, recommended action, TTP
// mapping cards, and the sanitization ("AI evasion") banner. Presentational.
// Includes one-click print/PDF export. Owner: Member D.
import type { LLMReport, SeverityBand, SubmissionDetail, Verdict } from "../../types";
import { BAND_BADGE, BAND_COLOR } from "../../utils/format";

export interface ReportViewerProps {
  detail: SubmissionDetail;
  verdict?: Verdict | null;
  report?: LLMReport | null;
  onExport?: () => void;
}

function RiskGauge({ score, band }: { score: number; band: SeverityBand }) {
  const radius = 46;
  const circ = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return (
    <svg width="120" height="120" viewBox="0 0 120 120" role="img" aria-label={`Risk score ${score}`}>
      <circle cx="60" cy="60" r={radius} fill="none" stroke="#eee" strokeWidth="10" />
      <circle
        cx="60" cy="60" r={radius} fill="none" stroke={BAND_COLOR[band]} strokeWidth="10"
        strokeLinecap="round" strokeDasharray={circ}
        strokeDashoffset={circ * (1 - pct)} transform="rotate(-90 60 60)"
      />
      <text x="60" y="58" textAnchor="middle" fontSize="26" fontWeight="800" fill="#111">
        {score}
      </text>
      <text x="60" y="76" textAnchor="middle" fontSize="11" fill="#666">/ 100</text>
    </svg>
  );
}

export default function ReportViewer({ detail, verdict, report, onExport }: ReportViewerProps) {
  const exportFn = onExport ?? (() => window.print());
  const reportBody = report?.ttp_mapping?.report;
  const summary = report?.summary_text ?? reportBody?.summary ?? "No report generated yet.";
  const behaviours = reportBody?.behaviour_chain ?? [];
  const ttps = report?.ttp_mapping?.ttp_mapping ?? [];
  const flagged = (report?.sanitization_flags?.count ?? 0) > 0;
  const band = verdict?.severity_band;
  const score = verdict?.effective_score ?? verdict?.final_risk_score;

  return (
    <article className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-bold text-gray-900">{detail.original_filename}</h1>
          <p className="font-mono text-xs text-gray-500">{detail.sha256_hash}</p>
        </div>
        <button
          onClick={exportFn}
          className="no-print rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          Export PDF
        </button>
      </div>

      {flagged && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-800">
          ⚠ AI evasion attempt detected and neutralized —{" "}
          {report?.sanitization_flags.count} prompt-injection string(s) redacted before analysis.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-6 rounded-xl border border-gray-200 bg-white p-4">
        {band && typeof score === "number" ? (
          <>
            <RiskGauge score={score} band={band} />
            <div>
              <span className={`rounded-full px-3 py-1 text-sm font-semibold ${BAND_BADGE[band]}`}>
                {band.toUpperCase()}
              </span>
              <div className="mt-2 text-sm text-gray-600">
                Recommended action:{" "}
                <span className="font-semibold text-gray-900">
                  {verdict?.recommended_action.replace(/_/g, " ")}
                </span>
              </div>
              {verdict?.analyst_override_score != null && (
                <div className="mt-1 text-xs text-gray-500">
                  Analyst override applied ({verdict.analyst_override_score}/100)
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="text-sm text-gray-400">Verdict pending…</div>
        )}
      </div>

      <section className="rounded-xl border border-gray-200 bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold text-gray-700">Summary</h2>
        <p className="text-sm leading-relaxed text-gray-800">{summary}</p>
        {behaviours.length > 0 && (
          <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-gray-700">
            {behaviours.map((b, i) => <li key={i}>{b}</li>)}
          </ul>
        )}
      </section>

      {ttps.length > 0 && (
        <section>
          <h2 className="mb-2 text-sm font-semibold text-gray-700">TTP mapping</h2>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {ttps.map((t) => (
              <div key={t.id} className="rounded-xl border border-gray-200 bg-white p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-gray-900">{t.name}</span>
                  <span className="text-xs text-gray-500">
                    {(t.confidence * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="font-mono text-xs text-indigo-600">{t.id}</div>
                {t.evidence && <p className="mt-1 text-xs text-gray-600">{t.evidence}</p>}
              </div>
            ))}
          </div>
        </section>
      )}
    </article>
  );
}
