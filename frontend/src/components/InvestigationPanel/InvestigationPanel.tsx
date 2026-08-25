// InvestigationPanel: client-side filters, finding search, investigation summary.
// Phase 8 — Evidence-grounded investigation workflow. No additional API calls.
// Owner: Member D.
import { useState, useMemo } from "react";
import type {
  AnalysisStage,
  LLMReport,
  MLScore,
  SubmissionDetail,
  TTPEntry,
  Verdict,
  VirusTotalResult,
} from "../../types";
import type { AnalysisOverallState } from "../AnalysisCompleteness/AnalysisCompletenessCard";
import { BAND_BADGE } from "../../utils/format";

export interface InvestigationFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "static" | "dynamic" | "network" | "ttp" | "ml" | "intel";
  title: string;
  evidence: string;
  whyItMatters?: string;
  source: string;
  relatedTTP?: string;
}

// ── Build a flat list of all findings from all sources ───────────────────
export function buildAllFindings(
  detail: SubmissionDetail,
  report?: LLMReport | null,
  mlScore?: MLScore | null,
  virustotal?: VirusTotalResult | null
): InvestigationFinding[] {
  const findings: InvestigationFinding[] = [];

  // Dynamic findings
  const dyn = detail.dynamic_finding;
  if (dyn) {
    if (dyn.sms_access) {
      findings.push({
        id: "dyn-sms",
        severity: "high",
        category: "dynamic",
        title: "SMS access activity detected",
        evidence: "Application accessed SMS-related functionality during runtime analysis.",
        whyItMatters: "SMS access can expose incoming OTP codes or message contents.",
        source: "Dynamic Analysis",
      });
    }
    if (dyn.overlay_detected) {
      findings.push({
        id: "dyn-overlay",
        severity: "high",
        category: "dynamic",
        title: "Overlay window drawn at runtime",
        evidence: "Application drew an overlay window during dynamic analysis.",
        whyItMatters: "Overlay windows can be used for tapjacking — intercepting input on top of legitimate apps.",
        source: "Dynamic Analysis",
      });
    }
    if (dyn.accessibility_abuse) {
      findings.push({
        id: "dyn-a11y",
        severity: "high",
        category: "dynamic",
        title: "Accessibility service interaction",
        evidence: "Application interacted with Accessibility Services during runtime.",
        whyItMatters: "Accessibility services can read screen content and automate interactions with other apps.",
        source: "Dynamic Analysis",
      });
    }
    const networkSinks = (dyn.network_calls ?? []).filter((c: any) => c.sink);
    if (networkSinks.length > 0) {
      findings.push({
        id: "dyn-network",
        severity: "medium",
        category: "network",
        title: `${networkSinks.length} connection(s) to flagged destination(s)`,
        evidence: `Connections observed: ${networkSinks.map((c: any) => c.host || c.url || "unknown").slice(0, 3).join(", ")}${networkSinks.length > 3 ? ` +${networkSinks.length - 3} more` : ""}.`,
        whyItMatters: "Connections to flagged destinations may indicate external data transmission.",
        source: "Dynamic Analysis",
      });
    }
  }

  // Static: permissions
  const perms: string[] =
    (detail.static_finding?.permissions as any)?.declared ?? [];

  const HIGH_RISK_PERMS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
  ];

  for (const p of perms) {
    if (HIGH_RISK_PERMS.includes(p)) {
      findings.push({
        id: `static-perm-${p}`,
        severity: "medium",
        category: "static",
        title: `Declares ${p.replace("android.permission.", "")}`,
        evidence: `Permission declared in AndroidManifest: ${p}`,
        source: "Static Analysis",
      });
    }
  }

  // TTP mappings
  const ttps = report?.ttp_mapping?.ttp_mapping ?? [];
  for (const ttp of ttps) {
    findings.push({
      id: `ttp-${ttp.id}`,
      severity: ttp.confidence >= 0.8 ? "high" : ttp.confidence >= 0.5 ? "medium" : "low",
      category: "ttp",
      title: `${ttp.id} — ${ttp.name}`,
      evidence: ttp.evidence ?? "No specific evidence provided by analysis model.",
      source: "TTP Mapping",
      relatedTTP: ttp.id,
    });
  }

  // ML high novelty
  if (mlScore && mlScore.novelty_score > 0.8) {
    findings.push({
      id: "ml-novelty",
      severity: "medium",
      category: "ml",
      title: "High novelty — unlike known samples",
      evidence: `Novelty score: ${(mlScore.novelty_score * 100).toFixed(1)}%. This sample differs significantly from the training distribution.`,
      whyItMatters: "High novelty may indicate an obfuscated, packed, or previously unseen malware variant.",
      source: "ML Risk Assessment",
    });
  }

  // VirusTotal detections
  if (virustotal?.status === "ok" && ((virustotal.malicious ?? 0) > 0 || (virustotal.suspicious ?? 0) > 0)) {
    findings.push({
      id: "vt-detections",
      severity: (virustotal.malicious ?? 0) > 5 ? "high" : "medium",
      category: "intel",
      title: `VirusTotal: ${virustotal.malicious ?? 0} malicious, ${virustotal.suspicious ?? 0} suspicious`,
      evidence: `${virustotal.malicious ?? 0} engines flagged as malicious, ${virustotal.suspicious ?? 0} as suspicious.${virustotal.meaningful_name ? ` Identified as: ${virustotal.meaningful_name}.` : ""}`,
      source: "Threat Intelligence",
    });
  }

  return findings;
}

type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";
type CategoryFilter = "all" | "static" | "dynamic" | "network" | "ttp" | "ml" | "intel";

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_ICONS: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

const CATEGORY_LABELS: Record<string, string> = {
  static: "Static",
  dynamic: "Dynamic",
  network: "Network",
  ttp: "TTP",
  ml: "ML",
  intel: "Threat Intel",
};

// ── Detail Drawer ─────────────────────────────────────────────────────────
function FindingDetailDrawer({
  finding,
  onClose,
}: {
  finding: InvestigationFinding;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      role="dialog"
      aria-modal="true"
      aria-label="Finding details"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg rounded-xl bg-background-elevated shadow-xl p-6 mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-text-muted/50 hover:text-text"
          aria-label="Close"
        >
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        <div className="mb-4">
          <div className="flex items-center gap-2 mb-1">
            <span aria-hidden>{SEVERITY_ICONS[finding.severity]}</span>
            <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">
              {finding.severity} · {CATEGORY_LABELS[finding.category] ?? finding.category}
            </span>
          </div>
          <h2 className="text-base font-bold text-text-bright">{finding.title}</h2>
        </div>

        <dl className="space-y-3 text-sm">
          <div>
            <dt className="font-semibold text-text">Observed Evidence</dt>
            <dd className="mt-0.5 text-text-bright bg-background-surface rounded p-2 text-xs font-mono whitespace-pre-wrap">
              {finding.evidence}
            </dd>
          </div>

          {finding.whyItMatters && (
            <div>
              <dt className="font-semibold text-text">Why It Matters</dt>
              <dd className="mt-0.5 text-text">{finding.whyItMatters}</dd>
            </div>
          )}

          <div>
            <dt className="font-semibold text-text">Analysis Source</dt>
            <dd className="mt-0.5">
              <span className="rounded-full bg-indigo-50 border border-indigo-200 px-2 py-0.5 text-xs text-indigo-700">
                {finding.source}
              </span>
            </dd>
          </div>

          {finding.relatedTTP && (
            <div>
              <dt className="font-semibold text-text">Related MITRE ATT&CK</dt>
              <dd className="mt-0.5 font-mono text-primary-cyan text-xs">{finding.relatedTTP}</dd>
            </div>
          )}
        </dl>
      </div>
    </div>
  );
}

// ── Investigation Summary card ─────────────────────────────────────────────
export function InvestigationSummary({
  verdict,
  findings,
  ttps,
  overallState,
  virustotal,
  detail,
}: {
  verdict?: Verdict | null;
  findings: InvestigationFinding[];
  ttps: TTPEntry[];
  overallState: AnalysisOverallState;
  virustotal?: VirusTotalResult | null;
  detail: SubmissionDetail;
}) {
  const band = verdict?.severity_band;
  const score = verdict?.effective_score ?? verdict?.final_risk_score;
  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const dynamicFlags = [
    detail.dynamic_finding?.sms_access,
    detail.dynamic_finding?.overlay_detected,
    detail.dynamic_finding?.accessibility_abuse,
  ].filter(Boolean).length;

  return (
    <div className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <h2 className="mb-4 text-base font-bold text-text-bright">Investigation Summary</h2>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {band && typeof score === "number" && (
          <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
            <p className="text-2xl font-bold text-text-bright">{score}</p>
            <p className="text-xs text-text-muted">Risk Score</p>
            {band && (
              <span className={`mt-1 inline-block rounded-full px-2 py-0.5 text-xs font-bold ${BAND_BADGE[band]}`}>
                {band.toUpperCase()}
              </span>
            )}
          </div>
        )}
        <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
          <p className="text-2xl font-bold text-text-bright">{highCount + criticalCount}</p>
          <p className="text-xs text-text-muted">High / Critical</p>
          <p className="text-xs text-text-muted/50">{mediumCount} medium</p>
        </div>
        <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
          <p className="text-2xl font-bold text-text-bright">{ttps.length}</p>
          <p className="text-xs text-text-muted">TTP Techniques</p>
        </div>
        <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
          <p className="text-2xl font-bold text-text-bright">{dynamicFlags}</p>
          <p className="text-xs text-text-muted">Runtime Flags</p>
          <p className="text-xs text-text-muted/50">
            {dynamicFlags === 0 ? "none" : "detected"}
          </p>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-3 text-xs text-text-muted">
        <div className="flex items-center gap-2">
          <span>Threat Intel:</span>
          <span className="font-medium">
            {virustotal?.status === "ok"
              ? `${virustotal.malicious ?? 0}/${(virustotal.malicious ?? 0) + (virustotal.suspicious ?? 0) + (virustotal.harmless ?? 0) + (virustotal.undetected ?? 0)} engines`
              : virustotal?.status === "not_found"
              ? "Not found in VT"
              : virustotal?.status === "not_configured"
              ? "Not configured"
              : "Unavailable"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span>Cluster:</span>
          <span className="font-medium">
            {detail.cluster?.cluster_name ?? "No association"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span>Pipeline:</span>
          <span className={`font-medium ${
            overallState === "COMPLETED" ? "text-status-success" :
            overallState === "COMPLETED_UNVERIFIED" ? "text-amber-700" :
            overallState === "PARTIALLY_COMPLETED" ? "text-amber-700" :
            overallState === "FAILED" ? "text-status-threat" : "text-text-muted"
          }`}>
            {overallState === "COMPLETED" ? "✓ Complete" :
             overallState === "COMPLETED_UNVERIFIED" ? "⚠ Complete (runtime unverified)" :
             overallState === "PARTIALLY_COMPLETED" ? "⚠ Partial" :
             overallState === "FAILED" ? "✗ Failed" : "In progress"}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Main InvestigationPanel ───────────────────────────────────────────────
export default function InvestigationPanel({
  findings: allFindings,
  stages,
  onNavigateToSection,
}: {
  findings: InvestigationFinding[];
  stages?: AnalysisStage[];
  onNavigateToSection?: (sectionId: string) => void;
}) {
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<InvestigationFinding | null>(null);

  const filtered = useMemo(() => {
    return allFindings
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .filter((f) => categoryFilter === "all" || f.category === categoryFilter)
      .filter((f) => {
        if (!searchQuery.trim()) return true;
        const q = searchQuery.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.evidence.toLowerCase().includes(q) ||
          (f.whyItMatters?.toLowerCase().includes(q) ?? false) ||
          f.source.toLowerCase().includes(q) ||
          (f.relatedTTP?.toLowerCase().includes(q) ?? false)
        );
      })
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }, [allFindings, severityFilter, categoryFilter, searchQuery]);

  if (allFindings.length === 0) {
    return (
      <section className="rounded-xl border border-border bg-background-elevated p-5">
        <h2 className="text-base font-bold text-text-bright mb-2">Investigation Findings</h2>
        <p className="text-sm text-text-muted">No findings were recorded for this submission.</p>
      </section>
    );
  }

  const severityBtns: { key: SeverityFilter; label: string }[] = [
    { key: "all", label: "All" },
    { key: "critical", label: "🔴 Critical" },
    { key: "high", label: "🟠 High" },
    { key: "medium", label: "🟡 Medium" },
    { key: "low", label: "🔵 Low" },
  ];

  const categoryBtns: { key: CategoryFilter; label: string }[] = [
    { key: "all", label: "All" },
    { key: "static", label: "Static" },
    { key: "dynamic", label: "Dynamic" },
    { key: "network", label: "Network" },
    { key: "ttp", label: "TTP" },
    { key: "ml", label: "ML" },
    { key: "intel", label: "Intel" },
  ];

  return (
    <>
      <section className="rounded-xl border border-border bg-background-elevated shadow-[0_4px_12px_rgba(0,0,0,0.1)] overflow-hidden">
        <div className="border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-base font-bold text-text-bright">
              Investigation Findings
              <span className="ml-2 rounded-full bg-background-surface px-2 py-0.5 text-xs font-normal text-text-muted">
                {filtered.length} of {allFindings.length}
              </span>
            </h2>
            {/* Search */}
            <div className="relative">
              <svg
                className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-text-muted/50"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                id="finding-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings…"
                aria-label="Search findings"
                className="rounded-lg border border-border pl-8 pr-3 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-indigo-300 w-48"
              />
            </div>
          </div>

          {/* Severity filter */}
          <div className="mt-3 flex flex-wrap gap-1.5">
            {severityBtns.map((btn) => (
              <button
                key={btn.key}
                id={`filter-severity-${btn.key}`}
                onClick={() => setSeverityFilter(btn.key)}
                className={`rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${
                  severityFilter === btn.key
                    ? "bg-primary-blue text-white"
                    : "bg-background-surface text-text hover:bg-gray-200"
                }`}
              >
                {btn.label}
              </button>
            ))}
          </div>

          {/* Category filter */}
          <div className="mt-2 flex flex-wrap gap-1.5">
            {categoryBtns.map((btn) => (
              <button
                key={btn.key}
                id={`filter-category-${btn.key}`}
                onClick={() => setCategoryFilter(btn.key)}
                className={`rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${
                  categoryFilter === btn.key
                    ? "bg-gray-700 text-white"
                    : "bg-background-surface text-text hover:bg-gray-200"
                }`}
              >
                {btn.label}
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        <div>
          {filtered.length === 0 ? (
            <div className="px-5 py-8 text-center text-sm text-text-muted">
              No findings match the current filters.
            </div>
          ) : (
            <div className="divide-y divide-gray-100">
              {filtered.map((f) => (
                <button
                  key={f.id}
                  id={`finding-${f.id}`}
                  onClick={() => setSelectedFinding(f)}
                  className="w-full text-left px-5 py-3 hover:bg-background-surface transition-colors group"
                >
                  <div className="flex items-start gap-3">
                    <span aria-label={f.severity} className="mt-0.5 text-base">
                      {SEVERITY_ICONS[f.severity]}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="text-sm font-medium text-text-bright">{f.title}</p>
                        <span className="rounded bg-background-surface px-1.5 py-0.5 text-xs text-text-muted">
                          {CATEGORY_LABELS[f.category]}
                        </span>
                        <span className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs text-primary-cyan">
                          {f.source}
                        </span>
                      </div>
                      <p className="mt-0.5 text-xs text-text-muted truncate">{f.evidence}</p>
                    </div>
                    <svg
                      className="h-4 w-4 shrink-0 text-gray-300 group-hover:text-text-muted transition-colors"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={2}
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Stage audit trail */}
        {stages && stages.length > 0 && (
          <div className="border-t border-border px-5 py-4">
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Analysis Audit Trail
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-text-muted">
                    <th className="text-left pb-2 pr-4">Stage</th>
                    <th className="text-left pb-2 pr-4">Status</th>
                    <th className="text-left pb-2 pr-4 hidden md:table-cell">Started</th>
                    <th className="text-left pb-2 hidden md:table-cell">Completed</th>
                    <th className="text-left pb-2">Issue</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {stages.map((s) => (
                    <tr key={s.stage} className="text-text">
                      <td
                        className="py-1.5 pr-4 font-medium text-primary-cyan cursor-pointer hover:underline"
                        onClick={() => {
                          const map: Record<string, string> = {
                            "Static Analysis": "section-static",
                            "Dynamic Analysis": "section-runtime",
                            "Threat Intelligence": "section-threat-intel",
                            "ML Risk Scoring": "section-ml",
                            "LLM Security Report": "section-llm",
                          };
                          if (map[s.stage] && onNavigateToSection) {
                            onNavigateToSection(map[s.stage]);
                          }
                        }}
                        title="Click to jump to report section"
                      >
                        {s.stage}
                      </td>
                      <td className="py-1.5 pr-4">
                        <span
                          className={`rounded-full px-2 py-0.5 font-medium ${
                            s.status === "completed"
                              ? "bg-green-100 text-status-success"
                              : s.status === "failed"
                              ? "bg-red-100 text-status-threat"
                              : s.status === "skipped"
                              ? "bg-background-surface text-text-muted"
                              : "bg-blue-100 text-primary-cyan"
                          }`}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td className="py-1.5 pr-4 hidden md:table-cell text-text-muted">
                        {s.started_at
                          ? new Date(s.started_at).toLocaleTimeString()
                          : "—"}
                      </td>
                      <td className="py-1.5 hidden md:table-cell text-text-muted">
                        {s.completed_at
                          ? new Date(s.completed_at).toLocaleTimeString()
                          : "—"}
                      </td>
                      <td className="py-1.5 text-text-muted">
                        {s.error_message ? (
                          <span className="text-red-600 truncate max-w-xs block" title={s.error_message}>
                            {s.error_message.length > 40
                              ? s.error_message.slice(0, 40) + "…"
                              : s.error_message}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Detail Drawer */}
      {selectedFinding && (
        <FindingDetailDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </>
  );
}
