// ReportViewer: Professional APK malware analysis report.
// Progressive disclosure: Summary → Key Findings → Technical Sections.
// Evidence-grounded: every claim maps to actual backend data.
// Owner: Member D.
import { useState } from "react";
import type {
  AnalysisStage,
  LLMReport,
  MLScore,
  SeverityBand,
  ShapFeature,
  StaticFindingOut,
  SubmissionDetail,
  TTPEntry,
  Verdict,
  VirusTotalResult,
} from "../../types";
import { BAND_BADGE, BAND_COLOR } from "../../utils/format";
import {
  deriveSandboxProvenance,
  networkCallOrigin,
  type SandboxProvenance,
} from "../../utils/sandboxProvenance";
import type { AnalysisOverallState } from "../AnalysisCompleteness/AnalysisCompletenessCard";

export interface ReportViewerProps {
  detail: SubmissionDetail;
  verdict?: Verdict | null;
  report?: LLMReport | null;
  mlScore?: MLScore | null;
  virustotal?: VirusTotalResult | null;
  overallState?: AnalysisOverallState;
  issues?: AnalysisStage[];
  onExport?: () => void;
}

// ── Permission classification (deterministic, no invented data) ────────────
const HIGH_RISK_PERMS = new Set([
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.SEND_SMS",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.READ_CALL_LOG",
  "android.permission.PROCESS_OUTGOING_CALLS",
  "android.permission.RECEIVE_BOOT_COMPLETED",
]);

const MEDIUM_RISK_PERMS = new Set([
  "android.permission.READ_CONTACTS",
  "android.permission.READ_PHONE_STATE",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.GET_ACCOUNTS",
]);

function classifyPerm(p: string): "high" | "medium" | "standard" {
  if (HIGH_RISK_PERMS.has(p)) return "high";
  if (MEDIUM_RISK_PERMS.has(p)) return "medium";
  return "standard";
}

function shortPerm(p: string): string {
  return p.replace(/^android\.permission\./, "").replace(/^android\./, "");
}

// Permission risk relevance descriptions — factual, not speculative
const PERM_RELEVANCE: Record<string, string> = {
  "android.permission.READ_SMS": "Allows reading SMS messages from device inbox.",
  "android.permission.RECEIVE_SMS": "Allows receiving incoming SMS messages.",
  "android.permission.SEND_SMS": "Allows sending SMS messages. Can incur costs without consent.",
  "android.permission.BIND_ACCESSIBILITY_SERVICE": "Allows binding as an Accessibility Service, which can read screen content and simulate input.",
  "android.permission.SYSTEM_ALERT_WINDOW": "Allows drawing windows over other apps. Used in overlay attack patterns.",
  "android.permission.REQUEST_INSTALL_PACKAGES": "Allows installing additional APKs at runtime (dropper behaviour).",
  "android.permission.READ_CONTACTS": "Allows reading device contacts.",
  "android.permission.READ_PHONE_STATE": "Allows reading device identity (IMEI, phone number).",
  "android.permission.RECORD_AUDIO": "Allows microphone access.",
  "android.permission.CAMERA": "Allows camera access.",
  "android.permission.ACCESS_FINE_LOCATION": "Allows precise GPS location access.",
  "android.permission.RECEIVE_BOOT_COMPLETED": "Allows app to start automatically on device boot.",
  "android.permission.READ_EXTERNAL_STORAGE": "Allows reading files from external storage.",
  "android.permission.WRITE_EXTERNAL_STORAGE": "Allows writing files to external storage.",
};

// ── Why it matters descriptions (only used for confirmed runtime flags) ───
const WHY_RUNTIME_MATTERS: Record<string, string> = {
  sms_access: "Runtime SMS access can expose incoming OTP codes or message contents to the app.",
  overlay_detected: "Drawing overlay windows can be used to intercept user input over legitimate apps (tapjacking).",
  accessibility_abuse: "Accessibility service access allows an app to read screen content, automate taps, and interact with other apps.",
};

// ── Accordion section wrapper ─────────────────────────────────────────────
function AccordionSection({
  title,
  badge,
  defaultOpen = false,
  children,
  id,
}: {
  title: string;
  badge?: React.ReactNode;
  defaultOpen?: boolean;
  children: React.ReactNode;
  id?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section
      id={id}
      className="rounded-xl overflow-hidden"
      style={{
        background: "#1a1b1e",
        border: "1px solid rgba(255,255,255,0.10)",
        boxShadow: "inset 0 1px 0 0 rgba(255,255,255,0.08)",
      }}
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left transition-colors"
        style={{ background: "transparent" }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.03)"; }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = "transparent"; }}
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-base font-semibold" style={{ color: "#e5e2e3" }}>{title}</span>
          {badge}
        </div>
        <svg
          className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`}
          style={{ color: "rgba(154,157,163,0.60)" }}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div
          className="px-5 py-4"
          style={{ borderTop: "1px solid rgba(255,255,255,0.08)" }}
        >
          {children}
        </div>
      )}
    </section>
  );
}

// ── Risk gauge SVG ────────────────────────────────────────────────────────
function RiskGauge({ score, band }: { score: number; band: SeverityBand }) {
  const radius = 46;
  const circ = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return (
    <svg width="120" height="120" viewBox="0 0 120 120" role="img" aria-label={`Risk score ${score} out of 100`}>
      <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.10)" strokeWidth="10" />
      <circle
        cx="60" cy="60" r={radius} fill="none"
        stroke={BAND_COLOR[band]} strokeWidth="10"
        strokeLinecap="round" strokeDasharray={circ}
        strokeDashoffset={circ * (1 - pct)} transform="rotate(-90 60 60)"
      />
      <text x="60" y="58" textAnchor="middle" fontSize="26" fontWeight="800" fill="#e5e2e3">
        {score}
      </text>
      <text x="60" y="76" textAnchor="middle" fontSize="11" fill="#9A9DA3">/ 100</text>
    </svg>
  );
}

// ── Severity badge ────────────────────────────────────────────────────────
const SEVERITY_ICONS: Record<SeverityBand, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

function SeverityBadge({ band }: { band: SeverityBand }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-bold ${BAND_BADGE[band]}`}>
      <span aria-hidden="true">{SEVERITY_ICONS[band]}</span>
      {band.toUpperCase()}
    </span>
  );
}

// ── Status pill (distinct from severity) ─────────────────────────────────
function StatusPill({
  label,
  color,
}: {
  label: string;
  color: "green" | "yellow" | "red" | "gray";
}) {
  const styles: React.CSSProperties = {
    green:  { background: "rgba(74,222,128,0.12)",  color: "#4ADE80", border: "1px solid rgba(74,222,128,0.25)" },
    yellow: { background: "rgba(251,191,36,0.12)",  color: "#FBBF24", border: "1px solid rgba(251,191,36,0.25)" },
    red:    { background: "rgba(255,77,103,0.12)",  color: "#FF4D67", border: "1px solid rgba(255,77,103,0.25)" },
    gray:   { background: "rgba(255,255,255,0.06)", color: "#c6c5d8", border: "1px solid rgba(255,255,255,0.12)" },
  }[color] as React.CSSProperties;
  return (
    <span className="rounded-full px-2.5 py-0.5 text-xs font-medium" style={styles}>
      {label}
    </span>
  );
}

// ── 1. Security Summary ───────────────────────────────────────────────────
function SecuritySummarySection({
  detail,
  verdict,
  overallState,
  issues,
}: {
  detail: SubmissionDetail;
  verdict?: Verdict | null;
  overallState: AnalysisOverallState;
  issues: AnalysisStage[];
}) {
  const band = verdict?.severity_band;
  const score = verdict?.effective_score ?? verdict?.final_risk_score;
  const isComplete = overallState === "COMPLETED";
  const isUnverified = overallState === "COMPLETED_UNVERIFIED";

  const summaryLines: string[] = [];
  if (overallState === "FAILED") {
    summaryLines.push(`Analysis of ${detail.original_filename} failed before a verdict could be determined.`);
  } else if (band && typeof score === "number") {
    summaryLines.push(
      `Analysis of ${detail.original_filename} concluded with a ${band.toUpperCase()} risk assessment (score: ${score}/100).`
    );
    if (isComplete) {
      summaryLines.push("All pipeline stages completed successfully.");
    } else if (isUnverified) {
      summaryLines.push(
        "All pipeline stages completed, but the runtime behaviour in this report was not produced by a verified live sandbox execution — see Runtime Behaviour for its actual provenance."
      );
    } else if (overallState === "PARTIALLY_COMPLETED") {
      summaryLines.push(
        `Analysis was partially completed — ${issues.length} stage(s) failed or were skipped. The verdict is based on the available evidence only.`
      );
    }
  } else {
    summaryLines.push(`Analysis of ${detail.original_filename} is in progress or pending a final verdict.`);
  }

  return (
    <section className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-lg font-bold text-text-bright break-all">{detail.original_filename}</h1>
          {(detail.static_finding as any)?.package_name && (
            <p className="mt-0.5 text-xs text-text-muted font-mono">
              {(detail.static_finding as any).package_name}
            </p>
          )}
          <p className="mt-1 font-mono text-xs text-text-muted/50 break-all">{detail.sha256_hash}</p>
        </div>
        <div className="flex flex-col items-end gap-2">
          {band && <SeverityBadge band={band} />}
          {isComplete ? (
            <StatusPill label="✓ Analysis Complete" color="green" />
          ) : isUnverified ? (
            <StatusPill label="⚠ Complete — Runtime Unverified" color="yellow" />
          ) : overallState === "PARTIALLY_COMPLETED" ? (
            <StatusPill label="⚠ Partially Complete" color="yellow" />
          ) : overallState === "FAILED" ? (
            <StatusPill label="✗ Analysis Failed" color="red" />
          ) : (
            <StatusPill label="⏳ Analyzing…" color="gray" />
          )}
        </div>
      </div>

      {band && typeof score === "number" && (
        <div className="mt-4 flex items-center gap-6 border-t border-border pt-4">
          <RiskGauge score={score} band={band} />
          <div>
            <p className="text-sm leading-relaxed text-text">{summaryLines.join(" ")}</p>
            {verdict?.analyst_override_score != null && (
              <p className="mt-2 text-xs text-text-muted flex items-center gap-1">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                </svg>
                Manual analyst override applied (override score: {verdict.analyst_override_score})
              </p>
            )}
          </div>
        </div>
      )}

      {!band && overallState !== "FAILED" && (
        <p className="mt-3 text-sm text-text-muted leading-relaxed">{summaryLines[0]}</p>
      )}
    </section>
  );
}

// ── 2. Key Findings ───────────────────────────────────────────────────────
interface KeyFinding {
  severity: "critical" | "high" | "medium";
  category: "dynamic" | "static" | "network";
  evidence: string;
  whyItMatters: string;
}

function buildKeyFindings(detail: SubmissionDetail): KeyFinding[] {
  const findings: KeyFinding[] = [];
  const dyn = detail.dynamic_finding;
  const perms: string[] =
    (detail.static_finding?.permissions as any)?.declared ?? [];

  if (dyn?.sms_access) {
    findings.push({
      severity: "high",
      category: "dynamic",
      evidence: "SMS access activity detected during runtime analysis.",
      whyItMatters: WHY_RUNTIME_MATTERS.sms_access,
    });
  }
  if (dyn?.overlay_detected) {
    findings.push({
      severity: "high",
      category: "dynamic",
      evidence: "Overlay window drawn during runtime analysis.",
      whyItMatters: WHY_RUNTIME_MATTERS.overlay_detected,
    });
  }
  if (dyn?.accessibility_abuse) {
    findings.push({
      severity: "high",
      category: "dynamic",
      evidence: "Accessibility service interaction detected during runtime.",
      whyItMatters: WHY_RUNTIME_MATTERS.accessibility_abuse,
    });
  }
  if (
    dyn?.network_calls &&
    dyn.network_calls.some((c: any) => c.sink === true)
  ) {
    findings.push({
      severity: "medium",
      category: "network",
      evidence: "Network connections to flagged destinations observed during runtime.",
      whyItMatters:
        "Connections to flagged hosts may indicate data exfiltration or command-and-control (C2) infrastructure.",
    });
  }

  // Static: high-risk declared permissions (only ones not already captured in dynamic)
  if (perms.includes("android.permission.REQUEST_INSTALL_PACKAGES")) {
    findings.push({
      severity: "high",
      category: "static",
      evidence: "Declares REQUEST_INSTALL_PACKAGES in AndroidManifest.",
      whyItMatters:
        "Could allow the application to install additional software at runtime without user consent.",
    });
  }
  if (
    perms.includes("android.permission.SYSTEM_ALERT_WINDOW") &&
    !dyn?.overlay_detected
  ) {
    findings.push({
      severity: "medium",
      category: "static",
      evidence: "Declares SYSTEM_ALERT_WINDOW in AndroidManifest.",
      whyItMatters:
        "This permission can be used to create overlay windows on top of other applications.",
    });
  }
  if (
    perms.includes("android.permission.BIND_ACCESSIBILITY_SERVICE") &&
    !dyn?.accessibility_abuse
  ) {
    findings.push({
      severity: "medium",
      category: "static",
      evidence: "Declares BIND_ACCESSIBILITY_SERVICE in AndroidManifest.",
      whyItMatters:
        "Accessibility services can read screen content and interact with other applications.",
    });
  }

  return findings;
}

const FIND_SEVERITY_STYLES: Record<string, React.CSSProperties> = {
  critical: { borderLeftColor: "#FF4D67", background: "rgba(255,77,103,0.08)", border: "1px solid rgba(255,77,103,0.20)", borderLeft: "4px solid #FF4D67" },
  high:     { borderLeftColor: "#FB923C", background: "rgba(251,146,60,0.08)",  border: "1px solid rgba(251,146,60,0.20)", borderLeft: "4px solid #FB923C" },
  medium:   { borderLeftColor: "#FBBF24", background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.18)", borderLeft: "4px solid #FBBF24" },
};
const FIND_SEVERITY_LABELS = {
  critical: { icon: "🔴", label: "Critical" },
  high:     { icon: "🟠", label: "High" },
  medium:   { icon: "🟡", label: "Medium" },
};

function KeyFindingsSection({ findings }: { findings: KeyFinding[] }) {
  if (findings.length === 0) return null;
  return (
    <AccordionSection
      id="section-key-findings"
      title="Key Findings"
      defaultOpen={true}
      badge={
        <span
          className="rounded-full px-2 py-0.5 text-xs font-bold"
          style={{ background: "rgba(255,77,103,0.15)", color: "#FF7090", border: "1px solid rgba(255,77,103,0.30)" }}
        >
          {findings.length}
        </span>
      }
    >
      <div className="space-y-3">
        {findings.map((f, i) => {
          const meta = FIND_SEVERITY_LABELS[f.severity];
          return (
            <div key={i} className="rounded-lg p-3" style={FIND_SEVERITY_STYLES[f.severity]}>
              <div className="flex items-center gap-2 mb-1">
                <span aria-hidden="true">{meta.icon}</span>
                <span className="text-xs font-bold uppercase tracking-wide" style={{ color: "rgba(229,226,227,0.70)" }}>
                  {meta.label} · {f.category === "dynamic" ? "Runtime" : f.category === "network" ? "Network" : "Static"}
                </span>
              </div>
              <p className="text-sm font-semibold" style={{ color: "#e5e2e3" }}>
                <span className="font-normal" style={{ color: "#9A9DA3" }}>Observed: </span>
                {f.evidence}
              </p>
              <p className="mt-1 text-sm" style={{ color: "#c6c5d8" }}>
                <span className="font-semibold" style={{ color: "#e5e2e3" }}>Why it matters: </span>
                {f.whyItMatters}
              </p>
            </div>
          );
        })}
      </div>
    </AccordionSection>
  );
}

// ── 3. Static Analysis ────────────────────────────────────────────────────
function StaticAnalysisSection({ sf }: { sf: StaticFindingOut | null | undefined }) {
  const [showAllPerms, setShowAllPerms] = useState(false);

  if (!sf) {
    return (
      <AccordionSection id="section-static" title="Static Analysis" defaultOpen={false}>
        <p className="text-sm text-text-muted">
          Static analysis data is unavailable for this submission.
        </p>
      </AccordionSection>
    );
  }

  const perms: string[] = (sf.permissions as any)?.declared ?? [];
  const used: string[] = (sf.permissions as any)?.used ?? [];
  const highPerms = perms.filter((p) => classifyPerm(p) === "high");
  const medPerms = perms.filter((p) => classifyPerm(p) === "medium");
  const stdPerms = perms.filter((p) => classifyPerm(p) === "standard");

  const displayPerms = showAllPerms ? perms : perms.slice(0, 6);

  const cert = sf.certificate_info as any;
  const acg = sf.api_call_graph as any;

  return (
    <AccordionSection id="section-static" title="Static Analysis" defaultOpen={false}>
      <div className="space-y-5">
        {/* APK Metadata */}
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
            APK Metadata
          </h3>
          <div className="overflow-hidden rounded-lg border border-border">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-gray-100">
                {sf.package_name && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-text w-40">Package Name</td>
                    <td className="px-3 py-2 font-mono text-text-bright break-all">{sf.package_name}</td>
                  </tr>
                )}
                {sf.obfuscation_score != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-text">Obfuscation Score</td>
                    <td className="px-3 py-2 text-text-bright">
                      {(sf.obfuscation_score * 100).toFixed(0)}%
                      <span className="ml-2 text-xs text-text-muted">
                        {sf.obfuscation_score > 0.5
                          ? "(High — code may be deliberately obfuscated)"
                          : sf.obfuscation_score > 0.2
                          ? "(Moderate)"
                          : "(Low)"}
                      </span>
                    </td>
                  </tr>
                )}
                {acg?.activities != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-text">Activities</td>
                    <td className="px-3 py-2 text-text-bright">{acg.activities}</td>
                  </tr>
                )}
                {acg?.services != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-text">Services</td>
                    <td className="px-3 py-2 text-text-bright">{acg.services}</td>
                  </tr>
                )}
                {acg?.receivers != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-text">Receivers</td>
                    <td className="px-3 py-2 text-text-bright">{acg.receivers}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Permissions */}
        {perms.length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Permissions ({perms.length} declared)
            </h3>
            {/* Summary pills */}
            <div className="mb-3 flex flex-wrap gap-2 text-xs">
              {highPerms.length > 0 && (
                <span className="rounded-full bg-orange-100 text-status-warning px-2 py-1 font-medium">
                  🟠 {highPerms.length} High Relevance
                </span>
              )}
              {medPerms.length > 0 && (
                <span className="rounded-full bg-amber-100 text-amber-800 px-2 py-1 font-medium">
                  🟡 {medPerms.length} Moderate Relevance
                </span>
              )}
              {stdPerms.length > 0 && (
                <span className="rounded-full bg-background-surface text-text px-2 py-1 font-medium">
                  ⚪ {stdPerms.length} Standard
                </span>
              )}
            </div>
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full text-sm">
                <thead className="bg-background-surface">
                  <tr>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted w-8">Risk</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted">Permission</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted hidden md:table-cell">Status</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-text-muted hidden lg:table-cell">Risk Relevance</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {displayPerms.map((p) => {
                    const cls = classifyPerm(p);
                    const isUsed = used.includes(p);
                    return (
                      <tr key={p} className="hover:bg-background-surface">
                        <td className="px-3 py-2 text-center">
                          {cls === "high" ? (
                            <span title="High relevance" aria-label="High relevance">🟠</span>
                          ) : cls === "medium" ? (
                            <span title="Moderate relevance" aria-label="Moderate relevance">🟡</span>
                          ) : (
                            <span title="Standard" aria-label="Standard">⚪</span>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-text-bright break-all">
                          {shortPerm(p)}
                        </td>
                        <td className="px-3 py-2 hidden md:table-cell">
                          <span className="text-xs">
                            {isUsed ? (
                              <span className="text-text">Declared + Observed</span>
                            ) : (
                              <span className="text-text-muted">Declared</span>
                            )}
                          </span>
                        </td>
                        <td className="px-3 py-2 hidden lg:table-cell text-xs text-text-muted">
                          {PERM_RELEVANCE[p] ?? "Standard permission with no specific elevated relevance."}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {perms.length > 6 && (
              <button
                onClick={() => setShowAllPerms((v) => !v)}
                className="mt-2 text-xs text-primary-cyan hover:underline"
              >
                {showAllPerms ? "Show fewer permissions" : `Show all ${perms.length} permissions`}
              </button>
            )}
          </div>
        )}

        {/* Certificate Info */}
        {cert && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Certificate / Signing
            </h3>
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-gray-100">
                  {cert.self_signed != null && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-text w-40">Self-signed</td>
                      <td className="px-3 py-2 text-text-bright">
                        {cert.self_signed ? (
                          <span className="text-amber-700">Yes — not signed by a trusted CA</span>
                        ) : (
                          "No"
                        )}
                      </td>
                    </tr>
                  )}
                  {cert.sha1 && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-text">SHA-1 Fingerprint</td>
                      <td className="px-3 py-2 font-mono text-xs text-text-bright break-all">{cert.sha1}</td>
                    </tr>
                  )}
                  {cert.not_before && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-text">Valid From</td>
                      <td className="px-3 py-2 text-text-bright">{cert.not_before}</td>
                    </tr>
                  )}
                  {cert.not_after && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-text">Valid Until</td>
                      <td className="px-3 py-2 text-text-bright">{cert.not_after}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* API indicators */}
        {acg?.sensitive_calls && Object.values(acg.sensitive_calls).some((val: any) => (Array.isArray(val) ? val.length : Number(val)) > 0) && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Sensitive API Indicators
            </h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(acg.sensitive_calls)
                .filter(([_, val]: [string, any]) => (Array.isArray(val) ? val.length : Number(val)) > 0)
                .map(([cat, val]: [string, any]) => {
                  const num = Array.isArray(val) ? val.length : Number(val);
                  return (
                    <span key={cat} className="rounded-md bg-status-warning/10 border border-status-warning/20 px-2 py-1 text-xs font-medium text-status-warning">
                      {cat} ({num} call{num !== 1 ? "s" : ""})
                    </span>
                  );
              })}
            </div>
          </div>
        )}
      </div>
    </AccordionSection>
  );
}

// ── 4. Runtime Behaviour ──────────────────────────────────────────────────
function RuntimeBehaviourSection({ detail }: { detail: SubmissionDetail }) {
  const dyn = detail.dynamic_finding;

  if (!dyn) {
    return (
      <AccordionSection id="section-runtime" title="Runtime Behaviour" defaultOpen={false}>
        <p className="text-sm text-text-muted">
          Runtime behaviour data is unavailable. Dynamic analysis may not have completed or the sandbox was not executed.
        </p>
      </AccordionSection>
    );
  }

  const networkCalls = dyn.network_calls ?? [];
  const anyFlag = dyn.sms_access || dyn.overlay_detected || dyn.accessibility_abuse;
  // Provenance drives the wording below. Previously every description asserted
  // "during dynamic analysis" unconditionally, which read as runtime evidence
  // even when the sample was never executed.
  const prov = deriveSandboxProvenance(dyn);
  const origin = networkCallOrigin(prov);

  const behaviourItems = [
    {
      key: "sms_access",
      label: "SMS Activity",
      detected: dyn.sms_access,
      desc: `Application accessed SMS-related functionality ${prov.observedPhrase}.`,
      matter: WHY_RUNTIME_MATTERS.sms_access,
    },
    {
      key: "overlay_detected",
      label: "Overlay Window",
      detected: dyn.overlay_detected,
      desc: `Application drew an overlay window ${prov.observedPhrase}.`,
      matter: WHY_RUNTIME_MATTERS.overlay_detected,
    },
    {
      key: "accessibility_abuse",
      label: "Accessibility Service",
      detected: dyn.accessibility_abuse,
      desc: `Application interacted with Accessibility Services ${prov.observedPhrase}.`,
      matter: WHY_RUNTIME_MATTERS.accessibility_abuse,
    },
  ];

  // A clean run is only reportable as "no suspicious flags" when the sample was
  // actually executed. Without a live run, absence of flags is absence of
  // evidence, so the badge reports provenance instead of a false all-clear.
  const badge = anyFlag ? (
    <StatusPill
      label={
        prov.runtimeObserved
          ? "Suspicious behaviour observed"
          : "Suspicious behaviour reported — unverified"
      }
      color="yellow"
    />
  ) : prov.runtimeObserved ? (
    <StatusPill label="No suspicious flags" color="green" />
  ) : (
    <StatusPill label={prov.label} color={prov.tone} />
  );

  return (
    <AccordionSection id="section-runtime" title="Runtime Behaviour" defaultOpen={anyFlag} badge={badge}>
      <div className="space-y-4">
        {/* Provenance banner — states plainly whether this is runtime evidence. */}
        <div
          className="rounded-lg p-3 text-xs"
          style={
            prov.tone === "green"
              ? { background: "rgba(74,222,128,0.08)", border: "1px solid rgba(74,222,128,0.25)", color: "#86EFAC" }
              : prov.tone === "yellow"
                ? { background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.25)", color: "#FDE68A" }
                : { background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "#c6c5d8" }
          }
        >
          <p className="font-semibold" style={{ color: prov.tone === "green" ? "#4ADE80" : prov.tone === "yellow" ? "#FBBF24" : "#e5e2e3" }}>Evidence source: {prov.label}</p>
          <p className="mt-1">{prov.summary}</p>
          <p className="mt-1 text-[11px] opacity-80">{prov.containmentLabel}.</p>
        </div>
        {/* Behaviour flags */}
        <div>
          <h3 className="mb-2 text-[9px] font-mono uppercase tracking-[0.2em]" style={{ color: "rgba(154,157,163,0.70)" }}>
            Observed Behaviour Flags
          </h3>
          <div className="space-y-2">
            {behaviourItems.map((item) => (
              <div
                key={item.key}
                className="rounded-lg p-3"
                style={
                  item.detected
                    ? { background: "rgba(251,146,60,0.08)", border: "1px solid rgba(251,146,60,0.2)" }
                    : { background: "#1a1b1e", border: "1px solid rgba(255,255,255,0.08)" }
                }
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span aria-label={item.detected ? "Detected" : "Not detected"}>
                      {item.detected ? "🟠" : "✅"}
                    </span>
                    <span className="text-sm font-semibold" style={{ color: "#e5e2e3" }}>{item.label}</span>
                    <span
                      className="rounded-full px-2 py-0.5 text-xs font-medium"
                      style={
                        item.detected
                          ? { background: "rgba(251,146,60,0.15)", color: "#FDBA74", border: "1px solid rgba(251,146,60,0.25)" }
                          : { background: "rgba(74,222,128,0.15)", color: "#86EFAC", border: "1px solid rgba(74,222,128,0.25)" }
                      }
                    >
                      {item.detected ? "Detected" : "Not Detected"}
                    </span>
                  </div>
                </div>
                {item.detected && (
                  <div className="mt-2 ml-6 space-y-1">
                    <p className="text-xs" style={{ color: "#c6c5d8" }}>
                      <span className="font-semibold" style={{ color: "#e5e2e3" }}>{prov.evidenceLabel}: </span>
                      {item.desc}
                    </p>
                    <p className="text-xs" style={{ color: "#9A9DA3" }}>
                      <span className="font-semibold" style={{ color: "#e5e2e3" }}>Why it matters: </span>
                      {item.matter}
                    </p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Network connections */}
        {networkCalls.length > 0 ? (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              {prov.runtimeObserved
                ? `Network Connections Observed (${networkCalls.length})`
                : `Network Connections Reported (${networkCalls.length})`}
            </h3>
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full text-xs">
                <thead className="bg-background-surface">
                  <tr>
                    <th className="px-3 py-2 text-left font-semibold text-text-muted">Destination</th>
                    <th className="px-3 py-2 text-left font-semibold text-text-muted">Port</th>
                    <th className="px-3 py-2 text-left font-semibold text-text-muted">Protocol</th>
                    {/* Origin (how the row was produced) and Classification (what
                        the row means) are separate columns on purpose. They used
                        to share one column, where the threat marker "Flagged
                        destination" alternated with the provenance word
                        "Observed" — conflating evidence with assessment. */}
                    <th className="px-3 py-2 text-left font-semibold text-text-muted">Origin</th>
                    <th className="px-3 py-2 text-left font-semibold text-text-muted">Classification</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {networkCalls.slice(0, 20).map((call: any, idx: number) => (
                    <tr key={idx} className="hover:bg-background-surface">
                      <td className="px-3 py-2 font-mono text-text-bright">
                        {call.host ?? call.url ?? call.destination ?? "Unknown"}
                      </td>
                      <td className="px-3 py-2 text-text">{call.port ?? "—"}</td>
                      <td className="px-3 py-2 text-text uppercase">{call.protocol ?? "—"}</td>
                      <td className="px-3 py-2">
                        <span
                          className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                            origin.tone === "green"
                              ? "bg-green-100 text-status-success"
                              : origin.tone === "yellow"
                                ? "bg-amber-100 text-amber-800"
                                : "bg-background-surface text-text"
                          }`}
                        >
                          {origin.label}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {call.sink === true ? (
                          <span className="rounded-full bg-orange-100 px-2 py-0.5 text-xs font-medium text-status-warning">
                            Monitored sink
                          </span>
                        ) : (
                          <span className="text-text-muted">Unclassified</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {networkCalls.length > 20 && (
                <div className="px-3 py-2 bg-background-surface text-xs text-text-muted text-center border-t border-border">
                  Showing 20 of {networkCalls.length} connections
                </div>
              )}
            </div>
            <p className="mt-1.5 text-xs text-text-muted">
              <span className="font-semibold">Origin</span> records how the row was
              produced; <span className="font-semibold">Classification</span> records
              what it means. "Monitored sink" means the sandbox recorded this host as a
              monitored sink — not confirmed C2 infrastructure unless explicitly stated.
              {prov.syntheticFindings &&
                " Rows on this run were synthesised rather than captured from a device, so no destination below is evidence of a real connection attempt."}
            </p>
          </div>
        ) : (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Network Connections
            </h3>
            <p className="text-sm text-text-muted">
              {prov.runtimeObserved
                ? "No network connections were recorded during the live sandbox run."
                : "No network connections are listed. Because this finding did not come from a verified live run, this is not evidence that the application made no connections."}
            </p>
          </div>
        )}
      </div>
    </AccordionSection>
  );
}

// ── 5. Threat Intelligence ────────────────────────────────────────────────
function ThreatIntelligenceSection({
  detail,
}: {
  detail: SubmissionDetail;
  virustotal?: VirusTotalResult | null;
}) {
  return (
    <AccordionSection id="section-threat-intel" title="Threat Intelligence" defaultOpen={false}>
      {/* Campaign Cluster — full width */}
      <div className="rounded-lg border border-border p-4">
        <h3 className="mb-3 text-sm font-semibold text-text-bright">Campaign Cluster</h3>
        {detail.cluster ? (
          <div className="space-y-2">
            <p className="text-sm text-text">
              This submission has been associated with cluster:{" "}
              <span className="font-semibold text-text-bright">{detail.cluster.cluster_name}</span>
            </p>
            <p className="text-xs text-text-muted">
              Cluster analysis groups submissions with similar characteristics to identify potential campaign patterns. This is a similarity association, not confirmation of a specific threat.
            </p>
          </div>
        ) : (
          <p className="text-sm text-text-muted">
            ⚪ No cluster association found. This submission was not assigned to any known campaign cluster.
          </p>
        )}
      </div>
    </AccordionSection>
  );
}

// ── 6. ML Risk Assessment ─────────────────────────────────────────────────
function MLRiskSection({ mlScore }: { mlScore?: MLScore | null }) {
  if (!mlScore) {
    return (
      <AccordionSection id="section-ml" title="ML Risk Assessment" defaultOpen={false}>
        <p className="text-sm text-text-muted">
          ML scoring data is unavailable for this submission.
        </p>
      </AccordionSection>
    );
  }

  const topFeatures: ShapFeature[] = mlScore.shap_values?.top_features ?? [];
  const hasShap = topFeatures.length > 0;

  return (
    <AccordionSection id="section-ml" title="ML Risk Assessment" defaultOpen={false}>
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
            <p className="text-2xl font-bold text-text-bright">
              {(mlScore.classifier_score * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-text-muted mt-0.5">Classifier Probability</p>
          </div>
          <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
            <p className="text-2xl font-bold text-text-bright">
              {(mlScore.novelty_score * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-text-muted mt-0.5">Novelty Score</p>
            <p className="text-xs text-text-muted/50">(higher = less similar to known samples)</p>
          </div>
          <div className="rounded-lg border border-border bg-background-surface p-3 text-center">
            <p className="text-xs font-mono text-text-muted mt-1 break-all">{mlScore.model_version}</p>
            <p className="text-xs text-text-muted mt-0.5">Model Version</p>
          </div>
        </div>

        {hasShap ? (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-muted">
              Top Contributing Signals (SHAP)
            </h3>
            <p className="mb-3 text-xs text-text-muted">
              These signals from the APK contributed most to the model's risk assessment. Each item originates from the ML model's SHAP analysis.
            </p>
            <div className="space-y-2">
              {topFeatures
                .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
                .slice(0, 8)
                .map((f, i) => {
                  const isRisk = f.direction === "increases_risk";
                  const barPct = Math.min(100, Math.abs(f.contribution) * 500);
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <span className={`text-sm ${isRisk ? "text-orange-600" : "text-green-600"}`} aria-hidden>
                        {isRisk ? "▲" : "▼"}
                      </span>
                      <span className="text-xs text-text w-40 shrink-0 truncate" title={f.feature}>
                        {f.feature}
                      </span>
                      <div className="flex-1 rounded-full bg-background-surface h-2">
                        <div
                          className={`h-2 rounded-full ${isRisk ? "bg-orange-400" : "bg-green-400"}`}
                          style={{ width: `${Math.max(4, barPct)}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-text-muted w-16 text-right">
                        {f.contribution.toFixed(4)}
                      </span>
                    </div>
                  );
                })}
            </div>
            <div className="mt-2 flex gap-4 text-xs text-text-muted">
              <span className="flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded bg-orange-400" /> Increases risk
              </span>
              <span className="flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded bg-green-400" /> Decreases risk
              </span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-text-muted">
            Model contribution details (SHAP) are unavailable for this submission.
          </p>
        )}
      </div>
    </AccordionSection>
  );
}

// ── 7. LLM Assessment ────────────────────────────────────────────────────
function LLMAssessmentSection({ report }: { report?: LLMReport | null }) {
  if (!report?.summary_text && !report?.ttp_mapping?.report?.summary) {
    return null;
  }

  const summary = report.summary_text ?? report.ttp_mapping?.report?.summary ?? "";
  const flagged = (report.sanitization_flags?.count ?? 0) > 0;

  return (
    <AccordionSection id="section-llm" title="LLM Security Assessment" defaultOpen={false}>
      <div className="space-y-3">
        {flagged && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            ⚠ {report.sanitization_flags.count} prompt-injection string(s) were detected in the APK content and redacted before LLM analysis.
          </div>
        )}
        <p className="text-sm leading-relaxed text-text">{summary}</p>
        <p className="text-xs text-text-muted/50">
          Model: {report.model_used}
          {report.model_used?.includes("fallback") &&
            " — live LLM was unavailable; this summary was generated by the deterministic fallback system."}
        </p>
      </div>
    </AccordionSection>
  );
}

// ── 8. TTP Mapping ───────────────────────────────────────────────────────
function TTPSection({ ttps }: { ttps: TTPEntry[] }) {
  if (ttps.length === 0) return null;

  return (
    <AccordionSection
      id="section-ttps"
      title="TTP Mapping (MITRE ATT&CK Mobile)"
      defaultOpen={false}
      badge={
        <span className="rounded-full bg-primary-blue/10 px-2 py-0.5 text-xs font-bold text-indigo-700">
          {ttps.length}
        </span>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-text-muted">
          These techniques are mapped from backend LLM analysis and are based on observed indicators. Confidence is provided by the analysis model.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {ttps.map((t) => {
            const confPct = Math.round(t.confidence * 100);
            const confColor =
              confPct >= 80
                ? "bg-orange-100 text-status-warning"
                : confPct >= 50
                ? "bg-amber-100 text-amber-800"
                : "bg-background-surface text-text-muted";
            return (
              <div key={t.id} className="rounded-lg border border-border p-3">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-semibold text-text-bright">{t.name}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${confColor}`}>
                    {confPct}% confidence
                  </span>
                </div>
                <div className="font-mono text-xs text-primary-cyan mb-2">{t.id}</div>
                {t.evidence ? (
                  <div className="text-xs text-text-muted border-l-2 border-indigo-200 pl-2">
                    <span className="font-semibold">Evidence: </span>
                    {t.evidence}
                  </div>
                ) : (
                  <div className="text-xs text-text-muted/50 border-l-2 border-border pl-2">
                    Specific evidence details not provided.
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </AccordionSection>
  );
}

// ── 9. Analysis Limitations ───────────────────────────────────────────────
function LimitationsSection({
  overallState,
  issues,
  provenance,
}: {
  overallState: AnalysisOverallState;
  issues: AnalysisStage[];
  provenance: SandboxProvenance | null;
}) {
  const provenanceLimited = provenance?.degraded ?? false;
  if (
    overallState !== "PARTIALLY_COMPLETED" &&
    overallState !== "FAILED" &&
    overallState !== "COMPLETED_UNVERIFIED" &&
    !provenanceLimited
  ) {
    return null;
  }

  return (
    <section className="rounded-xl border border-status-warning/20 bg-status-warning/10 p-5">
      <h2 className="mb-2 flex items-center gap-2 text-base font-bold text-yellow-900">
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        Analysis Limitations
      </h2>
      <p className="mb-3 text-sm text-status-warning">
        {overallState === "FAILED"
          ? "A critical pipeline stage failed. The final risk assessment may be incomplete or unavailable."
          : overallState === "COMPLETED_UNVERIFIED"
            ? "All pipeline stages completed, but the dynamic evidence in this report was not produced by a verified live sandbox execution."
            : "Some analysis stages did not complete successfully. The risk verdict is based on the evidence that was available."}
      </p>
      {provenanceLimited && provenance && (
        <ul className="mb-3 space-y-1.5">
          <li className="text-sm text-status-warning">
            <strong>Sandbox provenance</strong>: {provenance.label}. {provenance.summary}
          </li>
          <li className="text-sm text-status-warning">
            <strong>Containment</strong>: {provenance.containmentLabel}. Sandbox egress
            containment is not asserted for this run.
          </li>
        </ul>
      )}
      {issues.length > 0 && (
        <ul className="space-y-1.5">
          {issues.map((iss) => (
            <li key={iss.stage} className="text-sm text-status-warning">
              <strong>{iss.stage}</strong>:{" "}
              {iss.status === "failed" ? "Failed" : "Skipped"}.
              {iss.error_message ? ` (${iss.error_message})` : ""}
              {" — "}
              {iss.status === "skipped"
                ? "This stage was intentionally bypassed."
                : "Results from this stage could not be evaluated."}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ── 10. Recommended Action ────────────────────────────────────────────────
const ACTION_DESC: Record<string, string> = {
  monitor: "Continue monitoring this application. No immediate action required.",
  alert_customers: "Consider alerting affected users or stakeholders about this application.",
  block_hash: "Block this application hash across managed devices.",
  escalate_cert_in: "Escalate this finding to CERT-In for national incident response.",
};

function RecommendedActionSection({ verdict }: { verdict?: Verdict | null }) {
  if (!verdict?.recommended_action) return null;

  return (
    <section className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <h2 className="mb-3 text-base font-bold text-text-bright">Recommended Action</h2>
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md border border-border bg-background-surface px-4 py-2 text-sm font-semibold text-text-bright">
          {verdict.recommended_action.replace(/_/g, " ").toUpperCase()}
        </span>
        <p className="text-sm text-text-muted">
          {ACTION_DESC[verdict.recommended_action] ?? ""}
        </p>
      </div>
    </section>
  );
}

// ── Main ReportViewer ─────────────────────────────────────────────────────
export default function ReportViewer({
  detail,
  verdict,
  report,
  mlScore,
  virustotal,
  overallState = "COMPLETED",
  issues = [],
  onExport,
}: ReportViewerProps) {
  const exportFn = onExport ?? (() => window.print());
  const ttps = report?.ttp_mapping?.ttp_mapping ?? [];
  const flagged = (report?.sanitization_flags?.count ?? 0) > 0;
  const keyFindings = buildKeyFindings(detail);

  return (
    <article className="space-y-4">
      {/* Export button */}
      <div className="flex justify-end no-print">
        <button
          onClick={exportFn}
          className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-text hover:bg-background-surface transition-colors"
        >
          Export PDF
        </button>
      </div>

      {/* AI evasion warning */}
      {flagged && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800">
          ⚠ AI evasion attempt detected and neutralized — {report?.sanitization_flags.count} prompt-injection string(s) were redacted before analysis.
        </div>
      )}

      {/* 1. Security Summary (always visible, no accordion) */}
      <SecuritySummarySection
        detail={detail}
        verdict={verdict}
        overallState={overallState}
        issues={issues}
      />

      {/* 2. Key Findings */}
      <KeyFindingsSection findings={keyFindings} />

      {/* 3. Static Analysis */}
      <StaticAnalysisSection sf={detail.static_finding} />

      {/* 4. Runtime Behaviour */}
      <RuntimeBehaviourSection detail={detail} />

      {/* 5. Threat Intelligence */}
      <ThreatIntelligenceSection detail={detail} virustotal={virustotal} />

      {/* 6. ML Risk Assessment */}
      <MLRiskSection mlScore={mlScore} />

      {/* 7. LLM Assessment */}
      <LLMAssessmentSection report={report} />

      {/* 8. TTP Mapping */}
      <TTPSection ttps={ttps} />

      {/* 9. Analysis Limitations */}
      <LimitationsSection
        overallState={overallState}
        issues={issues}
        provenance={
          detail.dynamic_finding
            ? deriveSandboxProvenance(detail.dynamic_finding)
            : null
        }
      />

      {/* 10. Recommended Action */}
      <RecommendedActionSection verdict={verdict} />
    </article>
  );
}
