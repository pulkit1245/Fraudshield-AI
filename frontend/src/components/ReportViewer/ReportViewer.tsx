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
      className="rounded-xl border border-gray-200 bg-white shadow-sm overflow-hidden"
    >
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-gray-50 transition-colors"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-base font-semibold text-gray-900">{title}</span>
          {badge}
        </div>
        <svg
          className={`h-4 w-4 text-gray-400 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="border-t border-gray-100 px-5 py-4">{children}</div>}
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
      <circle cx="60" cy="60" r={radius} fill="none" stroke="#eee" strokeWidth="10" />
      <circle
        cx="60" cy="60" r={radius} fill="none"
        stroke={BAND_COLOR[band]} strokeWidth="10"
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
  const cls = {
    green: "bg-green-100 text-green-800 border-green-200",
    yellow: "bg-amber-100 text-amber-800 border-amber-200",
    red: "bg-red-100 text-red-800 border-red-200",
    gray: "bg-gray-100 text-gray-700 border-gray-200",
  }[color];
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${cls}`}>
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

  const summaryLines: string[] = [];
  if (overallState === "FAILED") {
    summaryLines.push(`Analysis of ${detail.original_filename} failed before a verdict could be determined.`);
  } else if (band && typeof score === "number") {
    summaryLines.push(
      `Analysis of ${detail.original_filename} concluded with a ${band.toUpperCase()} risk assessment (score: ${score}/100).`
    );
    if (isComplete) {
      summaryLines.push("All pipeline stages completed successfully.");
    } else if (overallState === "PARTIALLY_COMPLETED") {
      summaryLines.push(
        `Analysis was partially completed — ${issues.length} stage(s) failed or were skipped. The verdict is based on the available evidence only.`
      );
    }
  } else {
    summaryLines.push(`Analysis of ${detail.original_filename} is in progress or pending a final verdict.`);
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-lg font-bold text-gray-900 break-all">{detail.original_filename}</h1>
          {(detail.static_finding as any)?.package_name && (
            <p className="mt-0.5 text-xs text-gray-500 font-mono">
              {(detail.static_finding as any).package_name}
            </p>
          )}
          <p className="mt-1 font-mono text-xs text-gray-400 break-all">{detail.sha256_hash}</p>
        </div>
        <div className="flex flex-col items-end gap-2">
          {band && <SeverityBadge band={band} />}
          {isComplete ? (
            <StatusPill label="✓ Analysis Complete" color="green" />
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
        <div className="mt-4 flex items-center gap-6 border-t border-gray-100 pt-4">
          <RiskGauge score={score} band={band} />
          <div>
            <p className="text-sm leading-relaxed text-gray-700">{summaryLines.join(" ")}</p>
            {verdict?.analyst_override_score != null && (
              <p className="mt-2 text-xs text-gray-500 flex items-center gap-1">
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
        <p className="mt-3 text-sm text-gray-600 leading-relaxed">{summaryLines[0]}</p>
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

const FIND_SEVERITY_LABELS = {
  critical: { icon: "🔴", label: "Critical", cls: "border-red-400 bg-red-50" },
  high: { icon: "🟠", label: "High", cls: "border-orange-400 bg-orange-50" },
  medium: { icon: "🟡", label: "Medium", cls: "border-amber-400 bg-amber-50" },
};

function KeyFindingsSection({ findings }: { findings: KeyFinding[] }) {
  if (findings.length === 0) return null;
  return (
    <AccordionSection
      id="section-key-findings"
      title="Key Findings"
      defaultOpen={true}
      badge={
        <span className="rounded-full bg-rose-100 px-2 py-0.5 text-xs font-bold text-rose-700">
          {findings.length}
        </span>
      }
    >
      <div className="space-y-3">
        {findings.map((f, i) => {
          const meta = FIND_SEVERITY_LABELS[f.severity];
          return (
            <div key={i} className={`rounded-lg border-l-4 p-3 ${meta.cls}`}>
              <div className="flex items-center gap-2 mb-1">
                <span aria-hidden="true">{meta.icon}</span>
                <span className="text-xs font-bold uppercase tracking-wide text-gray-600">
                  {meta.label} · {f.category === "dynamic" ? "Runtime" : f.category === "network" ? "Network" : "Static"}
                </span>
              </div>
              <p className="text-sm font-semibold text-gray-900">
                <span className="text-gray-500 font-normal">Observed: </span>
                {f.evidence}
              </p>
              <p className="mt-1 text-sm text-gray-700">
                <span className="font-semibold">Why it matters: </span>
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
        <p className="text-sm text-gray-500">
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
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
            APK Metadata
          </h3>
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full text-sm">
              <tbody className="divide-y divide-gray-100">
                {sf.package_name && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-gray-700 w-40">Package Name</td>
                    <td className="px-3 py-2 font-mono text-gray-900 break-all">{sf.package_name}</td>
                  </tr>
                )}
                {sf.obfuscation_score != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-gray-700">Obfuscation Score</td>
                    <td className="px-3 py-2 text-gray-900">
                      {(sf.obfuscation_score * 100).toFixed(0)}%
                      <span className="ml-2 text-xs text-gray-500">
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
                    <td className="px-3 py-2 font-medium text-gray-700">Activities</td>
                    <td className="px-3 py-2 text-gray-900">{acg.activities}</td>
                  </tr>
                )}
                {acg?.services != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-gray-700">Services</td>
                    <td className="px-3 py-2 text-gray-900">{acg.services}</td>
                  </tr>
                )}
                {acg?.receivers != null && (
                  <tr>
                    <td className="px-3 py-2 font-medium text-gray-700">Receivers</td>
                    <td className="px-3 py-2 text-gray-900">{acg.receivers}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Permissions */}
        {perms.length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Permissions ({perms.length} declared)
            </h3>
            {/* Summary pills */}
            <div className="mb-3 flex flex-wrap gap-2 text-xs">
              {highPerms.length > 0 && (
                <span className="rounded-full bg-orange-100 text-orange-800 px-2 py-1 font-medium">
                  🟠 {highPerms.length} High Relevance
                </span>
              )}
              {medPerms.length > 0 && (
                <span className="rounded-full bg-amber-100 text-amber-800 px-2 py-1 font-medium">
                  🟡 {medPerms.length} Moderate Relevance
                </span>
              )}
              {stdPerms.length > 0 && (
                <span className="rounded-full bg-gray-100 text-gray-700 px-2 py-1 font-medium">
                  ⚪ {stdPerms.length} Standard
                </span>
              )}
            </div>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 w-8">Risk</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600">Permission</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 hidden md:table-cell">Status</th>
                    <th className="px-3 py-2 text-left text-xs font-semibold text-gray-600 hidden lg:table-cell">Risk Relevance</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {displayPerms.map((p) => {
                    const cls = classifyPerm(p);
                    const isUsed = used.includes(p);
                    return (
                      <tr key={p} className="hover:bg-gray-50">
                        <td className="px-3 py-2 text-center">
                          {cls === "high" ? (
                            <span title="High relevance" aria-label="High relevance">🟠</span>
                          ) : cls === "medium" ? (
                            <span title="Moderate relevance" aria-label="Moderate relevance">🟡</span>
                          ) : (
                            <span title="Standard" aria-label="Standard">⚪</span>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-gray-900 break-all">
                          {shortPerm(p)}
                        </td>
                        <td className="px-3 py-2 hidden md:table-cell">
                          <span className="text-xs">
                            {isUsed ? (
                              <span className="text-gray-700">Declared + Observed</span>
                            ) : (
                              <span className="text-gray-500">Declared</span>
                            )}
                          </span>
                        </td>
                        <td className="px-3 py-2 hidden lg:table-cell text-xs text-gray-600">
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
                className="mt-2 text-xs text-indigo-600 hover:underline"
              >
                {showAllPerms ? "Show fewer permissions" : `Show all ${perms.length} permissions`}
              </button>
            )}
          </div>
        )}

        {/* Certificate Info */}
        {cert && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Certificate / Signing
            </h3>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-sm">
                <tbody className="divide-y divide-gray-100">
                  {cert.self_signed != null && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-gray-700 w-40">Self-signed</td>
                      <td className="px-3 py-2 text-gray-900">
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
                      <td className="px-3 py-2 font-medium text-gray-700">SHA-1 Fingerprint</td>
                      <td className="px-3 py-2 font-mono text-xs text-gray-900 break-all">{cert.sha1}</td>
                    </tr>
                  )}
                  {cert.not_before && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-gray-700">Valid From</td>
                      <td className="px-3 py-2 text-gray-900">{cert.not_before}</td>
                    </tr>
                  )}
                  {cert.not_after && (
                    <tr>
                      <td className="px-3 py-2 font-medium text-gray-700">Valid Until</td>
                      <td className="px-3 py-2 text-gray-900">{cert.not_after}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* API indicators */}
        {acg?.sensitive_calls && Object.keys(acg.sensitive_calls).length > 0 && (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Sensitive API Indicators
            </h3>
            <div className="flex flex-wrap gap-2">
              {Object.entries(acg.sensitive_calls).map(([cat, calls]: [string, any]) => (
                <span key={cat} className="rounded-md bg-orange-50 border border-orange-200 px-2 py-1 text-xs font-medium text-orange-800">
                  {cat} ({Array.isArray(calls) ? calls.length : 1} call{Array.isArray(calls) && calls.length !== 1 ? "s" : ""})
                </span>
              ))}
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
        <p className="text-sm text-gray-500">
          Runtime behaviour data is unavailable. Dynamic analysis may not have completed or the sandbox was not executed.
        </p>
      </AccordionSection>
    );
  }

  const networkCalls = dyn.network_calls ?? [];
  const anyFlag = dyn.sms_access || dyn.overlay_detected || dyn.accessibility_abuse;

  const behaviourItems = [
    {
      key: "sms_access",
      label: "SMS Activity",
      detected: dyn.sms_access,
      desc: "Application accessed SMS-related functionality during dynamic analysis.",
      matter: WHY_RUNTIME_MATTERS.sms_access,
    },
    {
      key: "overlay_detected",
      label: "Overlay Window",
      detected: dyn.overlay_detected,
      desc: "Application drew an overlay window during dynamic analysis.",
      matter: WHY_RUNTIME_MATTERS.overlay_detected,
    },
    {
      key: "accessibility_abuse",
      label: "Accessibility Service",
      detected: dyn.accessibility_abuse,
      desc: "Application interacted with Accessibility Services during dynamic analysis.",
      matter: WHY_RUNTIME_MATTERS.accessibility_abuse,
    },
  ];

  const badge = anyFlag ? (
    <StatusPill label="Suspicious behaviour observed" color="yellow" />
  ) : (
    <StatusPill label="No suspicious flags" color="green" />
  );

  return (
    <AccordionSection id="section-runtime" title="Runtime Behaviour" defaultOpen={anyFlag} badge={badge}>
      <div className="space-y-4">
        {/* Behaviour flags */}
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Observed Behaviour Flags
          </h3>
          <div className="space-y-2">
            {behaviourItems.map((item) => (
              <div
                key={item.key}
                className={`rounded-lg border p-3 ${
                  item.detected
                    ? "border-orange-200 bg-orange-50"
                    : "border-gray-200 bg-gray-50"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span aria-label={item.detected ? "Detected" : "Not detected"}>
                      {item.detected ? "🟠" : "✅"}
                    </span>
                    <span className="text-sm font-semibold text-gray-900">{item.label}</span>
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                        item.detected
                          ? "bg-orange-100 text-orange-800"
                          : "bg-green-100 text-green-800"
                      }`}
                    >
                      {item.detected ? "Detected" : "Not Detected"}
                    </span>
                  </div>
                </div>
                {item.detected && (
                  <div className="mt-2 ml-6 space-y-1">
                    <p className="text-xs text-gray-700">
                      <span className="font-semibold">Observed: </span>
                      {item.desc}
                    </p>
                    <p className="text-xs text-gray-600">
                      <span className="font-semibold">Why it matters: </span>
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
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Network Connections Observed ({networkCalls.length})
            </h3>
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="w-full text-xs">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-3 py-2 text-left font-semibold text-gray-600">Destination</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-600">Port</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-600">Protocol</th>
                    <th className="px-3 py-2 text-left font-semibold text-gray-600">Classification</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {networkCalls.slice(0, 20).map((call: any, idx: number) => (
                    <tr key={idx} className="hover:bg-gray-50">
                      <td className="px-3 py-2 font-mono text-gray-900">
                        {call.host ?? call.url ?? call.destination ?? "Unknown"}
                      </td>
                      <td className="px-3 py-2 text-gray-700">{call.port ?? "—"}</td>
                      <td className="px-3 py-2 text-gray-700 uppercase">{call.protocol ?? "—"}</td>
                      <td className="px-3 py-2">
                        {call.sink === true ? (
                          <span className="rounded-full bg-orange-100 px-2 py-0.5 text-xs font-medium text-orange-800">
                            Flagged destination
                          </span>
                        ) : (
                          <span className="text-gray-500">Observed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {networkCalls.length > 20 && (
                <div className="px-3 py-2 bg-gray-50 text-xs text-gray-500 text-center border-t border-gray-200">
                  Showing 20 of {networkCalls.length} connections
                </div>
              )}
            </div>
            <p className="mt-1.5 text-xs text-gray-500">
              Note: "Flagged destination" means the sandbox recorded this host as a monitored sink, not confirmed C2 infrastructure unless explicitly stated.
            </p>
          </div>
        ) : (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Network Connections
            </h3>
            <p className="text-sm text-gray-500">No network connections were recorded during dynamic analysis.</p>
          </div>
        )}
      </div>
    </AccordionSection>
  );
}

// ── 5. Threat Intelligence ────────────────────────────────────────────────
function ThreatIntelligenceSection({
  detail,
  virustotal,
}: {
  detail: SubmissionDetail;
  virustotal?: VirusTotalResult | null;
}) {
  const vt = virustotal;

  return (
    <AccordionSection id="section-threat-intel" title="Threat Intelligence" defaultOpen={false}>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* VirusTotal */}
        <div className="rounded-lg border border-gray-200 p-4">
          <h3 className="mb-3 text-sm font-semibold text-gray-800">VirusTotal</h3>
          {!vt ? (
            <p className="text-sm text-gray-500">VirusTotal results are loading or unavailable.</p>
          ) : vt.status === "not_configured" ? (
            <p className="text-sm text-gray-500">
              ⚪ VirusTotal was not configured for this deployment. No results available.
            </p>
          ) : vt.status === "not_found" ? (
            <p className="text-sm text-gray-600">
              ⚪ This file hash was not found in VirusTotal's database. It may be a novel or unreported sample.
            </p>
          ) : vt.status === "error" ? (
            <p className="text-sm text-amber-700">
              ⚠ VirusTotal lookup encountered an error. Results are unavailable.
            </p>
          ) : vt.status === "ok" ? (
            <div className="space-y-3">
              <p className="text-sm text-gray-700">
                <span className="font-semibold text-gray-900">
                  {(vt.malicious ?? 0) + (vt.suspicious ?? 0)}
                </span>{" "}
                of{" "}
                <span className="font-semibold">
                  {(vt.malicious ?? 0) + (vt.suspicious ?? 0) + (vt.harmless ?? 0) + (vt.undetected ?? 0)}
                </span>{" "}
                engines flagged this sample.
              </p>
              <div className="space-y-1.5">
                {[
                  { label: "Malicious", count: vt.malicious ?? 0, color: "bg-red-500" },
                  { label: "Suspicious", count: vt.suspicious ?? 0, color: "bg-amber-500" },
                  { label: "Harmless", count: vt.harmless ?? 0, color: "bg-green-500" },
                  { label: "Undetected", count: vt.undetected ?? 0, color: "bg-gray-300" },
                ].map(({ label, count, color }) => {
                  const total = Math.max(
                    1,
                    (vt.malicious ?? 0) + (vt.suspicious ?? 0) + (vt.harmless ?? 0) + (vt.undetected ?? 0)
                  );
                  const pct = Math.round((count / total) * 100);
                  return (
                    <div key={label} className="flex items-center gap-2 text-xs">
                      <span className="w-20 text-gray-600">{label}</span>
                      <div className="flex-1 rounded-full bg-gray-100 h-2">
                        <div
                          className={`h-2 rounded-full ${color}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-6 text-right text-gray-900 font-medium">{count}</span>
                    </div>
                  );
                })}
              </div>
              {vt.meaningful_name && (
                <p className="text-xs text-gray-600 mt-2">
                  Identified as: <span className="font-semibold">{vt.meaningful_name}</span>
                </p>
              )}
            </div>
          ) : (
            <p className="text-sm text-gray-500">Status: {vt.status}</p>
          )}
        </div>

        {/* Campaign Cluster */}
        <div className="rounded-lg border border-gray-200 p-4">
          <h3 className="mb-3 text-sm font-semibold text-gray-800">Campaign Cluster</h3>
          {detail.cluster ? (
            <div className="space-y-2">
              <p className="text-sm text-gray-700">
                This submission has been associated with cluster:{" "}
                <span className="font-semibold text-gray-900">{detail.cluster.cluster_name}</span>
              </p>
              <p className="text-xs text-gray-500">
                Cluster analysis groups submissions with similar characteristics to identify potential campaign patterns. This is a similarity association, not confirmation of a specific threat.
              </p>
            </div>
          ) : (
            <p className="text-sm text-gray-500">
              ⚪ No cluster association found. This submission was not assigned to any known campaign cluster.
            </p>
          )}
        </div>
      </div>
    </AccordionSection>
  );
}

// ── 6. ML Risk Assessment ─────────────────────────────────────────────────
function MLRiskSection({ mlScore }: { mlScore?: MLScore | null }) {
  if (!mlScore) {
    return (
      <AccordionSection id="section-ml" title="ML Risk Assessment" defaultOpen={false}>
        <p className="text-sm text-gray-500">
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
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {(mlScore.classifier_score * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-gray-500 mt-0.5">Classifier Probability</p>
          </div>
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-center">
            <p className="text-2xl font-bold text-gray-900">
              {(mlScore.novelty_score * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-gray-500 mt-0.5">Novelty Score</p>
            <p className="text-xs text-gray-400">(higher = less similar to known samples)</p>
          </div>
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-3 text-center">
            <p className="text-xs font-mono text-gray-600 mt-1 break-all">{mlScore.model_version}</p>
            <p className="text-xs text-gray-500 mt-0.5">Model Version</p>
          </div>
        </div>

        {hasShap ? (
          <div>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
              Top Contributing Signals (SHAP)
            </h3>
            <p className="mb-3 text-xs text-gray-500">
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
                      <span className="text-xs text-gray-700 w-40 shrink-0 truncate" title={f.feature}>
                        {f.feature}
                      </span>
                      <div className="flex-1 rounded-full bg-gray-100 h-2">
                        <div
                          className={`h-2 rounded-full ${isRisk ? "bg-orange-400" : "bg-green-400"}`}
                          style={{ width: `${Math.max(4, barPct)}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-gray-500 w-16 text-right">
                        {f.contribution.toFixed(4)}
                      </span>
                    </div>
                  );
                })}
            </div>
            <div className="mt-2 flex gap-4 text-xs text-gray-500">
              <span className="flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded bg-orange-400" /> Increases risk
              </span>
              <span className="flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded bg-green-400" /> Decreases risk
              </span>
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-500">
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
        <p className="text-sm leading-relaxed text-gray-700">{summary}</p>
        <p className="text-xs text-gray-400">
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
        <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-bold text-indigo-700">
          {ttps.length}
        </span>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-gray-500">
          These techniques are mapped from backend LLM analysis and are based on observed indicators. Confidence is provided by the analysis model.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {ttps.map((t) => {
            const confPct = Math.round(t.confidence * 100);
            const confColor =
              confPct >= 80
                ? "bg-orange-100 text-orange-800"
                : confPct >= 50
                ? "bg-amber-100 text-amber-800"
                : "bg-gray-100 text-gray-600";
            return (
              <div key={t.id} className="rounded-lg border border-gray-200 p-3">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-semibold text-gray-900">{t.name}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-medium ${confColor}`}>
                    {confPct}% confidence
                  </span>
                </div>
                <div className="font-mono text-xs text-indigo-600 mb-2">{t.id}</div>
                {t.evidence ? (
                  <div className="text-xs text-gray-600 border-l-2 border-indigo-200 pl-2">
                    <span className="font-semibold">Evidence: </span>
                    {t.evidence}
                  </div>
                ) : (
                  <div className="text-xs text-gray-400 border-l-2 border-gray-200 pl-2">
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
}: {
  overallState: AnalysisOverallState;
  issues: AnalysisStage[];
}) {
  if (overallState !== "PARTIALLY_COMPLETED" && overallState !== "FAILED") return null;

  return (
    <section className="rounded-xl border border-yellow-200 bg-yellow-50 p-5">
      <h2 className="mb-2 flex items-center gap-2 text-base font-bold text-yellow-900">
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        Analysis Limitations
      </h2>
      <p className="mb-3 text-sm text-yellow-800">
        {overallState === "FAILED"
          ? "A critical pipeline stage failed. The final risk assessment may be incomplete or unavailable."
          : "Some analysis stages did not complete successfully. The risk verdict is based on the evidence that was available."}
      </p>
      {issues.length > 0 && (
        <ul className="space-y-1.5">
          {issues.map((iss) => (
            <li key={iss.stage} className="text-sm text-yellow-800">
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
    <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <h2 className="mb-3 text-base font-bold text-gray-900">Recommended Action</h2>
      <div className="flex flex-wrap items-center gap-3">
        <span className="rounded-md border border-gray-300 bg-gray-50 px-4 py-2 text-sm font-semibold text-gray-800">
          {verdict.recommended_action.replace(/_/g, " ").toUpperCase()}
        </span>
        <p className="text-sm text-gray-600">
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
          className="rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
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
      <LimitationsSection overallState={overallState} issues={issues} />

      {/* 10. Recommended Action */}
      <RecommendedActionSection verdict={verdict} />
    </article>
  );
}
