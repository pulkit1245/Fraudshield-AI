// Submission detail page — professional APK malware analysis console.
// Phases 7-8-9: structured layout, investigation panel, error resilience.
// Owner: Member D.
import { useMemo, useRef } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import ReportViewer from "../components/ReportViewer/ReportViewer";
import CausalChainSankey, {
  type SankeyStage,
} from "../components/SankeyDiagram/CausalChainSankey";
import RiskHeatmap from "../components/RiskHeatmap/RiskHeatmap";
import ChatPanel from "../components/ChatPanel/ChatPanel";
import LiveAnalysisConsole from "../components/LiveConsole/LiveAnalysisConsole";
import AnalysisCompletenessCard, {
  deriveAnalysisCompleteness,
} from "../components/AnalysisCompleteness/AnalysisCompletenessCard";
import InvestigationPanel, {
  buildAllFindings,
  InvestigationSummary,
} from "../components/InvestigationPanel/InvestigationPanel";
import { useAuth } from "../context/AuthContext";
import { usePolling } from "../hooks/usePolling";
import {
  useMlScore,
  useReport,
  useSubmission,
  useVerdict,
  useVirusTotal,
} from "../hooks/useSubmissions";
import { submissionsApi } from "../services/submissions";
import type { LLMReport, SubmissionDetail } from "../types";
import { formatRelativeTime, shortHash } from "../utils/format";

// ── Causal chain data builder ─────────────────────────────────────────────
const DANGEROUS_PERMS = new Set([
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.SEND_SMS",
  "android.permission.READ_CONTACTS",
  "android.permission.READ_PHONE_STATE",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.RECEIVE_BOOT_COMPLETED",
]);

function shortPerm(p: string): string {
  return p.replace("android.permission.", "");
}

function buildStages(detail?: SubmissionDetail, report?: LLMReport): SankeyStage[] {
  const declared: string[] =
    (detail?.static_finding?.permissions as { declared?: string[] })?.declared ?? [];
  const dangerousFound = declared.filter((p) => DANGEROUS_PERMS.has(p));
  const staticNodes = dangerousFound.length
    ? dangerousFound.slice(0, 4).map(shortPerm)
    : ["static signals"];

  const ttps = report?.ttp_mapping?.ttp_mapping ?? [];
  const behaviourNodes = ttps.length
    ? ttps.slice(0, 4).map((t) => t.name)
    : ["no behaviour"];

  const band = detail?.verdict?.severity_band ?? "verdict";
  return [
    { title: "Static signals", nodes: staticNodes },
    { title: "Behaviour (TTPs)", nodes: behaviourNodes },
    { title: "Verdict", nodes: [String(band)] },
  ];
}

// ── Error boundary wrapper (function component approach) ─────────────────
function SectionErrorBoundary({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  // Simple try-catch in render isn't possible in React, so we use a stable
  // component that catches errors via error state. For now, wrap in a div
  // to isolate each section. Real error boundary would use class component.
  return (
    <div id={`section-boundary-${title.toLowerCase().replace(/\s/g, "-")}`}>
      {children}
    </div>
  );
}

// ── Section error fallback ────────────────────────────────────────────────
function SectionError({ title, message }: { title: string; message: string }) {
  return (
    <div className="rounded-lg border border-status-threat/20 bg-status-threat/10 px-4 py-3 text-sm">
      <p className="font-semibold text-status-threat">{title} unavailable</p>
      <p className="text-status-threat text-xs mt-0.5">{message}</p>
    </div>
  );
}

// ── APK Header card ───────────────────────────────────────────────────────
function APKHeaderCard({ detail, submitted }: { detail: SubmissionDetail; submitted: string }) {
  const sf = detail.static_finding as any;
  return (
    <div className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-bold text-text-bright break-all leading-tight">
            {detail.original_filename}
          </h1>
          {sf?.package_name && (
            <p className="mt-0.5 font-mono text-xs text-text-muted">{sf.package_name}</p>
          )}
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
            <span>
              SHA-256:{" "}
              <span className="font-mono" title={detail.sha256_hash}>
                {shortHash(detail.sha256_hash, 16)}
              </span>
            </span>
            <span>Submitted {formatRelativeTime(submitted)}</span>
            {detail.completed_at && (
              <span>Completed {formatRelativeTime(detail.completed_at)}</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Pipeline status row ────────────────────────────────────────────────────
function PipelineStatusRow({
  stages,
}: {
  stages: Array<{ name: string; done: boolean; failed: boolean }>;
}) {
  return (
    <div className="rounded-xl border border-border bg-background-elevated px-5 py-3 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-text-muted">
        Analysis Pipeline
      </h2>
      <div className="flex flex-wrap gap-2">
        {stages.map((s) => (
          <span
            key={s.name}
            className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
              s.failed
                ? "bg-red-100 text-status-threat"
                : s.done
                ? "bg-green-100 text-status-success"
                : "bg-background-surface text-text-muted"
            }`}
          >
            {s.failed ? "✗" : s.done ? "✓" : "○"} {s.name}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────
export default function SubmissionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { user } = useAuth();
  const reportRef = useRef<HTMLDivElement>(null);

  const detail = useSubmission(id);
  const status = usePolling(id, true);
  const currentStatus = status.data?.status ?? detail.data?.status;
  const completed =
    currentStatus === "completed" || currentStatus === "failed";

  const verdict = useVerdict(id, completed);
  const report = useReport(id, completed);
  const ml = useMlScore(id, completed);
  const vt = useVirusTotal(id, completed);

  const stages = useMemo(
    () => buildStages(detail.data, report.data),
    [detail.data, report.data]
  );

  const canReview = user?.role === "lead" || user?.role === "admin";

  // Sandbox provenance participates in completeness: an all-green pipeline whose
  // dynamic evidence was simulated (or whose provenance was never recorded) is
  // COMPLETED_UNVERIFIED, not COMPLETED.
  const { state: overallState, issues } = deriveAnalysisCompleteness(
    status.data,
    detail.data?.dynamic_finding
  );
  const isPartialAnalysis =
    overallState === "PARTIALLY_COMPLETED" || overallState === "FAILED";

  // Build investigation findings from all available data
  const allFindings = useMemo(
    () =>
      detail.data
        ? buildAllFindings(detail.data, report.data, ml.data, vt.data)
        : [],
    [detail.data, report.data, ml.data, vt.data]
  );

  const ttps = report.data?.ttp_mapping?.ttp_mapping ?? [];

  // Pipeline status row data
  const pipelineStages = useMemo(() => {
    const backendStages = status.data?.analysis_stages ?? [];
    const stageNames = [
      "Static Analysis",
      "Dynamic Analysis",
      "Threat Intelligence",
      "ML Risk Scoring",
      "LLM Security Report",
      "Final Verdict",
    ];
    return stageNames.map((name) => {
      if (name === "Final Verdict") {
        return { name, done: completed, failed: currentStatus === "failed" };
      }
      const match = backendStages.find((s) => s.stage === name);
      return {
        name,
        done: match?.status === "completed",
        failed: match?.status === "failed" || match?.status === "skipped",
      };
    });
  }, [status.data, completed, currentStatus]);

  // Override / escalate
  const override = useMutation({
    mutationFn: (vars: { score: number; reason: string }) =>
      submissionsApi.override(id as string, vars.score, vars.reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["verdict", id] }),
  });
  const escalate = useMutation({
    mutationFn: () => submissionsApi.escalate(id as string, "cert_in"),
  });

  function onOverride() {
    const raw = window.prompt("Override risk score (0–100):");
    if (raw == null) return;
    const score = Number(raw);
    if (Number.isNaN(score) || score < 0 || score > 100) return;
    const reason = window.prompt("Reason for override:") ?? "manual review";
    override.mutate({ score, reason });
  }

  function navigateToSection(sectionId: string) {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // ── Loading / Error states ─────────────────────────────────────────────
  if (detail.isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-24 rounded-xl bg-background-surface" />
        <div className="h-12 rounded-xl bg-background-surface" />
        <div className="h-48 rounded-xl bg-background-surface" />
      </div>
    );
  }

  if (detail.isError) {
    return (
      <div className="rounded-xl border border-status-threat/20 bg-status-threat/10 p-6 text-sm text-status-threat">
        <p className="font-semibold">Failed to load submission</p>
        <p className="mt-1 text-status-threat">
          {(detail.error as Error)?.message ?? "Unknown error"}
        </p>
        <button
          onClick={() => navigate("/")}
          className="mt-3 text-primary-cyan hover:underline text-xs"
        >
          ← Return to dashboard
        </button>
      </div>
    );
  }

  if (!detail.data) {
    return (
      <div className="rounded-xl border border-border bg-background-elevated p-6 text-center text-sm text-text-muted">
        <p className="font-semibold text-text">Submission not found</p>
        <button
          onClick={() => navigate("/")}
          className="mt-3 text-primary-cyan hover:underline text-xs"
        >
          ← Return to dashboard
        </button>
      </div>
    );
  }

  const d = detail.data;

  return (
    <div className="space-y-5">
      {/* Back navigation */}
      <button
        onClick={() => navigate("/")}
        className="no-print flex items-center gap-1 text-sm text-primary-cyan hover:underline"
      >
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
        </svg>
        Back to dashboard
      </button>

      {/* ── APK Header ─────────────────────────────────────────────────── */}
      <APKHeaderCard detail={d} submitted={d.submitted_at} />

      {/* ── Analysis Pipeline (Live console) ───────────────────────────── */}
      <SectionErrorBoundary title="Timeline">
        {status.data && <LiveAnalysisConsole statusData={status.data} detail={d} virustotal={vt.data} mlScore={ml.data} report={report.data} />}
      </SectionErrorBoundary>

      {/* Completeness card (partial/failed warnings) */}
      <SectionErrorBoundary title="Completeness">
        <AnalysisCompletenessCard
          statusData={status.data ?? null}
          dynamicFinding={detail.data?.dynamic_finding}
        />
      </SectionErrorBoundary>

      {/* Pipeline status row (compact stage summary) */}
      {completed && (
        <PipelineStatusRow stages={pipelineStages} />
      )}

      {/* ── Investigation Summary ──────────────────────────────────────── */}
      {completed && (
        <SectionErrorBoundary title="Investigation Summary">
          <InvestigationSummary
            verdict={verdict.data}
            findings={allFindings}
            ttps={ttps}
            overallState={overallState}
            virustotal={vt.data}
            detail={d}
          />
        </SectionErrorBoundary>
      )}

      {/* ── Main Report ────────────────────────────────────────────────── */}
      <div ref={reportRef}>
        <SectionErrorBoundary title="Report">
          <ReportViewer
            detail={d}
            verdict={verdict.data}
            report={report.data}
            mlScore={ml.data}
            virustotal={vt.data}
            overallState={overallState}
            issues={issues}
          />
        </SectionErrorBoundary>
      </div>

      {/* ── Causal Behaviour Chain ─────────────────────────────────────── */}
      <SectionErrorBoundary title="Causal Chain">
        <div>
          <h2 className="mb-2 text-sm font-semibold text-text">Causal Behaviour Chain</h2>
          <CausalChainSankey stages={stages} band={d.verdict?.severity_band} />
        </div>
      </SectionErrorBoundary>

      {/* ── SHAP Risk Heatmap ──────────────────────────────────────────── */}
      <SectionErrorBoundary title="SHAP Heatmap">
        {ml.isError ? (
          <SectionError title="ML Score" message={(ml.error as Error)?.message ?? "Unavailable"} />
        ) : (
          <RiskHeatmap shap={ml.data?.shap_values?.top_features ?? []} />
        )}
      </SectionErrorBoundary>

      {/* ── Investigation Panel ────────────────────────────────────────── */}
      {completed && (
        <SectionErrorBoundary title="Investigation">
          <InvestigationPanel
            findings={allFindings}
            stages={status.data?.analysis_stages ?? []}
            onNavigateToSection={navigateToSection}
          />
        </SectionErrorBoundary>
      )}

      {/* ── APK Security Assistant ─────────────────────────────────────── */}
      <SectionErrorBoundary title="Chat">
        {id && (
          <div>
            <ChatPanel
              submissionId={id}
              isPartialAnalysis={isPartialAnalysis}
            />
          </div>
        )}
      </SectionErrorBoundary>

      {/* ── Analyst Actions (lead/admin) ────────────────────────────────── */}
      {canReview && completed && (
        <div className="no-print flex flex-wrap gap-3">
          <button
            id="btn-override-verdict"
            onClick={onOverride}
            className="rounded-md border border-border px-4 py-2 text-sm font-medium text-text hover:bg-background-surface transition-colors"
          >
            Override verdict
          </button>
          <button
            id="btn-escalate-certin"
            onClick={() => escalate.mutate()}
            className="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 transition-colors"
          >
            {escalate.isSuccess ? "Escalated to CERT-In ✓" : "Escalate to CERT-In"}
          </button>
        </div>
      )}

      {/* ── Section-level API error notices ────────────────────────────── */}
      {verdict.isError && (
        <SectionError
          title="Verdict"
          message={(verdict.error as Error)?.message ?? "Verdict data could not be loaded."}
        />
      )}
      {report.isError && (
        <SectionError
          title="LLM Report"
          message={(report.error as Error)?.message ?? "Report data could not be loaded."}
        />
      )}
      {vt.isError && (
        <SectionError
          title="VirusTotal"
          message={(vt.error as Error)?.message ?? "VirusTotal data could not be loaded."}
        />
      )}
    </div>
  );
}
