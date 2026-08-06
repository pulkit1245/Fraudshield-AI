// Submission detail: live pipeline status → report, causal Sankey, risk heatmap,
// chat, VirusTotal, and lead/admin verdict actions. Owner: Member D.
import { useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import ReportViewer from "../components/ReportViewer/ReportViewer";
import CausalChainSankey, {
  type SankeyStage,
} from "../components/SankeyDiagram/CausalChainSankey";
import RiskHeatmap from "../components/RiskHeatmap/RiskHeatmap";
import ChatPanel from "../components/ChatPanel/ChatPanel";
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
import { STATUS_LABEL } from "../utils/format";
import type { LLMReport, SubmissionDetail } from "../types";

// Dangerous Android permissions that indicate elevated risk
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
  // ── Static signals: dangerous permissions found ──────────────────────
  const declared: string[] = (detail?.static_finding?.permissions as { declared?: string[] })?.declared ?? [];
  const dangerousFound = declared.filter((p) => DANGEROUS_PERMS.has(p));
  const staticNodes = dangerousFound.length
    ? dangerousFound.slice(0, 4).map(shortPerm)
    : ["static signals"];

  // ── Behaviour: TTPs detected by LLM report ───────────────────────────
  const ttps = report?.ttp_mapping?.ttp_mapping ?? [];
  const behaviourNodes = ttps.length
    ? ttps.slice(0, 4).map((t) => t.name)
    : ["no behaviour"];

  // ── Verdict: severity band ───────────────────────────────────────────
  const band = detail?.verdict?.severity_band ?? "verdict";
  return [
    { title: "Static signals", nodes: staticNodes },
    { title: "Behaviour (TTPs)", nodes: behaviourNodes },
    { title: "Verdict", nodes: [String(band)] },
  ];
}

export default function SubmissionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { user } = useAuth();

  const detail = useSubmission(id);
  const status = usePolling(id, detail.data?.status !== "completed");
  const currentStatus = status.data?.status ?? detail.data?.status;
  const completed = currentStatus === "completed";

  const verdict = useVerdict(id, completed);
  const report = useReport(id, completed);
  const ml = useMlScore(id, completed);
  const vt = useVirusTotal(id, completed);

  const stages = useMemo(() => buildStages(detail.data, report.data), [detail.data, report.data]);
  const canReview = user?.role === "lead" || user?.role === "admin";

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

  if (detail.isLoading) return <div className="text-sm text-gray-500">Loading…</div>;
  if (detail.isError)
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
        <strong>Error loading submission:</strong>{" "}
        {(detail.error as Error)?.message ?? "Unknown error"}
      </div>
    );
  if (!detail.data)
    return <div className="text-sm text-red-600">Submission not found.</div>;

  return (
    <div className="space-y-6">
      <button onClick={() => navigate("/")} className="no-print text-sm text-indigo-600 hover:underline">
        ← Back to dashboard
      </button>

      {!completed && (
        <div className="rounded-xl border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-800">
          Pipeline running — {STATUS_LABEL[currentStatus ?? "queued"]} (
          {status.data?.progress_pct ?? 0}%). This view updates automatically.
        </div>
      )}

      <ReportViewer detail={detail.data} verdict={verdict.data} report={report.data} />

      {canReview && completed && (
        <div className="no-print flex gap-3">
          <button onClick={onOverride}
            className="rounded-md border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-50">
            Override verdict
          </button>
          <button onClick={() => escalate.mutate()}
            className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-red-700">
            {escalate.isSuccess ? "Escalated ✓" : "Escalate to CERT-In"}
          </button>
        </div>
      )}

      <CausalChainSankey stages={stages} band={detail.data.verdict?.severity_band} />

      {verdict.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-xs text-red-700">
          <strong>Verdict error:</strong> {(verdict.error as Error)?.message}
        </div>
      )}
      {report.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-xs text-red-700">
          <strong>Report error:</strong> {(report.error as Error)?.message}
        </div>
      )}
      {ml.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-xs text-red-700">
          <strong>ML score error:</strong> {(ml.error as Error)?.message}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RiskHeatmap shap={ml.data?.shap_values?.top_features ?? []} />
        {id && <ChatPanel submissionId={id} />}
      </div>

      {vt.data && (
        <div className="rounded-xl border border-gray-200 bg-white p-4 text-sm">
          <h2 className="mb-1 font-semibold text-gray-700">VirusTotal</h2>
          {vt.data.status === "ok" ? (
            <p className="text-gray-700">
              {vt.data.malicious} malicious · {vt.data.suspicious} suspicious ·{" "}
              {vt.data.harmless} harmless
            </p>
          ) : (
            <p className="text-gray-500">Status: {vt.data.status.replace(/_/g, " ")}</p>
          )}
        </div>
      )}
      {vt.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-xs text-red-700">
          <strong>VirusTotal error:</strong> {(vt.error as Error)?.message}
        </div>
      )}
    </div>
  );
}
