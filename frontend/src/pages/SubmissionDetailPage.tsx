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
import type { SubmissionDetail } from "../types";

const BEHAVIOUR_LABEL: Record<string, string> = {
  sms: "SMS / OTP access",
  overlay: "Overlay window",
  accessibility: "Accessibility abuse",
  telephony: "Phone-state read",
  install: "Silent install",
  dynamic_code: "Dynamic code load",
};

const STATIC_LABEL: Record<string, string> = {
  sms: "SMS Permission",
  overlay: "Overlay API",
  accessibility: "Accessibility API",
  telephony: "Telephony API",
  install: "Installer API",
  dynamic_code: "DexClassLoader",
};

function buildStages(detail?: SubmissionDetail): SankeyStage[] {
  const graph = (detail?.static_finding?.api_call_graph ?? {}) as {
    sensitive_calls?: Record<string, number>;
  };
  const active = Object.entries(graph.sensitive_calls ?? {})
    .filter(([, v]) => v)
    .map(([k]) => k);
  const staticNodes = active.length
    ? active.slice(0, 4).map((k) => STATIC_LABEL[k] ?? k.replace(/_/g, " "))
    : ["static signals"];
  const behaviourNodes = active.length
    ? active.slice(0, 4).map((k) => BEHAVIOUR_LABEL[k] ?? k.replace(/_/g, " "))
    : ["no behaviour"];
  const band = detail?.verdict?.severity_band ?? "verdict";
  return [
    { title: "Static signals", nodes: staticNodes },
    { title: "Behaviour", nodes: behaviourNodes },
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

  const stages = useMemo(() => buildStages(detail.data), [detail.data]);
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
  if (detail.isError || !detail.data)
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
    </div>
  );
}
