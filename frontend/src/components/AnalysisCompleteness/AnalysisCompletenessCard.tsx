import type {
  AnalysisStage,
  DynamicFindingOut,
  SubmissionStatusResponse,
} from "../../types";
import {
  deriveSandboxProvenance,
  type SandboxProvenance,
} from "../../utils/sandboxProvenance";

export type AnalysisOverallState =
  | "ANALYZING"
  | "COMPLETED"
  // Every stage reported success, but the dynamic evidence was not produced by a
  // live sandbox run (simulated, external, or provenance unrecorded). Stage
  // bookkeeping alone cannot see this, which is why a simulated run used to
  // render the green "Analysis Complete" banner.
  | "COMPLETED_UNVERIFIED"
  | "PARTIALLY_COMPLETED"
  | "FAILED"
  | "NOT_STARTED";

export function deriveAnalysisCompleteness(
  statusData?: SubmissionStatusResponse | null,
  // Optional so existing callers keep working. Semantics of the three cases:
  //   undefined → not loaded / not known: do NOT downgrade, or the banner would
  //               flicker amber on every page load before the detail arrives.
  //   null      → confirmed absent: the dynamic stage itself is the problem and
  //               the stage-based `issues` logic below already reports it.
  //   object    → evaluate provenance.
  dynamicFinding?: DynamicFindingOut | null
): {
  state: AnalysisOverallState;
  completedCount: number;
  totalCount: number;
  issues: AnalysisStage[];
  /** Present only when a dynamic finding was supplied. */
  provenance: SandboxProvenance | null;
} {
  if (!statusData) {
    return {
      state: "NOT_STARTED",
      completedCount: 0,
      totalCount: 7,
      issues: [],
      provenance: null,
    };
  }

  const { status, analysis_stages } = statusData;
  const stages = analysis_stages || [];

  if (status === "queued") {
    return {
      state: "NOT_STARTED",
      completedCount: 0,
      totalCount: 7,
      issues: [],
      provenance: null,
    };
  }

  const EXPECTED_STAGES = [
    "APK Received",
    "Static Analysis",
    "Dynamic Analysis",
    "Threat Intelligence",
    "ML Risk Scoring",
    "LLM Security Report",
    "Final Verdict",
  ];
  const totalCount = EXPECTED_STAGES.length;

  let completedCount = 1; // APK Received is always completed
  if (status === "completed" || status === "failed") {
    completedCount += 1; // Final Verdict stage is reached when terminal
  }

  stages.forEach((s) => {
    if (s.status === "completed") completedCount++;
  });

  const issues = stages.filter((s) => s.status === "failed" || s.status === "skipped");

  const provenance = dynamicFinding
    ? deriveSandboxProvenance(dynamicFinding)
    : null;

  let state: AnalysisOverallState = "ANALYZING";
  if (status === "failed") {
    state = "FAILED";
  } else if (status === "completed") {
    if (issues.length > 0) {
      state = "PARTIALLY_COMPLETED";
    } else if (provenance?.degraded) {
      // Stages are all green but the runtime evidence is not from a live run.
      // Deliberately does NOT add a synthetic entry to `issues`: `issues` is a
      // list of real AnalysisStage records, and inventing one would be the same
      // fabrication defect this phase exists to remove.
      state = "COMPLETED_UNVERIFIED";
    } else {
      state = "COMPLETED";
    }
  }

  return { state, completedCount, totalCount, issues, provenance };
}

interface Props {
  statusData: SubmissionStatusResponse | null;
  dynamicFinding?: DynamicFindingOut | null;
}

export default function AnalysisCompletenessCard({ statusData, dynamicFinding }: Props) {
  const { state, completedCount, totalCount, issues, provenance } =
    deriveAnalysisCompleteness(statusData, dynamicFinding);

  if (state === "NOT_STARTED" || state === "ANALYZING") {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      {state === "PARTIALLY_COMPLETED" && (
        <div className="rounded-xl border border-yellow-300 bg-status-warning/10 p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h2 className="text-lg font-bold text-yellow-900 uppercase tracking-wide">
              Analysis Partially Complete
            </h2>
          </div>
          <p className="mb-4 text-sm font-medium text-status-warning">
            {completedCount} of {totalCount} analysis stages completed
          </p>
          <p className="text-sm text-status-warning">
            The final assessment is based on the analysis signals that were successfully collected.
          </p>
        </div>
      )}

      {state === "FAILED" && (
        <div className="rounded-xl border border-red-300 bg-status-threat/10 p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-bold text-red-900 uppercase tracking-wide">
              Analysis Failed
            </h2>
          </div>
          <p className="mb-4 text-sm font-medium text-status-threat">
            {completedCount} of {totalCount} analysis stages completed
          </p>
          <p className="text-sm text-status-threat">
            A critical stage failed, preventing a full assessment. Risk verdict is unavailable.
          </p>
        </div>
      )}

      {state === "COMPLETED_UNVERIFIED" && (
        <div className="rounded-xl border border-amber-300 bg-amber-50 p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h2 className="text-lg font-bold text-amber-900 uppercase tracking-wide">
              Complete — Runtime Evidence Unverified
            </h2>
          </div>
          <p className="mb-4 text-sm font-medium text-amber-800">
            {completedCount} of {totalCount} analysis stages completed
          </p>
          <p className="text-sm text-amber-800">
            Every pipeline stage reported success, but the runtime behaviour in this
            report did not come from a verified live sandbox execution. Static and
            intelligence findings are unaffected.
          </p>
        </div>
      )}

      {state === "COMPLETED" && (
        <div className="rounded-xl border border-green-300 bg-status-success/10 p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-bold text-green-900 uppercase tracking-wide">
              Analysis Complete
            </h2>
          </div>
          <p className="text-sm text-status-success">
            All required security analysis stages completed successfully.
          </p>
        </div>
      )}

      {/* Sandbox provenance detail — shown for any terminal state whose dynamic
          evidence was not produced by a live run, so the reason is visible even
          when a stage failure already downgraded the banner above. */}
      {provenance?.degraded && (
        <div className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-text">
            Sandbox Provenance
          </h3>
          <div className="mb-2 grid grid-cols-[140px_1fr] items-baseline gap-2 text-sm">
            <span className="font-semibold text-text">Execution:</span>
            <span className="text-text-bright">{provenance.label}</span>
          </div>
          <div className="mb-2 grid grid-cols-[140px_1fr] items-baseline gap-2 text-sm">
            <span className="font-semibold text-text">Containment:</span>
            <span className="text-text-bright">{provenance.containmentLabel}</span>
          </div>
          <div className="grid grid-cols-[140px_1fr] items-baseline gap-2 text-sm">
            <span className="font-semibold text-text">Impact:</span>
            <span className="text-text-bright">{provenance.summary}</span>
          </div>
        </div>
      )}

      {/* Analysis Issues Section */}
      {issues.length > 0 && (
        <div className="rounded-xl border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-text">
            Analysis Issues
          </h3>
          <div className="space-y-4">
            {issues.map((issue) => (
              <div key={issue.stage} className="rounded-lg border border-border bg-background-surface p-4">
                <div className="mb-2 flex items-center gap-2">
                  {issue.status === "failed" ? (
                    <svg className="h-5 w-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  ) : (
                    <svg className="h-5 w-5 text-text-muted/50" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                    </svg>
                  )}
                  <span className="font-semibold text-text-bright">{issue.stage}</span>
                </div>
                
                <div className="mb-2 grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-text">Status:</span>
                  <span className="capitalize text-text-bright">{issue.status}</span>
                </div>
                
                <div className="mb-2 grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-text">Reason:</span>
                  <span className="text-text-bright">
                    {issue.error_message || "Additional details are unavailable."}
                  </span>
                </div>
                
                <div className="grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-text">Impact:</span>
                  <span className="text-text-bright">
                    {issue.status === "skipped"
                      ? "This analysis phase was intentionally bypassed and not included in this assessment."
                      : "Results from this stage could not be evaluated."}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
