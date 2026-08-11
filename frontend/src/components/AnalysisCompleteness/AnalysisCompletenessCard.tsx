import type { AnalysisStage, SubmissionStatusResponse } from "../../types";

export type AnalysisOverallState =
  | "ANALYZING"
  | "COMPLETED"
  | "PARTIALLY_COMPLETED"
  | "FAILED"
  | "NOT_STARTED";

export function deriveAnalysisCompleteness(
  statusData?: SubmissionStatusResponse | null
): {
  state: AnalysisOverallState;
  completedCount: number;
  totalCount: number;
  issues: AnalysisStage[];
} {
  if (!statusData) {
    return { state: "NOT_STARTED", completedCount: 0, totalCount: 7, issues: [] };
  }

  const { status, analysis_stages } = statusData;
  const stages = analysis_stages || [];

  if (status === "queued") {
    return { state: "NOT_STARTED", completedCount: 0, totalCount: 7, issues: [] };
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

  let state: AnalysisOverallState = "ANALYZING";
  if (status === "failed") {
    state = "FAILED";
  } else if (status === "completed") {
    if (issues.length > 0) {
      state = "PARTIALLY_COMPLETED";
    } else {
      state = "COMPLETED";
    }
  }

  return { state, completedCount, totalCount, issues };
}

interface Props {
  statusData: SubmissionStatusResponse | null;
}

export default function AnalysisCompletenessCard({ statusData }: Props) {
  const { state, completedCount, totalCount, issues } = deriveAnalysisCompleteness(statusData);

  if (state === "NOT_STARTED" || state === "ANALYZING") {
    return null;
  }

  return (
    <div className="space-y-6">
      {/* Overview Card */}
      {state === "PARTIALLY_COMPLETED" && (
        <div className="rounded-xl border border-yellow-300 bg-yellow-50 p-5 shadow-sm">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h2 className="text-lg font-bold text-yellow-900 uppercase tracking-wide">
              Analysis Partially Complete
            </h2>
          </div>
          <p className="mb-4 text-sm font-medium text-yellow-800">
            {completedCount} of {totalCount} analysis stages completed
          </p>
          <p className="text-sm text-yellow-800">
            The final assessment is based on the analysis signals that were successfully collected.
          </p>
        </div>
      )}

      {state === "FAILED" && (
        <div className="rounded-xl border border-red-300 bg-red-50 p-5 shadow-sm">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-bold text-red-900 uppercase tracking-wide">
              Analysis Failed
            </h2>
          </div>
          <p className="mb-4 text-sm font-medium text-red-800">
            {completedCount} of {totalCount} analysis stages completed
          </p>
          <p className="text-sm text-red-800">
            A critical stage failed, preventing a full assessment. Risk verdict is unavailable.
          </p>
        </div>
      )}

      {state === "COMPLETED" && (
        <div className="rounded-xl border border-green-300 bg-green-50 p-5 shadow-sm">
          <div className="mb-2 flex items-center gap-2">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h2 className="text-lg font-bold text-green-900 uppercase tracking-wide">
              Analysis Complete
            </h2>
          </div>
          <p className="text-sm text-green-800">
            All required security analysis stages completed successfully.
          </p>
        </div>
      )}

      {/* Analysis Issues Section */}
      {issues.length > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
          <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-gray-700">
            Analysis Issues
          </h3>
          <div className="space-y-4">
            {issues.map((issue) => (
              <div key={issue.stage} className="rounded-lg border border-gray-100 bg-gray-50 p-4">
                <div className="mb-2 flex items-center gap-2">
                  {issue.status === "failed" ? (
                    <svg className="h-5 w-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                  ) : (
                    <svg className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                    </svg>
                  )}
                  <span className="font-semibold text-gray-900">{issue.stage}</span>
                </div>
                
                <div className="mb-2 grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-gray-700">Status:</span>
                  <span className="capitalize text-gray-900">{issue.status}</span>
                </div>
                
                <div className="mb-2 grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-gray-700">Reason:</span>
                  <span className="text-gray-800">
                    {issue.error_message || "Additional details are unavailable."}
                  </span>
                </div>
                
                <div className="grid grid-cols-[80px_1fr] items-baseline gap-2 text-sm">
                  <span className="font-semibold text-gray-700">Impact:</span>
                  <span className="text-gray-800">
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
