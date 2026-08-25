import { useEffect, useState } from "react";
import type { SubmissionStatusResponse } from "../../types";

interface Props {
  statusData: SubmissionStatusResponse;
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

type StageState = "completed" | "running" | "pending" | "failed" | "skipped";

interface DerivedStage {
  name: string;
  state: StageState;
  errorMessage?: string;
}

function getIconForState(state: StageState) {
  switch (state) {
    case "completed":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-green-100 text-status-success" aria-label="Completed">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </span>
      );
    case "running":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary-blue/10 text-primary-cyan animate-pulse" aria-label="Running">
          <span className="h-2.5 w-2.5 rounded-full bg-primary-blue"></span>
        </span>
      );
    case "pending":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full border-2 border-border bg-background-elevated" aria-label="Pending">
          <span className="h-1.5 w-1.5 rounded-full bg-gray-300"></span>
        </span>
      );
    case "failed":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-red-100 text-red-600" aria-label="Failed">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </span>
      );
    case "skipped":
      return (
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-background-surface text-text-muted" aria-label="Skipped">
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
        </span>
      );
  }
}

function ElapsedTime({ startedAt }: { startedAt: string }) {
  const [elapsed, setElapsed] = useState("");

  useEffect(() => {
    const start = new Date(startedAt).getTime();
    
    // Initial update
    const update = () => {
      const now = Date.now();
      const diff = Math.max(0, Math.floor((now - start) / 1000));
      const m = Math.floor(diff / 60).toString().padStart(2, "0");
      const s = (diff % 60).toString().padStart(2, "0");
      setElapsed(`${m}:${s}`);
    };
    update();

    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [startedAt]);

  return <span>{elapsed || "00:00"}</span>;
}

export default function AnalysisTimeline({ statusData }: Props) {
  const backendStages = statusData.analysis_stages ?? [];
  const isGlobalTerminal =
    statusData.status === "completed" || statusData.status === "failed";

  const hasAnyFailedOrSkipped = backendStages.some(
    (s) => s.status === "failed" || s.status === "skipped"
  );
  
  const isPartiallyComplete =
    statusData.status === "completed" && hasAnyFailedOrSkipped;

  const currentRunningStage = backendStages.find((s) => s.status === "running");

  const derivedStages: DerivedStage[] = EXPECTED_STAGES.map((expectedName) => {
    if (expectedName === "APK Received") {
      return { name: expectedName, state: "completed" };
    }
    if (expectedName === "Final Verdict") {
      return {
        name: expectedName,
        state: isGlobalTerminal ? "completed" : "pending",
      };
    }

    const match = backendStages.find((s) => s.stage === expectedName);
    if (!match) {
      return { name: expectedName, state: "pending" };
    }

    return {
      name: expectedName,
      state: match.status,
      errorMessage: match.error_message ?? undefined,
    };
  });

  return (
    <div className="mb-8 overflow-hidden rounded-xl border border-border bg-background-elevated shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
      <div className="border-b border-border bg-background-surface/50 p-5">
        <h2 className="text-lg font-semibold text-text-bright">Live Analysis Console</h2>
        {isPartiallyComplete && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-status-warning/20 bg-status-warning/10 p-3 text-sm text-status-warning">
            <span className="mt-0.5 text-yellow-600">
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </span>
            <div>
              <strong className="block font-semibold">Analysis Partially Complete</strong>
              <p className="mt-0.5">
                Some stages could not be completed successfully. The final verdict is therefore based on the available analysis signals.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3">
        {/* Timeline (Left 2/3) */}
        <div className="col-span-2 border-b border-border p-6 md:border-b-0 md:border-r">
          <h3 className="mb-6 text-sm font-medium uppercase tracking-wider text-text-muted">Pipeline Timeline</h3>
          <div className="relative">
            {/* Vertical connecting line */}
            <div className="absolute bottom-4 left-3 top-4 w-0.5 -translate-x-1/2 bg-gray-200"></div>

            <div className="space-y-6">
              {derivedStages.map((stage) => (
                <div key={stage.name} className="relative flex items-start gap-4">
                  <div className="relative z-10 bg-background-elevated ring-4 ring-white">
                    {getIconForState(stage.state)}
                  </div>
                  <div className="flex-1 pt-0.5">
                    <p className={`font-medium ${stage.state === 'pending' ? 'text-text-muted/50' : 'text-text-bright'}`}>
                      {stage.name}
                    </p>
                    
                    {stage.state === "running" && (
                      <p className="mt-1 text-sm text-primary-cyan">Currently running...</p>
                    )}
                    {stage.state === "failed" && (
                      <div className="mt-1.5 rounded bg-status-threat/10 p-2 text-sm text-status-threat">
                        <span className="font-semibold">Reason:</span> {stage.errorMessage || "Unknown error"}
                        <div className="mt-1 font-semibold">Impact:</div>
                        <div className="text-red-600">Stage results could not be fully evaluated.</div>
                      </div>
                    )}
                    {stage.state === "skipped" && (
                      <p className="mt-1 text-sm text-text-muted">Skipped {stage.errorMessage ? `- ${stage.errorMessage}` : ""}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Currently Happening Card (Right 1/3) */}
        <div className="bg-background-surface p-6">
          <h3 className="mb-4 text-sm font-medium uppercase tracking-wider text-text-muted">Currently Happening</h3>
          
          <div className="rounded-lg border border-border bg-background-elevated p-5 shadow-[0_4px_12px_rgba(0,0,0,0.1)]">
            {!isGlobalTerminal ? (
              <>
                <div className="mb-3 flex items-center gap-2 border-b border-border pb-3">
                  <span className="relative flex h-3 w-3">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-indigo-400 opacity-75"></span>
                    <span className="relative inline-flex h-3 w-3 rounded-full bg-indigo-500"></span>
                  </span>
                  <span className="font-semibold text-indigo-900">
                    {currentRunningStage?.stage || "Processing"}
                  </span>
                </div>
                <div className="mb-1 text-sm font-medium text-text-bright">
                  {statusData.stage_detail?.current_step || "Active"}
                </div>
                <p className="text-sm text-text-muted">
                  {statusData.stage_detail?.step_description || "Executing background task..."}
                </p>
                {currentRunningStage?.started_at && (
                  <p className="mt-4 text-sm font-medium text-primary-cyan">
                    Elapsed: <ElapsedTime startedAt={currentRunningStage.started_at} />
                  </p>
                )}
              </>
            ) : statusData.status === "failed" ? (
              <div className="text-center">
                <div className="mx-auto mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
                  <svg className="h-5 w-5 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                </div>
                <span className="font-semibold text-status-threat">Analysis Failed</span>
                <p className="mt-1 text-sm text-red-600">
                  The pipeline encountered an error and stopped.
                </p>
              </div>
            ) : (
              <div className="text-center">
                <div className="mx-auto mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-green-100">
                  <svg className="h-5 w-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <span className="font-semibold text-status-success">Analysis Complete</span>
                <p className="mt-1 text-sm text-text-muted">Pipeline has finished all operations.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
