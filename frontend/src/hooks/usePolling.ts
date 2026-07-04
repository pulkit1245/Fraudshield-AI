// Polls GET /submissions/{id}/status every 3s until the pipeline reaches a
// terminal state (completed | failed). Owner: Member D.
import { useQuery } from "@tanstack/react-query";
import { submissionsApi } from "../services/submissions";
import type { SubmissionStatusResponse } from "../types";

const TERMINAL = new Set(["completed", "failed"]);
const POLL_MS = 3000;

export function usePolling(submissionId: string | undefined, enabled = true) {
  return useQuery<SubmissionStatusResponse>({
    queryKey: ["submission-status", submissionId],
    queryFn: () => submissionsApi.status(submissionId as string),
    enabled: enabled && !!submissionId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && TERMINAL.has(status) ? false : POLL_MS;
    },
  });
}
