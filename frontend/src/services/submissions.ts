// Submission / verdict / dashboard / chat / cluster / VT API calls.
// Matches every shape in shared/schemas exactly. Owner: Member D.
import { api } from "./api";
import type {
  ChatResponse,
  ClusterDetail,
  ClusterListResponse,
  DashboardStats,
  LLMReport,
  MLScore,
  PaginatedSubmissions,
  SubmissionDetail,
  SubmissionStatusResponse,
  SubmissionSummary,
  Verdict,
  VirusTotalResult,
} from "../types";

export interface QueueFilter {
  status?: string;
  severity?: string;
  page?: number;
  page_size?: number;
}

function qs(filter: QueueFilter): string {
  const p = new URLSearchParams();
  if (filter.status) p.set("status", filter.status);
  if (filter.severity) p.set("severity", filter.severity);
  p.set("page", String(filter.page ?? 1));
  p.set("page_size", String(filter.page_size ?? 20));
  return p.toString();
}

export const submissionsApi = {
  list: (filter: QueueFilter = {}) =>
    api.get<PaginatedSubmissions>(`/submissions?${qs(filter)}`),

  get: (id: string) => api.get<SubmissionDetail>(`/submissions/${id}`),

  status: (id: string) =>
    api.get<SubmissionStatusResponse>(`/submissions/${id}/status`),

  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api.upload<{ id: string; status: string; sha256_hash: string }>(
      "/submissions",
      form,
    );
  },

  remove: (id: string) => api.del<void>(`/submissions/${id}`),

  mlScore: (id: string) => api.get<MLScore>(`/submissions/${id}/ml-score`),

  report: (id: string) => api.get<LLMReport>(`/submissions/${id}/report`),

  verdict: (id: string) => api.get<Verdict>(`/submissions/${id}/verdict`),

  override: (id: string, overrideScore: number, reason: string) =>
    api.patch<Verdict>(`/submissions/${id}/verdict/override`, {
      override_score: overrideScore,
      reason,
    }),

  escalate: (id: string, destination = "cert_in", note?: string) =>
    api.post<{ submission_id: string; escalated: boolean; ioc_record: unknown }>(
      `/submissions/${id}/verdict/escalate`,
      { destination, note },
    ),

  chat: (id: string, message: string) =>
    api.post<ChatResponse>(`/submissions/${id}/chat`, { message }),

  virustotal: (id: string) =>
    api.get<VirusTotalResult>(`/submissions/${id}/virustotal`),
};

export const dashboardApi = {
  stats: () => api.get<DashboardStats>("/dashboard/stats"),
  queue: () => api.get<{ items: SubmissionSummary[]; count: number }>("/dashboard/queue"),
};

export const clustersApi = {
  list: () => api.get<ClusterListResponse>("/clusters"),
  get: (id: string) => api.get<ClusterDetail>(`/clusters/${id}`),
  recompute: () => api.post<{ clusters_recomputed: number }>("/clusters/recompute"),
};
