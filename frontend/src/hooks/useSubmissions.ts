// TanStack Query wrappers for submissions, verdicts, ml-score, report,
// dashboard and clusters. Owner: Member D.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  clustersApi,
  dashboardApi,
  submissionsApi,
  type QueueFilter,
} from "../services/submissions";

export function useSubmissionsList(filter: QueueFilter) {
  return useQuery({
    queryKey: ["submissions", filter],
    queryFn: () => submissionsApi.list(filter),
    refetchInterval: 5000, // keep the queue fresh while items are processing
  });
}

export function useSubmission(id: string | undefined) {
  return useQuery({
    queryKey: ["submission", id],
    queryFn: () => submissionsApi.get(id as string),
    enabled: !!id,
  });
}

export function useMlScore(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["ml-score", id],
    queryFn: () => submissionsApi.mlScore(id as string),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useReport(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["report", id],
    queryFn: () => submissionsApi.report(id as string),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useVerdict(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["verdict", id],
    queryFn: () => submissionsApi.verdict(id as string),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useVirusTotal(id: string | undefined, enabled = true) {
  return useQuery({
    queryKey: ["virustotal", id],
    queryFn: () => submissionsApi.virustotal(id as string),
    enabled: enabled && !!id,
    retry: false,
  });
}

export function useDashboardStats() {
  return useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: dashboardApi.stats,
    refetchInterval: 10000,
  });
}

export function useClusters() {
  return useQuery({ queryKey: ["clusters"], queryFn: clustersApi.list });
}

export function useCluster(id: string | undefined) {
  return useQuery({
    queryKey: ["cluster", id],
    queryFn: () => clustersApi.get(id as string),
    enabled: !!id,
  });
}

export function useUploadSubmission() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => submissionsApi.upload(file),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["submissions"] }),
  });
}
