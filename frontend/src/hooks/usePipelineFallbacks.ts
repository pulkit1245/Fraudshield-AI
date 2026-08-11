// Hook: polls /admin/threat-intelligence/pipeline/fallbacks every 60s.
// Owner: Member D.
import { useQuery } from "@tanstack/react-query";
import { fetchPipelineFallbacks } from "../services/threatIntelligence";
import type { FallbackEvent } from "../services/threatIntelligence";

export function usePipelineFallbacks() {
  return useQuery<FallbackEvent[]>({
    queryKey: ["pipeline-fallbacks"],
    queryFn: fetchPipelineFallbacks,
    // Poll every 60 seconds — fallback events are infrequent
    refetchInterval: 60_000,
    // Don't refetch on window focus — these are operational logs not live data
    refetchOnWindowFocus: false,
    // Return empty array on error instead of crashing the panel
    placeholderData: [],
  });
}
