// TI pipeline API calls — fallback events and feed status.
// Owner: Member D.
import { api } from "./api";

export interface FallbackEvent {
  ts: string;           // ISO-8601 UTC
  source: string;       // e.g. "mitre_attack", "otx"
  stage: string;        // "fetcher" | "normalizer" | "deduplicator"
  original: string;     // What was intended
  fallback: string;     // What was actually used
  reason: string;       // Why the original failed
}

export async function fetchPipelineFallbacks(): Promise<FallbackEvent[]> {
  return api.get<FallbackEvent[]>("/admin/threat-intelligence/pipeline/fallbacks");
}
