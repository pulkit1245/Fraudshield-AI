// TypeScript mirrors of shared/schemas/*.json. Keep in lockstep with the
// contracts (see shared/API_CONTRACTS.md). Owner: Member D.

export type Role = "analyst" | "lead" | "admin";
export type SeverityBand = "low" | "medium" | "high" | "critical";
export type RecommendedAction =
  | "monitor"
  | "alert_customers"
  | "block_hash"
  | "escalate_cert_in";
export type SubmissionStatus =
  | "queued"
  | "static_running"
  | "dynamic_running"
  | "scoring"
  | "completed"
  | "failed";

// ── auth ──────────────────────────────────────────────────────────────
export interface UserProfile {
  id: string;
  email: string;
  role: Role;
  org_name: string;
  created_at: string;
}
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "bearer";
  expires_in: number;
}
export interface AccessToken {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

// ── submissions ───────────────────────────────────────────────────────
export interface SubmissionSummary {
  id: string;
  original_filename: string;
  sha256_hash: string;
  status: SubmissionStatus;
  submitted_at: string;
  completed_at?: string | null;
  severity_band?: SeverityBand | null;
  final_risk_score?: number | null;
}
export interface PaginatedSubmissions {
  items: SubmissionSummary[];
  total: number;
  page: number;
  page_size: number;
}
export interface SubmissionStatusResponse {
  id: string;
  status: SubmissionStatus;
  progress_pct: number;
}
export interface StaticFindingOut {
  package_name?: string | null;
  permissions: Record<string, unknown>;
  certificate_info?: Record<string, unknown> | null;
  api_call_graph?: Record<string, unknown> | null;
  obfuscation_score?: number | null;
}
export interface VerdictOut {
  final_risk_score: number;
  severity_band: SeverityBand;
  recommended_action: RecommendedAction;
  analyst_override_score?: number | null;
}
export interface SubmissionDetail {
  id: string;
  uploaded_by: string;
  original_filename: string;
  sha256_hash: string;
  status: SubmissionStatus;
  submitted_at: string;
  completed_at?: string | null;
  static_finding?: StaticFindingOut | null;
  verdict?: VerdictOut | null;
}

// ── verdicts ──────────────────────────────────────────────────────────
export interface Verdict {
  submission_id: string;
  final_risk_score: number;
  severity_band: SeverityBand;
  recommended_action: RecommendedAction;
  analyst_override_score?: number | null;
  effective_score: number;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
}

// ── dashboard ─────────────────────────────────────────────────────────
export interface DashboardStats {
  by_severity: Record<SeverityBand, number>;
  queue_depth: number;
  total_submissions: number;
  completed: number;
  avg_triage_seconds: number | null;
}

// ── ml score / report ─────────────────────────────────────────────────
export interface ShapFeature {
  feature: string;
  value: number;
  contribution: number;
  direction: "increases_risk" | "decreases_risk";
}
export interface MLScore {
  classifier_score: number;
  novelty_score: number;
  shap_values: { method: string; top_features: ShapFeature[] };
  model_version: string;
}
export interface TTPEntry {
  id: string;
  name: string;
  confidence: number;
  evidence?: string;
}
export interface ReportPayload {
  summary: string;
  behaviour_chain?: string[];
  key_risks?: string[];
  recommended_action_rationale?: string;
  confidence?: number;
}
export interface LLMReport {
  summary_text: string | null;
  ttp_mapping: {
    ttp_mapping: TTPEntry[];
    primary_technique?: string | null;
    report?: ReportPayload;
  };
  sanitization_flags: { count: number; flags: unknown[] };
  model_used: string;
}

// ── chat ──────────────────────────────────────────────────────────────
export interface ChatSource {
  type: "static_findings" | "ttp";
  id?: string;
  name?: string;
  package_name?: string | null;
}
export interface ChatResponse {
  reply: string;
  sources: ChatSource[];
  cached: boolean;
}
export interface ChatMessage {
  role: "user" | "assistant";
  text: string;
  sources?: ChatSource[];
}

// ── clusters / virustotal ─────────────────────────────────────────────
export interface ClusterSummary {
  id: string;
  cluster_name: string;
  member_count: number;
}
export interface ClusterListResponse {
  items: ClusterSummary[];
  total: number;
}
export interface ClusterDetail {
  id: string;
  cluster_name: string;
  member_count: number;
  members: string[];
}
export interface VirusTotalResult {
  // Mirrors VirustotalService statuses (backend/app/services/virustotal_service.py).
  // Only "ok" carries detection counts; every other status scores as neutral.
  status:
    | "ok"
    | "not_found"
    | "not_configured"
    | "invalid_key"
    | "quota_exceeded"
    | "error";
  sha256: string;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number | null;
  meaningful_name?: string | null;
  detail?: string;
}

// ── API error envelope ────────────────────────────────────────────────
export interface ApiError {
  error: { code: string; message: string; request_id: string };
}
