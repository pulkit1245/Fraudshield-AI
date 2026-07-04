import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ReportViewer from "../src/components/ReportViewer/ReportViewer";
import type { LLMReport, SubmissionDetail, Verdict } from "../src/types";

const detail: SubmissionDetail = {
  id: "11111111-1111-1111-1111-111111111111",
  uploaded_by: "22222222-2222-2222-2222-222222222222",
  original_filename: "fraud-bank.apk",
  sha256_hash: "a".repeat(64),
  status: "completed",
  submitted_at: new Date().toISOString(),
  completed_at: new Date().toISOString(),
  static_finding: null,
  verdict: null,
};

const verdict: Verdict = {
  submission_id: detail.id,
  final_risk_score: 96,
  severity_band: "critical",
  recommended_action: "escalate_cert_in",
  analyst_override_score: null,
  effective_score: 96,
};

const report: LLMReport = {
  summary_text: "This sample intercepts SMS OTPs and draws overlay login screens.",
  ttp_mapping: {
    ttp_mapping: [
      { id: "TTP-OTP-INTERCEPT", name: "SMS OTP Interception", confidence: 0.9, evidence: "reads SMS" },
    ],
    primary_technique: "TTP-OTP-INTERCEPT",
    report: { summary: "", behaviour_chain: ["Reads SMS", "Creates overlay"] },
  },
  sanitization_flags: { count: 1, flags: [{}] },
  model_used: "fallback-deterministic-v1",
};

describe("ReportViewer", () => {
  it("renders filename, summary, band and recommended action", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    expect(screen.getByText("fraud-bank.apk")).toBeInTheDocument();
    expect(screen.getByText(/intercepts SMS OTPs/i)).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText(/escalate cert in/i)).toBeInTheDocument();
  });

  it("renders TTP mapping cards", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    expect(screen.getByText("SMS OTP Interception")).toBeInTheDocument();
    expect(screen.getByText("TTP-OTP-INTERCEPT")).toBeInTheDocument();
  });

  it("shows the AI-evasion banner when sanitization flags exist", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    expect(screen.getByText(/AI evasion attempt detected/i)).toBeInTheDocument();
  });

  it("calls onExport when Export PDF is clicked", async () => {
    const onExport = vi.fn();
    render(<ReportViewer detail={detail} verdict={verdict} report={report} onExport={onExport} />);
    await userEvent.click(screen.getByRole("button", { name: /export pdf/i }));
    expect(onExport).toHaveBeenCalledOnce();
  });

  it("degrades gracefully when the verdict is pending", () => {
    render(<ReportViewer detail={detail} verdict={null} report={null} />);
    expect(screen.getByText(/verdict pending/i)).toBeInTheDocument();
  });
});
