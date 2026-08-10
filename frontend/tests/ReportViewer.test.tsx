import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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
  it("renders filename, severity band and recommended action", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    expect(screen.getByText("fraud-bank.apk")).toBeInTheDocument();
    // Severity badge is visible in the Security Summary header
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText(/ESCALATE CERT IN/i)).toBeInTheDocument();
  });

  it("renders TTP mapping cards after opening the accordion", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    // TTP section is an accordion — click to open it
    const ttpBtn = screen.getByRole("button", { name: /TTP Mapping/i });
    fireEvent.click(ttpBtn);
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
    // The new summary text when no verdict is available
    expect(
      screen.getByText(/pending a final verdict|in progress/i)
    ).toBeInTheDocument();
  });

  it("shows static analysis section (collapsed) when no static_finding", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={null} />);
    expect(screen.getByRole("button", { name: /Static Analysis/i })).toBeInTheDocument();
  });

  it("shows runtime behaviour section (collapsed) when no dynamic_finding", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={null} />);
    expect(screen.getByRole("button", { name: /Runtime Behaviour/i })).toBeInTheDocument();
  });

  it("shows analysis limitations section for partial analysis", () => {
    render(
      <ReportViewer
        detail={detail}
        verdict={verdict}
        report={null}
        overallState="PARTIALLY_COMPLETED"
        issues={[{ stage: "Dynamic Analysis", status: "failed", error_message: "Sandbox unavailable" }]}
      />
    );
    expect(screen.getByText(/Analysis Limitations/i)).toBeInTheDocument();
    expect(screen.getByText(/Dynamic Analysis/i)).toBeInTheDocument();
  });

  it("shows recommended action with description", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={null} />);
    expect(screen.getByText(/ESCALATE CERT IN/i)).toBeInTheDocument();
    expect(screen.getByText(/CERT-In for national incident/i)).toBeInTheDocument();
  });

  it("shows LLM summary when report has summary_text", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={report} />);
    // LLM section is an accordion — open it
    const llmBtn = screen.getByRole("button", { name: /LLM Security Assessment/i });
    fireEvent.click(llmBtn);
    expect(screen.getByText(/intercepts SMS OTPs/i)).toBeInTheDocument();
  });

  it("shows VirusTotal unavailable when no VT data passed", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={null} virustotal={null} />);
    // Threat Intel section open it
    const tiBtn = screen.getByRole("button", { name: /Threat Intelligence/i });
    fireEvent.click(tiBtn);
    expect(screen.getByText(/loading or unavailable/i)).toBeInTheDocument();
  });

  it("shows ML scoring unavailable when mlScore is null", () => {
    render(<ReportViewer detail={detail} verdict={verdict} report={null} mlScore={null} />);
    const mlBtn = screen.getByRole("button", { name: /ML Risk Assessment/i });
    fireEvent.click(mlBtn);
    expect(screen.getByText(/ML scoring data is unavailable/i)).toBeInTheDocument();
  });
});
