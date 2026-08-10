import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import AnalysisCompletenessCard, { deriveAnalysisCompleteness } from "../src/components/AnalysisCompleteness/AnalysisCompletenessCard";
import type { SubmissionStatusResponse } from "../src/types";

describe("AnalysisCompleteness Logic", () => {
  it("1. All stages completed", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "Static Analysis", status: "completed" },
        { stage: "Dynamic Analysis", status: "completed" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("COMPLETED");
  });

  it("2. Optional stage failed (Partial analysis)", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "Static Analysis", status: "completed" },
        { stage: "Dynamic Analysis", status: "completed" },
        { stage: "LLM Security Report", status: "failed", error_message: "API error" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("PARTIALLY_COMPLETED");
  });

  it("3. Critical stage failed", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "failed",
      progress_pct: 30,
      analysis_stages: [
        { stage: "Static Analysis", status: "failed", error_message: "Crash" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("FAILED");
  });

  it("4. Stage skipped", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "Threat Intelligence", status: "skipped", error_message: "Disabled" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("PARTIALLY_COMPLETED");
    expect(res.issues[0].status).toBe("skipped");
  });

  it("5. Failed stage with safe error", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "failed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "Dynamic Analysis", status: "failed", error_message: "Timeout" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.issues[0].error_message).toBe("Timeout");
  });

  it("7. Old submission with null analysis_stages", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      // @ts-ignore
      analysis_stages: null
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("COMPLETED");
    expect(res.issues.length).toBe(0);
  });

  it("8. Analysis still running", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "dynamic_running",
      progress_pct: 50,
      analysis_stages: [
        { stage: "Static Analysis", status: "completed" },
        { stage: "Dynamic Analysis", status: "running" }
      ]
    };
    const res = deriveAnalysisCompleteness(data);
    expect(res.state).toBe("ANALYZING");
  });
});

describe("AnalysisCompletenessCard Component", () => {
  it("renders Analysis Partially Complete", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "LLM Security Report", status: "failed", error_message: "Timeout" }
      ]
    };
    render(<AnalysisCompletenessCard statusData={data} />);
    expect(screen.getByText(/Analysis Partially Complete/i)).toBeDefined();
    expect(screen.getByText(/LLM Security Report/i)).toBeDefined();
    expect(screen.getByText(/Timeout/i)).toBeDefined();
  });

  it("renders Analysis Failed", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "failed",
      progress_pct: 100,
      analysis_stages: []
    };
    render(<AnalysisCompletenessCard statusData={data} />);
    expect(screen.getByText(/Analysis Failed/i)).toBeDefined();
  });

  it("renders Analysis Complete", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: []
    };
    render(<AnalysisCompletenessCard statusData={data} />);
    expect(screen.getByText(/Analysis Complete/i)).toBeDefined();
    expect(screen.queryByText(/Analysis Issues/i)).toBeNull();
  });

  it("6. Failed stage without safe error fallback", () => {
    const data: SubmissionStatusResponse = { id: "test-id",
      status: "completed",
      progress_pct: 100,
      analysis_stages: [
        { stage: "LLM Security Report", status: "failed", error_message: undefined }
      ]
    };
    render(<AnalysisCompletenessCard statusData={data} />);
    expect(screen.getByText(/Additional details are unavailable\./i)).toBeDefined();
  });
});
