import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import QueueTable from "../src/components/SubmissionQueue/QueueTable";
import type { SubmissionSummary } from "../src/types";

const items: SubmissionSummary[] = [
  {
    id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    original_filename: "sample-one.apk",
    sha256_hash: "a".repeat(64),
    status: "completed",
    submitted_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    severity_band: "critical",
    final_risk_score: 92,
  },
  {
    id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    original_filename: "sample-two.apk",
    sha256_hash: "b".repeat(64),
    status: "scoring",
    submitted_at: new Date().toISOString(),
    completed_at: null,
    severity_band: null,
    final_risk_score: null,
  },
];

function setup(overrides: Partial<React.ComponentProps<typeof QueueTable>> = {}) {
  const props = {
    items,
    total: 2,
    page: 1,
    pageSize: 20,
    statusFilter: "",
    onStatusFilterChange: vi.fn(),
    onPageChange: vi.fn(),
    onRowClick: vi.fn(),
    ...overrides,
  };
  render(<QueueTable {...props} />);
  return props;
}

describe("QueueTable", () => {
  it("renders a row per submission", () => {
    setup();
    expect(screen.getByText("sample-one.apk")).toBeInTheDocument();
    expect(screen.getByText("sample-two.apk")).toBeInTheDocument();
  });

  it("shows the severity badge for scored rows", () => {
    setup();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("calls onRowClick with the submission id", async () => {
    const props = setup();
    await userEvent.click(screen.getByText("sample-one.apk"));
    expect(props.onRowClick).toHaveBeenCalledWith(items[0].id);
  });

  it("calls onStatusFilterChange when the filter changes", async () => {
    const props = setup();
    await userEvent.selectOptions(
      screen.getByLabelText(/filter by status/i),
      "completed",
    );
    expect(props.onStatusFilterChange).toHaveBeenCalledWith("completed");
  });

  it("shows an empty state when there are no items", () => {
    setup({ items: [], total: 0 });
    expect(screen.getByText(/no submissions/i)).toBeInTheDocument();
  });
});
