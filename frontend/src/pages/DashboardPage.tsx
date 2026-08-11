// Dashboard: stats panel + upload + live submission queue. Owner: Member D.
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import StatsPanel from "../components/Dashboard/StatsPanel";
import TIPipelinePanel from "../components/Dashboard/TIPipelinePanel";
import QueueTable from "../components/SubmissionQueue/QueueTable";
import { useAuth } from "../context/AuthContext";
import {
  useDashboardStats,
  useSubmissionsList,
  useUploadSubmission,
} from "../hooks/useSubmissions";

const PAGE_SIZE = 20;

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [statusFilter, setStatusFilter] = useState("");
  const [page, setPage] = useState(1);
  const fileRef = useRef<HTMLInputElement>(null);

  const stats = useDashboardStats();
  const list = useSubmissionsList({
    status: statusFilter || undefined,
    page,
    page_size: PAGE_SIZE,
  });
  const upload = useUploadSubmission();

  function onFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) upload.mutate(file);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-gray-900">Analyst dashboard</h1>
        <div className="flex items-center gap-3">
          {upload.isPending && <span className="text-xs text-gray-500">Uploading…</span>}
          {upload.isError && (
            <span className="max-w-xs truncate rounded bg-red-50 px-2 py-1 text-xs text-red-700 border border-red-200">
              ⚠ Upload failed: {(upload.error as Error)?.message ?? "Unknown error"}
            </span>
          )}
          <input
            ref={fileRef} type="file" accept=".apk" onChange={onFileChange}
            className="hidden" id="apk-upload"
          />
          <label
            htmlFor="apk-upload"
            className="cursor-pointer rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white hover:bg-indigo-700"
          >
            Upload APK
          </label>
        </div>
      </div>

      {stats.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <strong>Stats error:</strong> {(stats.error as Error)?.message ?? "Failed to load dashboard stats"}
        </div>
      )}
      {stats.data && <StatsPanel stats={stats.data} />}

      {/* TI Pipeline fallback alerts — shown when a source had to use a
          fallback strategy (e.g. TAXII instead of GitHub, source skipped due to
          missing API key). Empty state shows ✅ when all is healthy.
          Admin-only: GET /admin/threat-intelligence/pipeline/fallbacks requires
          the admin role, so rendering this for analysts would only ever show an
          error box. Same gating pattern as ClustersPage. */}
      {user?.role === "admin" && <TIPipelinePanel />}

      {list.isError && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
          <strong>Queue error:</strong> {(list.error as Error)?.message ?? "Failed to load submission queue"}
        </div>
      )}
      <QueueTable
        items={list.data?.items ?? []}
        total={list.data?.total ?? 0}
        page={page}
        pageSize={PAGE_SIZE}
        statusFilter={statusFilter}
        onStatusFilterChange={(s) => { setStatusFilter(s); setPage(1); }}
        onPageChange={setPage}
        onRowClick={(id) => navigate(`/submissions/${id}`)}
        isLoading={list.isLoading}
      />
    </div>
  );
}
