// Dashboard: stats panel + upload + live submission queue. Owner: Member D.
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import StatsPanel from "../components/Dashboard/StatsPanel";
import QueueTable from "../components/SubmissionQueue/QueueTable";
import {
  useDashboardStats,
  useSubmissionsList,
  useUploadSubmission,
} from "../hooks/useSubmissions";

const PAGE_SIZE = 20;

export default function DashboardPage() {
  const navigate = useNavigate();
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
          {upload.isError && <span className="text-xs text-red-600">Upload failed</span>}
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

      {stats.data && <StatsPanel stats={stats.data} />}

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
