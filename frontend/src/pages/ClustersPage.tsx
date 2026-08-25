// Clusters page: campaign cluster explorer + selected-cluster members, with an
// admin-only recompute action. Owner: Member D.
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import ClusterExplorer from "../components/ClusterExplorer/ClusterExplorer";
import { useAuth } from "../context/AuthContext";
import { useCluster, useClusters } from "../hooks/useSubmissions";
import { clustersApi } from "../services/submissions";
import { shortHash } from "../utils/format";

export default function ClustersPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { user } = useAuth();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const clusters = useClusters();
  const detail = useCluster(selectedId ?? undefined);

  const recompute = useMutation({
    mutationFn: () => clustersApi.recompute(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["clusters"] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-bold text-text-bright">Campaign clusters</h1>
        {user?.role === "admin" && (
          <button
            onClick={() => recompute.mutate()}
            disabled={recompute.isPending}
            className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-background-surface disabled:opacity-50"
          >
            {recompute.isPending ? "Recomputing…" : "Recompute centroids"}
          </button>
        )}
      </div>

      <ClusterExplorer
        clusters={clusters.data?.items ?? []}
        selectedId={selectedId}
        onSelect={setSelectedId}
      />

      {detail.data && (
        <div className="rounded-xl border border-border bg-background-elevated p-4">
          <h2 className="mb-2 text-sm font-semibold text-text">
            {detail.data.cluster_name} · {detail.data.member_count} members
          </h2>
          <ul className="divide-y divide-gray-100 text-sm">
            {detail.data.members.map((sid) => (
              <li key={sid} className="flex items-center justify-between py-2">
                <span className="font-mono text-xs text-text-muted">{shortHash(sid, 18)}</span>
                <button
                  onClick={() => navigate(`/submissions/${sid}`)}
                  className="text-xs text-primary-cyan hover:underline"
                >
                  Open report →
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
