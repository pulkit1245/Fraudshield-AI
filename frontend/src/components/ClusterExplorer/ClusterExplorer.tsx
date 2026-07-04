// Campaign cluster explorer: clusters as sized bubbles (radius ∝ member count)
// in a radial layout. Clicking a bubble selects the cluster. Presentational.
// Owner: Member D.
import type { ClusterSummary } from "../../types";

export interface ClusterExplorerProps {
  clusters: ClusterSummary[];
  selectedId?: string | null;
  onSelect: (id: string) => void;
}

const W = 720;
const H = 420;

export default function ClusterExplorer({ clusters, selectedId, onSelect }: ClusterExplorerProps) {
  if (clusters.length === 0) {
    return (
      <div className="rounded-xl border border-gray-200 bg-white p-8 text-center text-sm text-gray-400">
        No campaign clusters yet. Clusters form as repackaged variants are analyzed.
      </div>
    );
  }

  const cx = W / 2;
  const cy = H / 2;
  const ringR = Math.min(W, H) / 2 - 70;
  const maxMembers = Math.max(...clusters.map((c) => c.member_count), 1);

  const nodes = clusters.map((c, i) => {
    const angle = (2 * Math.PI * i) / clusters.length - Math.PI / 2;
    const single = clusters.length === 1;
    return {
      ...c,
      x: single ? cx : cx + ringR * Math.cos(angle),
      y: single ? cy : cy + ringR * Math.sin(angle),
      r: 22 + 26 * (c.member_count / maxMembers),
    };
  });

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <h2 className="mb-2 text-sm font-semibold text-gray-700">Campaign clusters</h2>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Cluster explorer">
        {nodes.map((n) => (
          <line key={`l-${n.id}`} x1={cx} y1={cy} x2={n.x} y2={n.y}
                stroke="#e5e7eb" strokeWidth="1" />
        ))}
        <circle cx={cx} cy={cy} r="6" fill="#9ca3af" />
        {nodes.map((n) => {
          const selected = n.id === selectedId;
          return (
            <g key={n.id} onClick={() => onSelect(n.id)} style={{ cursor: "pointer" }}>
              <circle
                cx={n.x} cy={n.y} r={n.r}
                fill={selected ? "#6e5ee0" : "#eef0fb"}
                stroke={selected ? "#4a3db5" : "#c7c9e6"} strokeWidth="2"
              />
              <text x={n.x} y={n.y - 2} textAnchor="middle" fontSize="11" fontWeight="700"
                    fill={selected ? "#fff" : "#3a2da0"}>
                {n.member_count}
              </text>
              <text x={n.x} y={n.y + n.r + 14} textAnchor="middle" fontSize="10" fill="#6b7280">
                {n.cluster_name}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
