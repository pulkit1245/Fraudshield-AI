// Risk heatmap: SHAP-weighted feature contributions from GET /submissions/{id}/ml-score.
// Presentational — takes the SHAP feature list as a prop. Owner: Member D.
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ShapFeature } from "../../types";

const UP = "#c0672a"; // increases risk
const DOWN = "#2a9e65"; // decreases risk

export default function RiskHeatmap({ shap }: { shap: ShapFeature[] }) {
  if (!shap || shap.length === 0) {
    return (
      <div className="rounded-xl border border-gray-200 bg-white p-4 text-sm text-gray-400">
        No feature contributions available yet.
      </div>
    );
  }
  const data = [...shap]
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
    .slice(0, 8)
    .map((f) => ({ ...f, abs: Math.abs(f.contribution) }));

  const height = Math.max(160, data.length * 34);

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <h2 className="mb-2 text-sm font-semibold text-gray-700">
        Top risk drivers (SHAP)
      </h2>
      <div style={{ width: "100%", height }}>
        <ResponsiveContainer>
          <BarChart data={data} layout="vertical" margin={{ left: 24, right: 16 }}>
            <XAxis type="number" fontSize={11} tickLine={false} axisLine={false} />
            <YAxis
              type="category"
              dataKey="feature"
              width={130}
              fontSize={11}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              cursor={{ fill: "#f3f4f6" }}
              formatter={(v: number) => v.toFixed(4)}
            />
            <Bar dataKey="abs" radius={[0, 4, 4, 0]}>
              {data.map((d) => (
                <Cell
                  key={d.feature}
                  fill={d.direction === "increases_risk" ? UP : DOWN}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-1 flex gap-4 text-xs text-gray-500">
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded" style={{ background: UP }} /> increases risk
        </span>
        <span className="flex items-center gap-1">
          <span className="inline-block h-2 w-2 rounded" style={{ background: DOWN }} /> decreases risk
        </span>
      </div>
    </div>
  );
}
