// Dashboard aggregate stats: severity-band bar chart + headline metrics.
// Presentational — consumes GET /dashboard/stats via a prop. Owner: Member D.
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DashboardStats, SeverityBand } from "../../types";
import { BAND_COLOR, formatDuration } from "../../utils/format";

const BANDS: SeverityBand[] = ["low", "medium", "high", "critical"];

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-border bg-background-elevated px-4 py-3">
      <div className="text-2xl font-extrabold text-text-bright">{value}</div>
      <div className="text-xs uppercase tracking-wide text-text-muted">{label}</div>
    </div>
  );
}

export default function StatsPanel({ stats }: { stats: DashboardStats }) {
  const data = BANDS.map((band) => ({ band, count: stats.by_severity[band] ?? 0 }));

  return (
    <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
      <div className="md:col-span-2 rounded-xl border border-border bg-background-elevated p-4">
        <h2 className="mb-2 text-sm font-semibold text-text">Severity distribution</h2>
        <div style={{ width: "100%", height: 180 }}>
          <ResponsiveContainer>
            <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <XAxis dataKey="band" tickLine={false} axisLine={false}
                     fontSize={12} tickFormatter={(b: string) => b[0].toUpperCase() + b.slice(1)} />
              <YAxis allowDecimals={false} fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip cursor={{ fill: "#f3f4f6" }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {data.map((d) => (
                  <Cell key={d.band} fill={BAND_COLOR[d.band]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <Metric label="Queue depth" value={stats.queue_depth} />
        <Metric label="Completed" value={stats.completed} />
        <Metric label="Total" value={stats.total_submissions} />
        <Metric label="Avg triage" value={formatDuration(stats.avg_triage_seconds)} />
      </div>
    </section>
  );
}
