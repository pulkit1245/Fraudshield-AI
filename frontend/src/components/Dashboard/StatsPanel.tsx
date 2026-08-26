// Dashboard aggregate stats: severity-band bar chart + headline metrics.
// Presentational — consumes GET /dashboard/stats via a prop. Owner: Member D.
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { DashboardStats, SeverityBand } from "../../types";
import { BAND_COLOR, formatDuration } from "../../utils/format";

const BANDS: SeverityBand[] = ["low", "medium", "high", "critical"];

// Stitch glass card style
const glassStyle: React.CSSProperties = {
  background: "rgba(255,255,255,0.05)",
  backdropFilter: "blur(20px)",
  WebkitBackdropFilter: "blur(20px)",
  border: "1px solid rgba(255,255,255,0.10)",
  boxShadow: "inset 0 1px 0 0 rgba(255,255,255,0.10)",
};

const sfPro = "-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text', system-ui, sans-serif";

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl px-5 py-4 flex flex-col justify-between" style={glassStyle}>
      <div
        className="text-[28px] leading-none text-[#e5e2e3] font-sans font-bold tabular-nums"
      >
        {value}
      </div>
      <div className="text-[9px] uppercase tracking-[0.2em] text-[#9A9DA3] font-sans mt-2">
        {label}
      </div>
    </div>
  );
}

export default function StatsPanel({ stats }: { stats: DashboardStats }) {
  const data = BANDS.map((band) => ({ band, count: stats.by_severity[band] ?? 0 }));

  return (
    <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {/* Chart panel */}
      <div className="md:col-span-2 rounded-xl p-4" style={glassStyle}>
        <h2
          className="mb-3 text-[11px] font-sans uppercase tracking-[0.2em]"
          style={{ color: "rgba(154,157,163,0.70)" }}
        >
          Severity distribution
        </h2>
        <div style={{ width: "100%", height: 160 }}>
          <ResponsiveContainer>
            <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <XAxis
                dataKey="band"
                tickLine={false}
                axisLine={false}
                fontSize={10}
                tick={{ fill: "#9A9DA3", fontFamily: sfPro }}
                tickFormatter={(b: string) => b[0].toUpperCase() + b.slice(1)}
              />
              <YAxis
                allowDecimals={false}
                fontSize={10}
                tickLine={false}
                axisLine={false}
                tick={{ fill: "#9A9DA3", fontFamily: sfPro }}
              />
              <Tooltip
                cursor={{ fill: "rgba(255,255,255,0.04)" }}
                contentStyle={{
                  background: "rgba(16,17,18,0.95)",
                  border: "1px solid rgba(255,255,255,0.12)",
                  borderRadius: "6px",
                  color: "#e5e2e3",
                  fontSize: "12px",
                  fontFamily: sfPro,
                }}
              />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {data.map((d) => (
                  <Cell key={d.band} fill={BAND_COLOR[d.band]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Metric cards grid */}
      <div className="grid grid-cols-2 gap-4">
        <Metric label="Queue depth" value={stats.queue_depth} />
        <Metric label="Completed" value={stats.completed} />
        <Metric label="Total" value={stats.total_submissions} />
        <Metric label="Avg triage" value={formatDuration(stats.avg_triage_seconds)} />
      </div>
    </section>
  );
}
