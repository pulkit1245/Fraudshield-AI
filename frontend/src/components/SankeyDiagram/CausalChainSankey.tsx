// Causal-chain flow: static signals → observed behaviour → verdict, rendered as
// a lightweight SVG Sankey (no d3 dependency). Presentational. Owner: Member D.
import type { SeverityBand } from "../../types";
import { BAND_COLOR } from "../../utils/format";

export interface SankeyStage {
  title: string;
  nodes: string[];
}

export interface CausalChainSankeyProps {
  stages: SankeyStage[];
  band?: SeverityBand;
}

const WIDTH = 720;
const HEIGHT = 260;
const NODE_W = 130;
const NODE_H = 30;
const PAD_TOP = 40;

export default function CausalChainSankey({ stages, band }: CausalChainSankeyProps) {
  const cols = stages.length;
  if (cols === 0) return null;
  const gapX = (WIDTH - NODE_W) / Math.max(1, cols - 1);

  // Node layout per column.
  const layout = stages.map((stage, ci) => {
    const x = ci * gapX;
    const n = Math.max(1, stage.nodes.length);
    const usableH = HEIGHT - PAD_TOP - 20;
    return stage.nodes.map((label, ni) => {
      const y = PAD_TOP + (usableH / n) * ni + (usableH / n - NODE_H) / 2;
      return { label, x, y, ci, isLast: ci === cols - 1 };
    });
  });

  const links: { x1: number; y1: number; x2: number; y2: number }[] = [];
  for (let ci = 0; ci < cols - 1; ci++) {
    for (const a of layout[ci]) {
      for (const b of layout[ci + 1]) {
        links.push({
          x1: a.x + NODE_W,
          y1: a.y + NODE_H / 2,
          x2: b.x,
          y2: b.y + NODE_H / 2,
        });
      }
    }
  }

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4">
      <h2 className="mb-2 text-sm font-semibold text-gray-700">Causal behaviour chain</h2>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" role="img"
           aria-label="Causal chain from static signals to verdict">
        {stages.map((s, ci) => (
          <text key={s.title} x={ci * gapX + NODE_W / 2} y={20} textAnchor="middle"
                fontSize="11" fontWeight="600" fill="#6b7280">
            {s.title}
          </text>
        ))}

        {links.map((l, i) => (
          <path
            key={i}
            d={`M ${l.x1} ${l.y1} C ${(l.x1 + l.x2) / 2} ${l.y1}, ${(l.x1 + l.x2) / 2} ${l.y2}, ${l.x2} ${l.y2}`}
            fill="none" stroke="#c7c9e6" strokeWidth="1.5" opacity="0.6"
          />
        ))}

        {layout.flat().map((node, i) => {
          const fill = node.isLast && band ? BAND_COLOR[band] : "#eef0fb";
          const text = node.isLast && band ? "#fff" : "#3a2da0";
          return (
            <g key={i}>
              <rect x={node.x} y={node.y} width={NODE_W} height={NODE_H} rx="6"
                    fill={fill} stroke="#d7d9f0" />
              <text x={node.x + NODE_W / 2} y={node.y + NODE_H / 2 + 4} textAnchor="middle"
                    fontSize="11" fill={text}>
                {node.label.length > 20 ? node.label.slice(0, 19) + "…" : node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
