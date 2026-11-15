import { useState } from "react";
import { motion } from "motion/react";
import {
  Bug,
  CalendarClock,
  CheckCircle2,
  Fish,
  Globe,
  Link2,
  Lock,
  Shield,
  type LucideIcon,
} from "lucide-react";
import type { Check, CheckCategory, CheckId, ScanResponse, Severity } from "../../lib/api";
import { useCapabilities } from "../../lib/motion/useCapabilities";

const CATEGORY_ICONS: Record<CheckCategory, LucideIcon> = {
  phishing: Fish,
  malware: Bug,
  reputation: Globe,
  domain: CalendarClock,
  ssl: Lock,
  url_structure: Link2,
};

const SEVERITY_COLORS: Record<Severity, string> = {
  info: "var(--safe)",
  low: "var(--safe)",
  medium: "var(--caution)",
  high: "var(--orange)",
  critical: "var(--danger)",
};

interface ScanConstellationProps {
  scan: ScanResponse;
  onSelectCheck?: (checkId: CheckId) => void;
}

export function ScanConstellation({ scan, onSelectCheck }: ScanConstellationProps) {
  const { reducedMotion } = useCapabilities();
  const [hoveredCheckId, setHoveredCheckId] = useState<string | null>(null);

  const isScanning = ["queued", "running"].includes(scan.status);

  // Safe constellation geometry centered with ample headroom
  const vbWidth = 500;
  const vbHeight = 220;
  const cx = 250;
  const cy = 110;
  const rx = 175;
  const ry = 44;

  const handleNodeClick = (check: Check) => {
    onSelectCheck?.(check.id);
    const element = document.getElementById(`check-card-${check.id}`);
    if (element) {
      element.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "center" });
      element.classList.add("check-card-flash");
      setTimeout(() => element.classList.remove("check-card-flash"), 1200);
    }
  };

  return (
    <div
      className="constellation-slot"
      style={{
        position: "relative",
        minHeight: "13.5rem",
        height: "13.5rem",
        overflow: "hidden",
        width: "100%",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      aria-label="Safety checks interactive constellation"
    >
      <div
        className="constellation-radar-sweep"
        aria-hidden="true"
        style={{
          position: "absolute",
          width: "24rem",
          height: "24rem",
          borderRadius: "50%",
          pointerEvents: "none",
          opacity: isScanning ? 1 : 0,
          transition: "opacity 0.6s ease",
          background: "conic-gradient(from 0deg, transparent 0deg, transparent 270deg, hsl(173 80% 40% / 0.18) 360deg)",
          animation: isScanning && !reducedMotion ? "radarSweepAnim 3s linear infinite" : "none",
        }}
      />

      <svg
        viewBox={`0 0 ${vbWidth} ${vbHeight}`}
        style={{ width: "100%", height: "100%", maxWidth: "560px", position: "relative", zIndex: 1 }}
      >
        <defs>
          <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="hsl(173 80% 45%)" stopOpacity="0.8" />
            <stop offset="100%" stopColor="hsl(173 80% 45%)" stopOpacity="0" />
          </radialGradient>
        </defs>

        <ellipse
          cx={cx}
          cy={cy}
          rx={rx}
          ry={ry}
          fill="none"
          stroke="hsl(173 80% 40% / 0.2)"
          strokeWidth="1.5"
          strokeDasharray="4 6"
        />

        <g transform={`translate(${cx - 18}, ${cy - 18})`}>
          <circle cx="18" cy="18" r="20" fill="var(--card)" stroke="hsl(173 80% 40% / 0.45)" strokeWidth="1.5" />
          <Shield
            width="22"
            height="22"
            x="7"
            y="7"
            color="var(--primary)"
            style={{ filter: "drop-shadow(0 0 8px var(--primary))" }}
          />
        </g>

        {scan.checks.map((check, index) => {
          const total = scan.checks.length || 8;
          const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
          const nx = cx + Math.cos(angle) * rx;
          const ny = cy + Math.sin(angle) * ry;

          const isHovered = hoveredCheckId === check.id;
          const isDone = check.status === "done";
          const isSkippedOrError = check.status === "skipped" || check.status === "error";

          const nodeColor = isDone
            ? SEVERITY_COLORS[check.severity] || "var(--safe)"
            : isSkippedOrError
              ? "var(--caution)"
              : "var(--muted-foreground)";

          const CategoryIcon = CATEGORY_ICONS[check.category] || CheckCircle2;

          // Tooltip sizing & safe boundary calculations
          const isUpperHalf = ny < cy;
          const tooltipWidth = Math.max(130, check.name.length * 7.2 + 26);
          const halfW = tooltipWidth / 2;
          // Clamp X so tooltip never crosses left or right SVG boundary
          const tooltipX = Math.max(halfW + 16, Math.min(vbWidth - halfW - 16, nx));
          // For upper half, place safely above the node; for lower half, place below the node
          // Clamped so it strictly maintains >= 24px margin from top and bottom borders
          const rawTooltipY = isUpperHalf ? ny - 30 : ny + 32;
          const tooltipY = isUpperHalf
            ? Math.max(26, rawTooltipY)
            : Math.min(vbHeight - 26, rawTooltipY);

          return (
            <g
              key={check.id}
              style={{ cursor: "pointer" }}
              onMouseEnter={() => setHoveredCheckId(check.id)}
              onMouseLeave={() => setHoveredCheckId(null)}
              onClick={() => handleNodeClick(check)}
              role="button"
              tabIndex={0}
              aria-label={`${check.name}: ${check.status}`}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  handleNodeClick(check);
                }
              }}
            >
              <line
                x1={cx}
                y1={cy}
                x2={nx}
                y2={ny}
                stroke={nodeColor}
                strokeWidth={isHovered ? 2.2 : 1.2}
                strokeOpacity={isHovered ? 0.75 : 0.25}
                strokeDasharray={isDone ? undefined : "3 3"}
              />

              {isScanning && !reducedMotion && (
                <circle
                  cx={cx + (nx - cx) * 0.5}
                  cy={cy + (ny - cy) * 0.5}
                  r="2"
                  fill="var(--primary)"
                  opacity="0.8"
                />
              )}

              <motion.g
                animate={{
                  scale: isHovered ? 1.22 : 1.0,
                }}
                transition={{ type: "spring", stiffness: 350, damping: 22 }}
              >
                {(isHovered || (isDone && check.severity === "critical")) && (
                  <circle cx={nx} cy={ny} r="20" fill={nodeColor} opacity="0.25" />
                )}

                <circle
                  cx={nx}
                  cy={ny}
                  r="14"
                  fill={isDone ? nodeColor : isSkippedOrError ? "hsl(38 92% 50% / 0.15)" : "var(--solid)"}
                  stroke={nodeColor}
                  strokeWidth={isHovered ? 2.5 : 1.8}
                  fillOpacity={isDone ? 0.22 : 0.9}
                />

                <g transform={`translate(${nx - 7.5}, ${ny - 7.5})`}>
                  <CategoryIcon
                    width="15"
                    height="15"
                    color={nodeColor}
                    strokeWidth={2}
                  />
                </g>
              </motion.g>

              {isHovered && (
                <g transform={`translate(${tooltipX}, ${tooltipY})`} pointerEvents="none">
                  <rect
                    x={-halfW}
                    y="-13"
                    width={tooltipWidth}
                    height="24"
                    rx="6"
                    fill="var(--solid)"
                    stroke="var(--border)"
                    strokeWidth="1"
                    filter="drop-shadow(0 4px 14px rgba(0,0,0,0.3))"
                  />
                  <text
                    x="0"
                    y="3.5"
                    textAnchor="middle"
                    fill="var(--foreground)"
                    fontSize="10.5"
                    fontWeight="600"
                    fontFamily="Inter, sans-serif"
                  >
                    {check.name}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
