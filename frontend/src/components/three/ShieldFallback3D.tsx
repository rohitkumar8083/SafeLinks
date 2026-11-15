import React, { useEffect, useRef, useState } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

interface ShieldFallback3DProps {
  color?: string;
  className?: string;
  style?: React.CSSProperties;
}

export function ShieldFallback3D({
  color = "var(--primary)",
  className = "",
  style = {},
}: ShieldFallback3DProps) {
  const { reducedMotion, coarsePointer } = useCapabilities();
  const containerRef = useRef<HTMLDivElement>(null);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (reducedMotion) return;

    if (coarsePointer) {
      const handleScroll = () => {
        const scrollY = window.scrollY || 0;
        const tiltX = Math.sin(scrollY * 0.005) * 12;
        const tiltY = Math.cos(scrollY * 0.005) * 8;
        setTilt({ x: tiltX, y: tiltY });
      };
      window.addEventListener("scroll", handleScroll, { passive: true });
      return () => window.removeEventListener("scroll", handleScroll);
    } else {
      const handleMouseMove = (e: MouseEvent) => {
        if (!containerRef.current) return;
        const rect = containerRef.current.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        const deltaX = (e.clientX - centerX) / (window.innerWidth / 2);
        const deltaY = (e.clientY - centerY) / (window.innerHeight / 2);
        setTilt({
          x: Math.max(-18, Math.min(18, -deltaY * 18)),
          y: Math.max(-18, Math.min(18, deltaX * 18)),
        });
      };
      window.addEventListener("mousemove", handleMouseMove, { passive: true });
      return () => window.removeEventListener("mousemove", handleMouseMove);
    }
  }, [reducedMotion, coarsePointer]);

  if (reducedMotion) {
    return (
      <div
        className={`fallback-shield-static ${className}`}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          width: "100%",
          height: "100%",
          ...style,
        }}
        aria-hidden="true"
      >
        <svg
          viewBox="0 0 100 115"
          style={{ width: "80%", height: "80%", color }}
          fill="none"
          stroke="currentColor"
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M 50,8 C 76,8 90,15 90,15 C 90,52 75,88 50,105 C 25,88 10,52 10,15 C 10,15 24,8 50,8 Z" />
          <path d="M 34,56 L 46,68 L 68,44" strokeWidth="4" />
        </svg>
      </div>
    );
  }

  const depths = [-32, -16, 0, 16, 32];

  return (
    <div
      ref={containerRef}
      className={`fallback-3d-container ${className}`}
      style={{
        perspective: 900,
        transformStyle: "preserve-3d",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        height: "100%",
        position: "relative",
        ...style,
      }}
      aria-hidden="true"
    >
      <div
        className="fallback-3d-rig"
        style={{
          width: "10rem",
          height: "11.5rem",
          position: "relative",
          transformStyle: "preserve-3d",
          transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
          transition: coarsePointer ? "transform 0.1s ease-out" : "transform 0.08s ease-out",
          filter: `drop-shadow(0 0 25px ${color})`,
        }}
      >
        {depths.map((z, idx) => {
          const opacity = idx === 2 ? 1 : 0.35 + (1 - Math.abs(idx - 2) / 2) * 0.45;
          const scale = 1 - Math.abs(z) * 0.003;
          return (
            <svg
              key={z}
              viewBox="0 0 100 115"
              fill={idx === 2 ? "color-mix(in hsl, currentColor 14%, transparent)" : "none"}
              stroke="currentColor"
              strokeWidth={idx === 2 ? 3.5 : 2}
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{
                position: "absolute",
                inset: 0,
                width: "100%",
                height: "100%",
                color,
                opacity,
                transform: `translateZ(${z}px) scale(${scale})`,
                pointerEvents: "none",
              }}
            >
              <path d="M 50,8 C 76,8 90,15 90,15 C 90,52 75,88 50,105 C 25,88 10,52 10,15 C 10,15 24,8 50,8 Z" />
              {idx === 2 && <path d="M 34,56 L 46,68 L 68,44" strokeWidth="4" />}
            </svg>
          );
        })}
      </div>
    </div>
  );
}
