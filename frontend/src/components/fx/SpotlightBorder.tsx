import React, { useRef, useState, type MouseEvent } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

export function useSpotlight() {
  const { reducedMotion, coarsePointer } = useCapabilities();
  const [pos, setPos] = useState({ x: 0, y: 0 });
  const [opacity, setOpacity] = useState(0);

  const handleMouseMove = (e: MouseEvent<HTMLElement>) => {
    if (reducedMotion || coarsePointer) return;
    const rect = e.currentTarget.getBoundingClientRect();
    setPos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleMouseEnter = () => {
    if (reducedMotion || coarsePointer) return;
    setOpacity(1);
  };

  const handleMouseLeave = () => {
    setOpacity(0);
  };

  return { pos, opacity, handleMouseMove, handleMouseEnter, handleMouseLeave };
}

interface SpotlightBorderProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export function SpotlightBorder({ children, className = "", style = {} }: SpotlightBorderProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { pos, opacity, handleMouseMove, handleMouseEnter, handleMouseLeave } = useSpotlight();

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className={`fx-spotlight-wrapper ${className}`}
      style={{
        position: "relative",
        borderRadius: "inherit",
        ...style,
      }}
    >
      <div
        className="fx-spotlight-border"
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: -1,
          borderRadius: "inherit",
          pointerEvents: "none",
          opacity,
          transition: "opacity 0.25s ease",
          background: `radial-gradient(280px circle at ${pos.x}px ${pos.y}px, hsl(173 80% 45% / 0.4), transparent 80%)`,
          mask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
          WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
          maskComposite: "exclude",
          WebkitMaskComposite: "xor",
          padding: 1,
        }}
      />
      {children}
    </div>
  );
}
