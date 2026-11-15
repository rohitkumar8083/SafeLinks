import { useEffect, useState } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

export function AnimatedGrid() {
  const { reducedMotion } = useCapabilities();
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    const handleVis = () => setPaused(document.visibilityState === "hidden");
    document.addEventListener("visibilitychange", handleVis);
    return () => document.removeEventListener("visibilitychange", handleVis);
  }, []);

  if (reducedMotion) return null;

  return (
    <div
      className="fx-grid-viewport"
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        overflow: "hidden",
        pointerEvents: "none",
        zIndex: 0,
      }}
    >
      <div
        className={`fx-grid-plane ${paused ? "paused" : ""}`}
        style={{
          position: "absolute",
          width: "200%",
          height: "200%",
          left: "-50%",
          top: "10%",
          transform: "perspective(500px) rotateX(60deg)",
          transformOrigin: "center top",
          maskImage: "radial-gradient(ellipse at 50% 20%, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 70%)",
          WebkitMaskImage: "radial-gradient(ellipse at 50% 20%, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 70%)",
        }}
      />
    </div>
  );
}
