import { useEffect } from "react";
import { motion, useMotionValue, useSpring } from "motion/react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

export function GlowCursor() {
  const { reducedMotion, coarsePointer } = useCapabilities();

  const mouseX = useMotionValue(-500);
  const mouseY = useMotionValue(-500);

  const springConfig = { damping: 28, stiffness: 220, mass: 0.6 };
  const smoothX = useSpring(mouseX, springConfig);
  const smoothY = useSpring(mouseY, springConfig);

  useEffect(() => {
    if (reducedMotion || coarsePointer) return;

    const handlePointerMove = (e: PointerEvent) => {
      mouseX.set(e.clientX);
      mouseY.set(e.clientY);
    };

    window.addEventListener("pointermove", handlePointerMove, { passive: true });
    return () => window.removeEventListener("pointermove", handlePointerMove);
  }, [reducedMotion, coarsePointer, mouseX, mouseY]);

  if (reducedMotion || coarsePointer) return null;

  return (
    <motion.div
      className="fx-glow-cursor"
      aria-hidden="true"
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        width: 320,
        height: 320,
        borderRadius: "50%",
        pointerEvents: "none",
        zIndex: 0,
        x: smoothX,
        y: smoothY,
        translateX: "-50%",
        translateY: "-50%",
      }}
    />
  );
}
