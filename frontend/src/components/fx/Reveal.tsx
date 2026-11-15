import React, { useRef } from "react";
import { motion, useInView } from "motion/react";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { MOTION_TOKENS } from "../../lib/motion/tokens";

interface RevealProps {
  children: React.ReactNode;
  delay?: number;
  yOffset?: number;
  className?: string;
}

export function Reveal({ children, delay = 0, yOffset = 24, className }: RevealProps) {
  const { reducedMotion } = useCapabilities();
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-40px" });

  if (reducedMotion) {
    return <div className={className}>{children}</div>;
  }

  return (
    <div ref={ref} className={className}>
      <motion.div
        initial={{ opacity: 0, y: yOffset }}
        animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: yOffset }}
        transition={{
          duration: MOTION_TOKENS.duration.base,
          delay,
          ease: MOTION_TOKENS.ease.easeOutExpo,
        }}
      >
        {children}
      </motion.div>
    </div>
  );
}
