import React, { useRef, useState, type MouseEvent } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { cn } from "../../app/components/ui";

interface TiltCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  className?: string;
  maxTilt?: number;
}

export function TiltCard({ children, className, maxTilt = 6, ...props }: TiltCardProps) {
  const { reducedMotion, coarsePointer } = useCapabilities();
  const cardRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [glarePos, setGlarePos] = useState({ x: 50, y: 50 });

  const x = useMotionValue(0);
  const y = useMotionValue(0);

  const springConfig = { stiffness: 260, damping: 24 };
  const rotateX = useSpring(useTransform(y, [-0.5, 0.5], [maxTilt, -maxTilt]), springConfig);
  const rotateY = useSpring(useTransform(x, [-0.5, 0.5], [-maxTilt, maxTilt]), springConfig);
  const translateY = useSpring(isHovered ? -4 : 0, springConfig);

  const handleMouseMove = (e: MouseEvent<HTMLDivElement>) => {
    if (reducedMotion || coarsePointer || !cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const xPct = mouseX / width - 0.5;
    const yPct = mouseY / height - 0.5;

    x.set(xPct);
    y.set(yPct);
    setGlarePos({ x: (mouseX / width) * 100, y: (mouseY / height) * 100 });
  };

  const handleMouseEnter = () => {
    if (reducedMotion || coarsePointer) return;
    setIsHovered(true);
  };

  const handleMouseLeave = () => {
    setIsHovered(false);
    x.set(0);
    y.set(0);
  };

  if (reducedMotion || coarsePointer) {
    return (
      <div className={cn("glass-card", className)} {...props}>
        {children}
      </div>
    );
  }

  return (
    <div style={{ perspective: 1000 }} className="fx-tilt-card-wrapper">
      <motion.div
        ref={cardRef}
        onMouseMove={handleMouseMove}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        style={{
          rotateX,
          rotateY,
          y: translateY,
          transformStyle: "preserve-3d",
        }}
        className={cn(
          "glass-card fx-tilt-card",
          isHovered && "fx-tilt-active",
          className
        )}
        {...(props as any)}
      >
        <div
          className="fx-spotlight-border"
          aria-hidden="true"
          style={{
            position: "absolute",
            inset: -1,
            borderRadius: "inherit",
            pointerEvents: "none",
            zIndex: 1,
            opacity: isHovered ? 1 : 0,
            transition: "opacity 0.25s ease",
            background: `radial-gradient(280px circle at ${glarePos.x}% ${glarePos.y}%, hsl(173 80% 45% / 0.38), transparent 80%)`,
            mask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
            WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
            maskComposite: "exclude",
            WebkitMaskComposite: "xor",
            padding: 1,
          }}
        />
        <div
          className="fx-glare-layer"
          aria-hidden="true"
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "inherit",
            pointerEvents: "none",
            opacity: isHovered ? 0.08 : 0,
            transition: "opacity 0.25s ease",
            background: `radial-gradient(circle at ${glarePos.x}% ${glarePos.y}%, rgba(255,255,255,1) 0%, transparent 60%)`,
          }}
        />
        {children}
      </motion.div>
    </div>
  );
}
