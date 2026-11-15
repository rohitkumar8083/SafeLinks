import React, { useRef, useState, type MouseEvent } from "react";
import { motion, useSpring } from "motion/react";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { cn } from "../../app/components/ui";

interface MagneticButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "default" | "icon" | "lg";
  className?: string;
}

interface Ripple {
  x: number;
  y: number;
  id: number;
}

export function MagneticButton({
  children,
  variant = "primary",
  size = "default",
  className,
  onClick,
  disabled,
  ...props
}: MagneticButtonProps) {
  const { reducedMotion, coarsePointer } = useCapabilities();
  const btnRef = useRef<HTMLButtonElement>(null);
  const [ripples, setRipples] = useState<Ripple[]>([]);

  const springConfig = { stiffness: 260, damping: 20 };
  const dx = useSpring(0, springConfig);
  const dy = useSpring(0, springConfig);

  const handleMouseMove = (e: MouseEvent<HTMLButtonElement>) => {
    if (reducedMotion || coarsePointer || disabled || !btnRef.current) return;
    const rect = btnRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    const distX = e.clientX - centerX;
    const distY = e.clientY - centerY;
    const dist = Math.sqrt(distX * distX + distY * distY);

    if (dist < 80) {
      dx.set((distX / 80) * 6);
      dy.set((distY / 80) * 6);
    } else {
      dx.set(0);
      dy.set(0);
    }
  };

  const handleMouseLeave = () => {
    dx.set(0);
    dy.set(0);
  };

  const handleClick = (e: MouseEvent<HTMLButtonElement>) => {
    if (!reducedMotion && btnRef.current) {
      const rect = btnRef.current.getBoundingClientRect();
      const rippleX = e.clientX - rect.left;
      const rippleY = e.clientY - rect.top;
      const newRipple: Ripple = { x: rippleX, y: rippleY, id: Date.now() };
      setRipples((prev) => [...prev, newRipple]);
      setTimeout(() => {
        setRipples((prev) => prev.filter((r) => r.id !== newRipple.id));
      }, 600);
    }
    onClick?.(e);
  };

  if (reducedMotion || coarsePointer) {
    return (
      <button
        ref={btnRef}
        className={cn("button", `button-${variant}`, `button-${size}`, className)}
        onClick={onClick}
        disabled={disabled}
        {...props}
      >
        {children}
      </button>
    );
  }

  return (
    <motion.button
      ref={btnRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      onClick={handleClick}
      disabled={disabled}
      style={{ x: dx, y: dy }}
      whileTap={{ scale: disabled ? 1 : 0.97 }}
      className={cn(
        "button fx-magnetic-button",
        `button-${variant}`,
        `button-${size}`,
        className
      )}
      {...(props as any)}
    >
      <span className="fx-shimmer-sweep" aria-hidden="true" />
      {ripples.map((r) => (
        <span
          key={r.id}
          className="fx-ripple"
          style={{
            left: r.x - 15,
            top: r.y - 15,
            width: 30,
            height: 30,
          }}
          aria-hidden="true"
        />
      ))}
      {children}
    </motion.button>
  );
}
