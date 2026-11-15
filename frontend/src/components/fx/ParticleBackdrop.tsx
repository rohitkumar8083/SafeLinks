import { useEffect, useRef } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
}

export function ParticleBackdrop() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { reducedMotion, lowPower, coarsePointer } = useCapabilities();

  useEffect(() => {
    if (reducedMotion) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId = 0;
    let isPaused = document.visibilityState === "hidden";
    const particleCount = lowPower || coarsePointer ? 30 : 60;
    const maxDist = 115;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const onResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", onResize);

    const onVisibility = () => {
      isPaused = document.visibilityState === "hidden";
    };
    document.addEventListener("visibilitychange", onVisibility);

    const particles: Particle[] = Array.from({ length: particleCount }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      radius: Math.random() * 1.2 + 0.8,
    }));

    const render = () => {
      if (!isPaused && ctx) {
        ctx.clearRect(0, 0, width, height);
        const isDark = document.documentElement.classList.contains("dark");
        const dotColor = isDark ? "rgba(45, 212, 191, 0.55)" : "rgba(13, 148, 136, 0.45)";
        const lineColor = isDark ? "rgba(45, 212, 191, " : "rgba(13, 148, 136, ";

        for (let i = 0; i < particles.length; i++) {
          const p = particles[i];
          p.x += p.vx;
          p.y += p.vy;

          if (p.x < 0) p.x = width;
          else if (p.x > width) p.x = 0;
          if (p.y < 0) p.y = height;
          else if (p.y > height) p.y = 0;

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
          ctx.fillStyle = dotColor;
          ctx.fill();

          for (let j = i + 1; j < particles.length; j++) {
            const p2 = particles[j];
            const dx = p.x - p2.x;
            const dy = p.y - p2.y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < maxDist) {
              const alpha = (1 - dist / maxDist) * 0.22;
              ctx.beginPath();
              ctx.moveTo(p.x, p.y);
              ctx.lineTo(p2.x, p2.y);
              ctx.strokeStyle = `${lineColor}${alpha})`;
              ctx.lineWidth = 0.75;
              ctx.stroke();
            }
          }
        }
      }
      animId = requestAnimationFrame(render);
    };

    animId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", onResize);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [reducedMotion, lowPower, coarsePointer]);

  if (reducedMotion) return null;

  return (
    <canvas
      ref={canvasRef}
      className="fx-particle-backdrop"
      aria-hidden="true"
      style={{
        position: "fixed",
        inset: 0,
        pointerEvents: "none",
        zIndex: 0,
        opacity: 0.85,
      }}
    />
  );
}
