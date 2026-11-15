import { useEffect, useState } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

interface CountUpProps {
  end?: number;
  target?: number;
  start?: number;
  duration?: number;
  className?: string;
}

export function CountUp({ end, target, start = 0, duration = 1.2, className }: CountUpProps) {
  const finalVal = end ?? target ?? 0;
  const { reducedMotion } = useCapabilities();
  const [current, setCurrent] = useState(reducedMotion ? finalVal : start);

  useEffect(() => {
    if (reducedMotion) {
      setCurrent(finalVal);
      return;
    }

    let startTime = 0;
    let animId = 0;

    const easeOutExpo = (t: number): number => {
      return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
    };

    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1);
      const eased = easeOutExpo(progress);
      const val = Math.round(start + (finalVal - start) * eased);
      setCurrent(val);

      if (progress < 1) {
        animId = requestAnimationFrame(step);
      } else {
        setCurrent(finalVal);
      }
    };

    animId = requestAnimationFrame(step);

    return () => cancelAnimationFrame(animId);
  }, [finalVal, start, duration, reducedMotion]);

  return <span className={className}>{current}</span>;
}
