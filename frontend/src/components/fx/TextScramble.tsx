import { useEffect, useRef, useState } from "react";
import { useCapabilities } from "../../lib/motion/useCapabilities";

interface TextScrambleProps {
  text: string;
  durationMs?: number;
  className?: string;
}

const GLYPHS = "!<>-_\\/[]{}—=+*^?#_0101";

export function TextScramble({ text, durationMs = 400, className }: TextScrambleProps) {
  const { reducedMotion } = useCapabilities();
  const [displayText, setDisplayText] = useState(text);
  const prevTextRef = useRef(text);

  useEffect(() => {
    if (reducedMotion || prevTextRef.current === text) {
      setDisplayText(text);
      prevTextRef.current = text;
      return;
    }

    prevTextRef.current = text;
    let frame = 0;
    const totalFrames = Math.max(1, Math.round(durationMs / 30));
    let timer: ReturnType<typeof setInterval>;

    timer = setInterval(() => {
      frame++;
      const progress = frame / totalFrames;
      const targetLength = text.length;

      let output = "";
      for (let i = 0; i < targetLength; i++) {
        if (i < Math.floor(progress * targetLength)) {
          output += text[i];
        } else {
          output += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
        }
      }

      setDisplayText(output);

      if (frame >= totalFrames) {
        clearInterval(timer);
        setDisplayText(text);
      }
    }, 30);

    return () => clearInterval(timer);
  }, [text, durationMs, reducedMotion]);

  return <span className={className}>{displayText}</span>;
}
