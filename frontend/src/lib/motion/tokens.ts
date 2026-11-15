export const MOTION_TOKENS = {
  duration: {
    fast: 0.15,
    base: 0.25,
    slow: 0.5,
    hero: 0.9,
  },
  ease: {
    easeOutExpo: [0.16, 1, 0.3, 1] as const,
    easeOutBack: [0.34, 1.56, 0.64, 1] as const,
    easeInOut: [0.4, 0, 0.2, 1] as const,
  },
  cssEase: {
    easeOutExpo: "cubic-bezier(0.16, 1, 0.3, 1)",
    easeOutBack: "cubic-bezier(0.34, 1.56, 0.64, 1)",
  },
  spring: {
    type: "spring" as const,
    stiffness: 260,
    damping: 24,
  },
  springBouncy: {
    type: "spring" as const,
    stiffness: 300,
    damping: 18,
  },
  stagger: 0.06,
  colors: {
    primary: "var(--primary)",
    accent: "var(--accent)",
    safe: "var(--safe)",
    caution: "var(--caution)",
    danger: "var(--danger)",
    unknown: "var(--unknown)",
  },
} as const;
