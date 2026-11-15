import { useCallback, useSyncExternalStore } from "react";

export type EffectsMode = "full" | "reduced";

const STORAGE_KEY = "safelinks:effects:v1";
let memoryMode: EffectsMode | null = null;
const listeners = new Set<() => void>();
let cachedWebGL: boolean | null = null;

function checkWebGLSupport(): boolean {
  if (cachedWebGL !== null) return cachedWebGL;
  if (typeof window === "undefined") return false;
  try {
    const canvas = document.createElement("canvas");
    const gl =
      canvas.getContext("webgl2") ||
      canvas.getContext("webgl") ||
      canvas.getContext("experimental-webgl");
    cachedWebGL = Boolean(gl);
  } catch {
    cachedWebGL = false;
  }
  return cachedWebGL;
}

function getSystemPrefersReduced(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function readStoredMode(): EffectsMode {
  if (memoryMode) return memoryMode;
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "full" || stored === "reduced") {
      memoryMode = stored;
      return stored;
    }
  } catch {
    // LocalStorage blocked/unavailable
  }
  const fallback: EffectsMode = getSystemPrefersReduced() ? "reduced" : "full";
  memoryMode = fallback;
  return fallback;
}

function writeStoredMode(mode: EffectsMode) {
  memoryMode = mode;
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // LocalStorage blocked/unavailable
  }
  if (typeof document !== "undefined") {
    if (mode === "reduced") {
      document.documentElement.classList.add("effects-reduced");
    } else {
      document.documentElement.classList.remove("effects-reduced");
    }
  }
  listeners.forEach((listener) => listener());
}

if (typeof document !== "undefined") {
  const initialMode = readStoredMode();
  if (initialMode === "reduced" || getSystemPrefersReduced()) {
    document.documentElement.classList.add("effects-reduced");
  }
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function useCapabilities() {
  const effectsMode = useSyncExternalStore(subscribe, readStoredMode, readStoredMode);

  const setEffectsMode = useCallback((mode: EffectsMode) => {
    writeStoredMode(mode);
  }, []);

  const systemReduced =
    typeof window !== "undefined" && window.matchMedia
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false;

  const reducedMotion = effectsMode === "reduced" || systemReduced;

  const coarsePointer =
    typeof window !== "undefined" && window.matchMedia
      ? window.matchMedia("(pointer: coarse)").matches
      : false;

  const nav = typeof navigator !== "undefined" ? navigator : undefined;
  const hardwareConcurrency = nav?.hardwareConcurrency ?? 8;
  const deviceMemory = (nav as unknown as { deviceMemory?: number })?.deviceMemory ?? 8;
  const lowPower = hardwareConcurrency <= 4 || deviceMemory <= 4;
  const webgl = checkWebGLSupport();

  return {
    reducedMotion,
    coarsePointer,
    lowPower,
    webgl,
    effectsMode,
    setEffectsMode,
  };
}
