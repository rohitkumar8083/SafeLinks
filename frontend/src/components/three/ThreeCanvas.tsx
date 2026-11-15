import React, { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { ShieldFallback3D } from "./ShieldFallback3D";

export interface ThreeContext {
  scene: THREE.Scene;
  camera: THREE.PerspectiveCamera;
  renderer: THREE.WebGLRenderer;
  canvas: HTMLCanvasElement;
  width: number;
  height: number;
  isPaused: boolean;
}

interface ThreeCanvasProps {
  onInit: (ctx: ThreeContext) => {
    update?: (delta: number, time: number) => void;
    onResize?: (width: number, height: number) => void;
    onDestroy?: () => void;
  };
  fallback?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  ariaLabel?: string;
}

export function ThreeCanvas({
  onInit,
  fallback,
  className = "",
  style = {},
  ariaLabel = "3D visual element",
}: ThreeCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { webgl, reducedMotion, lowPower } = useCapabilities();
  const [hasError, setHasError] = useState(false);

  useEffect(() => {
    if (!webgl || reducedMotion || hasError) return;

    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    let renderer: THREE.WebGLRenderer | null = null;
    let animId = 0;
    let isPaused = document.visibilityState === "hidden";
    let isIntersecting = true;
    let customHooks: ReturnType<typeof onInit> | null = null;

    try {
      renderer = new THREE.WebGLRenderer({
        canvas,
        alpha: true,
        antialias: !lowPower,
        powerPreference: lowPower ? "low-power" : "high-performance",
      });

      const maxDpr = lowPower ? 1.5 : 2;
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, maxDpr));

      const rect = container.getBoundingClientRect();
      const width = Math.max(1, rect.width || 300);
      const height = Math.max(1, rect.height || 300);

      renderer.setSize(width, height, false);

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
      camera.position.z = 5;

      const ctx: ThreeContext = {
        scene,
        camera,
        renderer,
        canvas,
        width,
        height,
        get isPaused() {
          return isPaused || !isIntersecting;
        },
      };

      customHooks = onInit(ctx);

      const resizeObserver = new ResizeObserver((entries) => {
        if (!entries.length || !renderer) return;
        const entry = entries[0];
        const newWidth = Math.max(1, entry.contentRect.width);
        const newHeight = Math.max(1, entry.contentRect.height);

        camera.aspect = newWidth / newHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(newWidth, newHeight, false);
        customHooks?.onResize?.(newWidth, newHeight);
      });
      resizeObserver.observe(container);

      const intersectionObserver = new IntersectionObserver(
        ([entry]) => {
          isIntersecting = entry.isIntersecting;
        },
        { threshold: 0.05 }
      );
      intersectionObserver.observe(container);

      const handleVisibilityChange = () => {
        isPaused = document.visibilityState === "hidden";
      };
      document.addEventListener("visibilitychange", handleVisibilityChange);

      const clock = new THREE.Clock();

      const loop = () => {
        animId = requestAnimationFrame(loop);
        if (isPaused || !isIntersecting || !renderer) return;

        const delta = Math.min(clock.getDelta(), 0.1);
        const elapsedTime = clock.getElapsedTime();

        customHooks?.update?.(delta, elapsedTime);
        renderer.render(scene, camera);
      };

      loop();

      return () => {
        cancelAnimationFrame(animId);
        resizeObserver.disconnect();
        intersectionObserver.disconnect();
        document.removeEventListener("visibilitychange", handleVisibilityChange);

        customHooks?.onDestroy?.();

        scene.traverse((obj: THREE.Object3D) => {
          if (obj instanceof THREE.Mesh || obj instanceof THREE.LineSegments || obj instanceof THREE.Points) {
            obj.geometry?.dispose();
            if (Array.isArray(obj.material)) {
              obj.material.forEach((m: THREE.Material) => m.dispose());
            } else if (obj.material) {
              (obj.material as THREE.Material).dispose();
            }
          }
        });

        renderer?.dispose();
      };
    } catch (err) {
      console.warn("WebGL initialization failed, falling back to CSS 3D:", err);
      setHasError(true);
    }
  }, [webgl, reducedMotion, lowPower, onInit, hasError]);

  if (!webgl || reducedMotion || hasError) {
    return (
      <div className={className} style={{ width: "100%", height: "100%", ...style }}>
        {fallback ?? <ShieldFallback3D />}
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={className}
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        overflow: "hidden",
        pointerEvents: "none",
        ...style,
      }}
      aria-hidden="true"
      aria-label={ariaLabel}
    >
      <canvas
        ref={canvasRef}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          pointerEvents: "none",
        }}
      />
    </div>
  );
}
