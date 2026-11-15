import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { ScanResponse, Verdict } from "../../lib/api";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { ThreeCanvas, type ThreeContext } from "./ThreeCanvas";
import {
  createCheckMarkGeometry,
  createExclamationGeometry,
  createFracturedShieldGeometries,
  createFresnelMaterial,
  createQuestionMarkGeometry,
  createShieldShape,
  createXMarkGeometry,
  shieldExtrudeSettings,
} from "./shieldGeometry";
import { ShieldFallback3D } from "./ShieldFallback3D";

interface VerdictOrbProps {
  scan: ScanResponse;
  className?: string;
  style?: React.CSSProperties;
}

type VisualMode = "scanning" | "likely_safe" | "suspicious" | "likely_malicious" | "unknown";

const COLOR_MAP: Record<VisualMode, number> = {
  scanning: 0x2dd4bf,
  likely_safe: 0x10b981,
  suspicious: 0xf59e0b,
  likely_malicious: 0xef4444,
  unknown: 0x64748b,
};

const CSS_COLOR_MAP: Record<VisualMode, string> = {
  scanning: "var(--primary)",
  likely_safe: "var(--safe)",
  suspicious: "var(--caution)",
  likely_malicious: "var(--danger)",
  unknown: "var(--unknown)",
};

export function VerdictOrb({ scan, className = "", style = {} }: VerdictOrbProps) {
  const { coarsePointer } = useCapabilities();
  const pointerTarget = useRef({ x: 0, y: 0 });

  const getVisualMode = (): VisualMode => {
    if (scan.status === "failed") return "unknown";
    if (["queued", "running"].includes(scan.status)) return "scanning";
    const verdict = scan.result?.verdict as Verdict | undefined;
    if (verdict === "likely_safe" || verdict === "suspicious" || verdict === "likely_malicious") {
      return verdict;
    }
    return "unknown";
  };

  const visualMode = getVisualMode();
  const visualModeRef = useRef<VisualMode>(visualMode);
  visualModeRef.current = visualMode;

  useEffect(() => {
    if (coarsePointer) return;
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = -(e.clientY / window.innerHeight) * 2 + 1;
      pointerTarget.current = { x: x * 0.25, y: y * 0.25 };
    };
    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, [coarsePointer]);

  const handleInit = (ctx: ThreeContext) => {
    const { scene, camera } = ctx;
    camera.position.set(0.08, 0.05, 4.0);

    const rootGroup = new THREE.Group();
    rootGroup.scale.set(0.72, 0.72, 0.72);
    scene.add(rootGroup);

    // ==========================================
    // 1. INTACT SHIELD (Safe / Suspicious / Scanning / Unknown)
    // ==========================================
    const shieldShape = createShieldShape();
    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, shieldExtrudeSettings);
    shieldGeo.center();

    const shieldMat = new THREE.MeshStandardMaterial({
      color: 0x052e25,
      metalness: 0.88,
      roughness: 0.16,
      emissive: new THREE.Color(COLOR_MAP[visualModeRef.current]),
      emissiveIntensity: 0.45,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    rootGroup.add(shieldMesh);

    const edgesGeo = new THREE.EdgesGeometry(shieldGeo);
    const edgesMat = new THREE.LineBasicMaterial({
      color: COLOR_MAP[visualModeRef.current],
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
    });
    const edgesMesh = new THREE.LineSegments(edgesGeo, edgesMat);
    shieldMesh.add(edgesMesh);

    const fresnelMat = createFresnelMaterial(COLOR_MAP[visualModeRef.current]);
    const fresnelMesh = new THREE.Mesh(shieldGeo, fresnelMat);
    fresnelMesh.scale.set(1.04, 1.04, 1.04);
    shieldMesh.add(fresnelMesh);

    // 3D Luminous Checkmark (Safe)
    const checkGeo = createCheckMarkGeometry();
    const checkMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      emissive: 0x34d399,
      emissiveIntensity: 1.8,
      roughness: 0.2,
      metalness: 0.4,
    });
    const checkMesh = new THREE.Mesh(checkGeo, checkMat);
    shieldMesh.add(checkMesh);

    // 3D Exclamation Symbol (Suspicious)
    const { stem: exclStemGeo, dot: exclDotGeo } = createExclamationGeometry();
    const exclMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      emissive: 0xfbbf24,
      emissiveIntensity: 1.6,
      roughness: 0.2,
    });
    const exclStemMesh = new THREE.Mesh(exclStemGeo, exclMat);
    const exclDotMesh = new THREE.Mesh(exclDotGeo, exclMat);
    exclDotMesh.position.set(0, -0.24, 0.22);
    const exclGroup = new THREE.Group();
    exclGroup.add(exclStemMesh);
    exclGroup.add(exclDotMesh);
    shieldMesh.add(exclGroup);

    // 3D Question Mark Symbol (Unknown)
    const { stem: qStemGeo, dot: qDotGeo } = createQuestionMarkGeometry();
    const qMat = new THREE.MeshBasicMaterial({ color: 0x94a3b8, blending: THREE.AdditiveBlending });
    const qStemMesh = new THREE.Mesh(qStemGeo, qMat);
    const qDotMesh = new THREE.Mesh(qDotGeo, qMat);
    qDotMesh.position.set(0, -0.22, 0.22);
    const qGroup = new THREE.Group();
    qGroup.add(qStemMesh);
    qGroup.add(qDotMesh);
    shieldMesh.add(qGroup);

    // Safe Orbiting Laser Ring
    const safeRingGeo = new THREE.TorusGeometry(1.62, 0.024, 12, 64);
    const safeRingMat = new THREE.MeshBasicMaterial({
      color: 0x10b981,
      transparent: true,
      opacity: 0.75,
      blending: THREE.AdditiveBlending,
    });
    const safeRingMesh = new THREE.Mesh(safeRingGeo, safeRingMat);
    safeRingMesh.rotation.x = 1.15;
    safeRingMesh.rotation.y = -0.25;
    rootGroup.add(safeRingMesh);

    // Safe Cyber Spark Motes
    const safePCount = 45;
    const safePGeo = new THREE.BufferGeometry();
    const safePPos = new Float32Array(safePCount * 3);
    for (let i = 0; i < safePCount; i++) {
      safePPos[i * 3] = (Math.random() - 0.5) * 3.2;
      safePPos[i * 3 + 1] = (Math.random() - 0.5) * 3.2;
      safePPos[i * 3 + 2] = (Math.random() - 0.5) * 2.0;
    }
    safePGeo.setAttribute("position", new THREE.BufferAttribute(safePPos, 3));
    const safePMat = new THREE.PointsMaterial({
      size: 0.05,
      color: 0x34d399,
      transparent: true,
      opacity: 0.7,
      blending: THREE.AdditiveBlending,
    });
    const safeParticles = new THREE.Points(safePGeo, safePMat);
    rootGroup.add(safeParticles);

    // ==========================================
    // 2. FRACTURED CYBER SHIELD (Likely Malicious / DANGER)
    // ==========================================
    const fracturedGroup = new THREE.Group();
    rootGroup.add(fracturedGroup);

    const { leftGeo, rightGeo } = createFracturedShieldGeometries();
    const fracturedMat = new THREE.MeshStandardMaterial({
      color: 0x180206,
      metalness: 0.92,
      roughness: 0.14,
      emissive: 0xef4444,
      emissiveIntensity: 0.7,
    });

    const leftShieldMesh = new THREE.Mesh(leftGeo, fracturedMat);
    leftShieldMesh.position.set(-0.52, 0, 0);
    leftShieldMesh.rotation.z = -0.05;
    fracturedGroup.add(leftShieldMesh);

    const rightShieldMesh = new THREE.Mesh(rightGeo, fracturedMat);
    rightShieldMesh.position.set(0.52, 0, 0);
    rightShieldMesh.rotation.z = 0.05;
    fracturedGroup.add(rightShieldMesh);

    // Glowing ruby edges on fractured halves
    const leftEdgesGeo = new THREE.EdgesGeometry(leftGeo);
    const rightEdgesGeo = new THREE.EdgesGeometry(rightGeo);
    const dangerEdgeMat = new THREE.LineBasicMaterial({
      color: 0xff3b5c,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const leftEdgesMesh = new THREE.LineSegments(leftEdgesGeo, dangerEdgeMat);
    leftShieldMesh.add(leftEdgesMesh);
    const rightEdgesMesh = new THREE.LineSegments(rightEdgesGeo, dangerEdgeMat);
    rightShieldMesh.add(rightEdgesMesh);

    // 3D Luminous X-Mark Symbol
    const { bar1, bar2 } = createXMarkGeometry();
    const xMat = new THREE.MeshStandardMaterial({
      color: 0xffffff,
      emissive: 0xff1e40,
      emissiveIntensity: 2.4,
      roughness: 0.2,
      metalness: 0.4,
    });
    const xBar1Mesh = new THREE.Mesh(bar1, xMat);
    const xBar2Mesh = new THREE.Mesh(bar2, xMat);
    fracturedGroup.add(xBar1Mesh);
    fracturedGroup.add(xBar2Mesh);

    // Dual Orbiting Crimson Laser Energy Rings
    const dangerRing1Geo = new THREE.TorusGeometry(1.68, 0.026, 12, 64);
    const dangerRing1Mat = new THREE.MeshBasicMaterial({
      color: 0xff1e40,
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
    });
    const dangerRing1Mesh = new THREE.Mesh(dangerRing1Geo, dangerRing1Mat);
    dangerRing1Mesh.rotation.x = 1.18;
    dangerRing1Mesh.rotation.y = -0.28;
    fracturedGroup.add(dangerRing1Mesh);

    const dangerRing2Geo = new THREE.TorusGeometry(1.95, 0.015, 10, 64);
    const dangerRing2Mat = new THREE.MeshBasicMaterial({
      color: 0xff4d6d,
      transparent: true,
      opacity: 0.55,
      blending: THREE.AdditiveBlending,
    });
    const dangerRing2Mesh = new THREE.Mesh(dangerRing2Geo, dangerRing2Mat);
    dangerRing2Mesh.rotation.x = -0.92;
    dangerRing2Mesh.rotation.y = 0.35;
    fracturedGroup.add(dangerRing2Mesh);

    // 16 3D Floating Crystal Glass Shards Tumble Field
    const shardGeos = [
      new THREE.TetrahedronGeometry(0.14),
      new THREE.ConeGeometry(0.1, 0.22, 3),
      new THREE.TetrahedronGeometry(0.18),
      new THREE.OctahedronGeometry(0.12),
    ];
    const shardMat = new THREE.MeshStandardMaterial({
      color: 0x7f0914,
      emissive: 0xef4444,
      emissiveIntensity: 0.9,
      metalness: 0.88,
      roughness: 0.12,
      transparent: true,
      opacity: 0.85,
    });

    const shardData: {
      mesh: THREE.Mesh;
      basePos: THREE.Vector3;
      rotSpeed: THREE.Vector3;
      phase: number;
    }[] = [];

    const shardCount = 14;
    for (let i = 0; i < shardCount; i++) {
      const sGeo = shardGeos[i % shardGeos.length];
      const sMesh = new THREE.Mesh(sGeo, shardMat);
      const angle = (i / shardCount) * Math.PI * 2;
      const dist = 1.15 + (i % 3) * 0.35;
      const sx = Math.cos(angle) * dist;
      const sy = Math.sin(angle) * dist * 0.85;
      const sz = ((i % 5) - 2) * 0.32;
      sMesh.position.set(sx, sy, sz);
      sMesh.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, 0);

      const sEdges = new THREE.LineSegments(
        new THREE.EdgesGeometry(sGeo),
        new THREE.LineBasicMaterial({ color: 0xff4d6d, blending: THREE.AdditiveBlending })
      );
      sMesh.add(sEdges);

      fracturedGroup.add(sMesh);
      shardData.push({
        mesh: sMesh,
        basePos: new THREE.Vector3(sx, sy, sz),
        rotSpeed: new THREE.Vector3(
          0.8 + Math.random() * 1.2,
          0.6 + Math.random() * 1.4,
          0.5 + Math.random() * 1.0
        ),
        phase: i * 0.8,
      });
    }

    // Danger Floating Ember Sparks
    const emberCount = 35;
    const emberGeo = new THREE.BufferGeometry();
    const emberPos = new Float32Array(emberCount * 3);
    for (let i = 0; i < emberCount; i++) {
      emberPos[i * 3] = (Math.random() - 0.5) * 3.5;
      emberPos[i * 3 + 1] = (Math.random() - 0.5) * 3.5;
      emberPos[i * 3 + 2] = (Math.random() - 0.5) * 2.2;
    }
    emberGeo.setAttribute("position", new THREE.BufferAttribute(emberPos, 3));
    const emberMat = new THREE.PointsMaterial({
      size: 0.055,
      color: 0xff2e54,
      transparent: true,
      opacity: 0.8,
      blending: THREE.AdditiveBlending,
    });
    const emberParticles = new THREE.Points(emberGeo, emberMat);
    fracturedGroup.add(emberParticles);

    // ==========================================
    // 3. SCANNING & COMMON VISUALS
    // ==========================================
    const icoGeo = new THREE.IcosahedronGeometry(1.5, 1);
    const icoMat = new THREE.MeshBasicMaterial({
      color: 0x2dd4bf,
      wireframe: true,
      transparent: true,
      opacity: 0.45,
    });
    const icoMesh = new THREE.Mesh(icoGeo, icoMat);
    rootGroup.add(icoMesh);

    const ringGeo = new THREE.RingGeometry(0.35, 0.4, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0x2dd4bf,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.6,
      blending: THREE.AdditiveBlending,
    });
    const ringMeshes: THREE.Mesh[] = [];
    for (let i = 0; i < 3; i++) {
      const ring = new THREE.Mesh(ringGeo, ringMat.clone());
      ring.position.z = 0.1;
      rootGroup.add(ring);
      ringMeshes.push(ring);
    }

    // Multi-Directional Dynamic Specular Lighting
    const hemiLight = new THREE.HemisphereLight(0xffffff, 0x071e22, 1.2);
    scene.add(hemiLight);

    const dirLight1 = new THREE.DirectionalLight(0xff3b5c, 1.8);
    dirLight1.position.set(3, 4, 3.5);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0x8b5cf6, 1.1);
    dirLight2.position.set(-3, -2, 1.5);
    scene.add(dirLight2);

    const pointLight = new THREE.PointLight(0xff1e40, 2.4, 7);
    scene.add(pointLight);

    let prevMode: VisualMode = visualModeRef.current;
    let transitionTime = 1.0;

    return {
      update: (delta: number, time: number) => {
        const mode = visualModeRef.current;

        if (mode !== prevMode) {
          prevMode = mode;
          transitionTime = 0.0;
        }

        if (transitionTime < 1.0) {
          transitionTime = Math.min(1.0, transitionTime + delta * 1.6);
        }

        const floatRotX = 0.14 + Math.sin(time * 0.9) * 0.05 + pointerTarget.current.y * 0.25;
        const floatRotY = -0.28 + Math.cos(time * 0.8) * 0.07 + pointerTarget.current.x * 0.35;
        const targetRotX = floatRotX;
        const targetRotY = floatRotY;

        shieldMesh.rotation.x += (targetRotX - shieldMesh.rotation.x) * 0.08;
        shieldMesh.rotation.y += (targetRotY - shieldMesh.rotation.y) * 0.08;

        fracturedGroup.rotation.x += (targetRotX - fracturedGroup.rotation.x) * 0.08;
        fracturedGroup.rotation.y += (targetRotY - fracturedGroup.rotation.y) * 0.08;

        pointLight.position.x = Math.cos(time * 0.9) * 2.4;
        pointLight.position.y = Math.sin(time * 0.9) * 2.0;
        pointLight.position.z = 2.0;

        const isMalicious = mode === "likely_malicious";
        shieldMesh.visible = !isMalicious;
        fracturedGroup.visible = isMalicious;
        safeRingMesh.visible = mode === "likely_safe";
        safeParticles.visible = mode === "likely_safe";

        if (isMalicious) {
          // Dynamic crimson lighting
          pointLight.color.setHex(0xff1e40);
          dirLight1.color.setHex(0xff3b5c);

          // Animate danger cyber rings
          dangerRing1Mesh.rotation.z += delta * 0.9;
          dangerRing2Mesh.rotation.z -= delta * 0.55;

          // Animate floating crystal shards
          for (let i = 0; i < shardData.length; i++) {
            const s = shardData[i];
            s.mesh.rotation.x += s.rotSpeed.x * delta;
            s.mesh.rotation.y += s.rotSpeed.y * delta;
            s.mesh.position.y = s.basePos.y + Math.sin(time * 1.8 + s.phase) * 0.1;
            s.mesh.position.x = s.basePos.x + Math.cos(time * 1.2 + s.phase) * 0.06;
          }

          // Heartbeat pulse rhythm
          const beatCycle = (time % 1.5) / 1.5;
          const pulse = beatCycle < 0.15 ? Math.sin(beatCycle * Math.PI * 6.6) * 0.08 : 0;
          const curScale = 1.0 + pulse;
          fracturedGroup.scale.set(curScale, curScale, curScale);
          fracturedMat.emissiveIntensity = 0.7 + pulse * 0.5;
          xMat.emissiveIntensity = 2.4 + pulse * 0.8;
        } else {
          // Non-danger states
          const targetColor = new THREE.Color(COLOR_MAP[mode]);
          shieldMat.emissive.lerp(targetColor, 0.08);
          edgesMat.color.lerp(targetColor, 0.08);
          pointLight.color.lerp(targetColor, 0.08);
          dirLight1.color.setHex(0x5eead4);

          checkMesh.visible = mode === "likely_safe";
          exclGroup.visible = mode === "suspicious";
          qGroup.visible = mode === "unknown";

          if (mode === "likely_safe") {
            safeRingMesh.rotation.z += delta * 0.55;
            shieldMesh.rotation.y += delta * 0.18;
            shieldMat.emissiveIntensity = 0.55 + Math.sin(time * 2.0) * 0.2;
          } else if (mode === "suspicious") {
            shieldMesh.rotation.z = Math.sin(time * 3.0) * 0.04;
            shieldMat.emissiveIntensity = 0.5 + Math.sin(time * 10) * 0.2;
          }
        }

        if (mode === "scanning") {
          icoMesh.visible = true;
          icoMesh.rotation.y += delta * 0.6;
          icoMesh.rotation.x += delta * 0.4;
          (icoMesh.material as THREE.MeshBasicMaterial).opacity = 0.5;

          shieldMesh.scale.set(0.85, 0.85, 0.85);

          for (let i = 0; i < ringMeshes.length; i++) {
            const phase = ((time * 0.8 + i * 0.33) % 1.0);
            const rScale = 0.5 + phase * 2.8;
            ringMeshes[i].visible = true;
            ringMeshes[i].scale.set(rScale, rScale, 1);
            (ringMeshes[i].material as THREE.MeshBasicMaterial).opacity = (1 - phase) * 0.65;
          }
        } else {
          icoMesh.visible = transitionTime < 0.8;
          if (icoMesh.visible) {
            (icoMesh.material as THREE.MeshBasicMaterial).opacity = (1 - transitionTime) * 0.45;
          }
          ringMeshes.forEach((r) => (r.visible = false));
        }
      },
      onDestroy: () => {
        shieldGeo.dispose();
        edgesGeo.dispose();
        checkGeo.dispose();
        exclStemGeo.dispose();
        exclDotGeo.dispose();
        qStemGeo.dispose();
        qDotGeo.dispose();
        icoGeo.dispose();
        ringGeo.dispose();
        leftGeo.dispose();
        rightGeo.dispose();
        leftEdgesGeo.dispose();
        rightEdgesGeo.dispose();
        bar1.dispose();
        bar2.dispose();
        safeRingGeo.dispose();
        safePGeo.dispose();
        dangerRing1Geo.dispose();
        dangerRing2Geo.dispose();
        shardGeos.forEach((g) => g.dispose());
        emberGeo.dispose();
      },
    };
  };

  const verdictCssColor = CSS_COLOR_MAP[visualMode];

  return (
    <ThreeCanvas
      onInit={handleInit}
      fallback={<ShieldFallback3D color={verdictCssColor} style={{ width: "10rem", height: "10rem" }} />}
      className={`verdict-orb-canvas ${className}`}
      style={{ width: "13.75rem", height: "13.75rem", margin: "0 auto", ...style }}
      ariaLabel={`3D security verdict shield: ${visualMode.replace("_", " ")}`}
    />
  );
}
