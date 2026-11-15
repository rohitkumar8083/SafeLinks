import { useEffect, useRef } from "react";
import * as THREE from "three";
import { useCapabilities } from "../../lib/motion/useCapabilities";
import { ThreeCanvas, type ThreeContext } from "./ThreeCanvas";
import {
  createCheckMarkGeometry,
  createFresnelMaterial,
  createInnerShieldShape,
  createParticleTexture,
  createShieldShape,
  innerShieldExtrudeSettings,
  shieldExtrudeSettings,
} from "./shieldGeometry";
import { ShieldFallback3D } from "./ShieldFallback3D";

export interface HeroShieldState {
  armed?: boolean;
  valid?: boolean;
  invalid?: boolean;
  launching?: boolean;
}

export function HeroShield(props: HeroShieldState) {
  const { lowPower, coarsePointer } = useCapabilities();
  const stateRef = useRef<HeroShieldState>(props);
  const pointerTarget = useRef({ x: 0, y: 0 });
  const scrollOffset = useRef(0);

  useEffect(() => {
    stateRef.current = props;
  }, [props]);

  useEffect(() => {
    const handleFormEvent = (e: Event) => {
      const detail = (e as CustomEvent<HeroShieldState>).detail;
      if (detail) {
        stateRef.current = { ...stateRef.current, ...detail };
      }
    };
    window.addEventListener("safelinks:form-state", handleFormEvent);
    return () => window.removeEventListener("safelinks:form-state", handleFormEvent);
  }, []);

  useEffect(() => {
    if (coarsePointer) return;
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = -(e.clientY / window.innerHeight) * 2 + 1;
      pointerTarget.current = {
        x: Math.max(-1, Math.min(1, x)),
        y: Math.max(-1, Math.min(1, y)),
      };
    };
    const handleScroll = () => {
      scrollOffset.current = (window.scrollY || 0) * 0.001;
    };
    window.addEventListener("mousemove", handleMouseMove, { passive: true });
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("scroll", handleScroll);
    };
  }, [coarsePointer]);

  const handleInit = (ctx: ThreeContext) => {
    const { scene, camera } = ctx;
    camera.position.set(0.1, 0.05, 4.3);

    const rootGroup = new THREE.Group();
    rootGroup.scale.set(0.65, 0.65, 0.65);
    scene.add(rootGroup);

    // Main 3D Extruded Shield Chassis
    const shieldShape = createShieldShape();
    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, shieldExtrudeSettings);
    shieldGeo.center();

    const shieldMat = new THREE.MeshStandardMaterial({
      color: 0x062826,
      metalness: 0.88,
      roughness: 0.18,
      emissive: 0x0d9488,
      emissiveIntensity: 0.28,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    rootGroup.add(shieldMesh);

    // Inner Cyber Core Plate
    const innerShape = createInnerShieldShape();
    const innerGeo = new THREE.ExtrudeGeometry(innerShape, innerShieldExtrudeSettings);
    innerGeo.center();
    const innerMat = new THREE.MeshStandardMaterial({
      color: 0x08373d,
      metalness: 0.82,
      roughness: 0.22,
      emissive: 0x14b8a6,
      emissiveIntensity: 0.38,
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    innerMesh.position.z = 0.22;
    shieldMesh.add(innerMesh);

    // Glowing Neon Edge Lines
    const edgesGeo = new THREE.EdgesGeometry(shieldGeo);
    const edgesMat = new THREE.LineBasicMaterial({
      color: 0x2dd4bf,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
    });
    const edgesMesh = new THREE.LineSegments(edgesGeo, edgesMat);
    shieldMesh.add(edgesMesh);

    // Inner plate edges
    const innerEdgesGeo = new THREE.EdgesGeometry(innerGeo);
    const innerEdgesMat = new THREE.LineBasicMaterial({
      color: 0x5eead4,
      transparent: true,
      opacity: 0.7,
      blending: THREE.AdditiveBlending,
    });
    const innerEdgesMesh = new THREE.LineSegments(innerEdgesGeo, innerEdgesMat);
    innerEdgesMesh.position.z = 0.22;
    shieldMesh.add(innerEdgesMesh);

    // 3D Extruded Checkmark
    const checkGeo = createCheckMarkGeometry();
    const checkMat = new THREE.MeshStandardMaterial({
      color: 0x5eead4,
      emissive: 0x2dd4bf,
      emissiveIntensity: 0.75,
      metalness: 0.6,
      roughness: 0.18,
    });
    const checkMesh = new THREE.Mesh(checkGeo, checkMat);
    checkMesh.position.z = 0.04;
    shieldMesh.add(checkMesh);

    // Fresnel Rim Glow
    const fresnelMat = createFresnelMaterial(0x2dd4bf);
    const fresnelMesh = new THREE.Mesh(shieldGeo, fresnelMat);
    fresnelMesh.scale.set(1.05, 1.05, 1.05);
    shieldMesh.add(fresnelMesh);

    // Dynamic Scanning Laser Beam
    const beamGeo = new THREE.PlaneGeometry(2.3, 0.2);
    const beamCanvas = document.createElement("canvas");
    beamCanvas.width = 128;
    beamCanvas.height = 32;
    const bCtx = beamCanvas.getContext("2d");
    if (bCtx) {
      const grad = bCtx.createLinearGradient(0, 0, 0, 32);
      grad.addColorStop(0, "rgba(45, 212, 191, 0)");
      grad.addColorStop(0.5, "rgba(255, 255, 255, 0.95)");
      grad.addColorStop(1, "rgba(45, 212, 191, 0)");
      bCtx.fillStyle = grad;
      bCtx.fillRect(0, 0, 128, 32);
    }
    const beamTex = new THREE.CanvasTexture(beamCanvas);
    const beamMat = new THREE.MeshBasicMaterial({
      map: beamTex,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      opacity: 0.65,
    });
    const beamMesh = new THREE.Mesh(beamGeo, beamMat);
    beamMesh.position.z = 0.28;
    shieldMesh.add(beamMesh);

    // 3D Orbital Planetary Chain Ring
    const chainGroup = new THREE.Group();
    chainGroup.rotation.x = 1.15; // 66-degree orbital perspective tilt
    chainGroup.rotation.y = -0.32;
    rootGroup.add(chainGroup);

    const linkGeo = new THREE.TorusGeometry(0.12, 0.034, 10, 20);
    const linkMat = new THREE.MeshStandardMaterial({
      color: 0x0f766e,
      metalness: 0.9,
      roughness: 0.2,
      emissive: 0x14b8a6,
      emissiveIntensity: 0.28,
    });
    const linkCount = 24;
    const chainMesh = new THREE.InstancedMesh(linkGeo, linkMat, linkCount);
    const chainRadius = 2.05;
    const dummy = new THREE.Object3D();

    const updateChainPositions = (radius: number) => {
      for (let i = 0; i < linkCount; i++) {
        const angle = (i / linkCount) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const y = Math.sin(angle) * radius;
        dummy.position.set(x, y, 0);
        dummy.rotation.set(0, 0, angle + Math.PI / 2);
        if (i % 2 === 1) {
          dummy.rotateX(Math.PI / 2);
        }
        dummy.updateMatrix();
        chainMesh.setMatrixAt(i, dummy.matrix);
      }
      chainMesh.instanceMatrix.needsUpdate = true;
    };
    updateChainPositions(chainRadius);
    chainGroup.add(chainMesh);

    // 3D Orbiting Network Nodes with Genuine Depth
    const nodeCount = 10;
    const nodeGeo = new THREE.SphereGeometry(0.065, 14, 14);
    const nodeMat = new THREE.MeshStandardMaterial({
      color: 0x5eead4,
      emissive: 0x2dd4bf,
      emissiveIntensity: 0.8,
      metalness: 0.5,
      roughness: 0.2,
    });
    const nodesMesh = new THREE.InstancedMesh(nodeGeo, nodeMat, nodeCount);
    rootGroup.add(nodesMesh);

    // Dynamic 3D Connecting Beams
    const maxLines = 15;
    const lineGeo = new THREE.BufferGeometry();
    const linePositions = new Float32Array(maxLines * 6);
    lineGeo.setAttribute("position", new THREE.BufferAttribute(linePositions, 3));
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x2dd4bf,
      transparent: true,
      opacity: 0.35,
      blending: THREE.AdditiveBlending,
    });
    const lineSegments = new THREE.LineSegments(lineGeo, lineMat);
    rootGroup.add(lineSegments);

    // Floating Cyber Particle Dust
    const particleCount = lowPower ? 200 : 450;
    const pGeo = new THREE.BufferGeometry();
    const pPos = new Float32Array(particleCount * 3);
    const pVel = new Float32Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      pPos[i * 3] = (Math.random() - 0.5) * 5.5;
      pPos[i * 3 + 1] = (Math.random() - 0.5) * 5.5;
      pPos[i * 3 + 2] = (Math.random() - 0.5) * 3.5;
      pVel[i] = 0.2 + Math.random() * 0.4;
    }
    pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
    const pMat = new THREE.PointsMaterial({
      size: 0.065,
      map: createParticleTexture(),
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      color: 0x2dd4bf,
      opacity: 0.65,
    });
    const particles = new THREE.Points(pGeo, pMat);
    rootGroup.add(particles);

    // Multi-Directional Specular Lighting Setup
    const hemiLight = new THREE.HemisphereLight(0x2dd4bf, 0x051b20, 1.1);
    scene.add(hemiLight);

    const dirLight1 = new THREE.DirectionalLight(0x5eead4, 1.8);
    dirLight1.position.set(3.5, 4.5, 3.5);
    scene.add(dirLight1);

    const dirLight2 = new THREE.DirectionalLight(0x8b5cf6, 1.2);
    dirLight2.position.set(-3.5, -2.5, 1.5);
    scene.add(dirLight2);

    const pointLight = new THREE.PointLight(0x2dd4bf, 2.0, 7);
    scene.add(pointLight);

    let entranceScale = 0.6;
    let chainAngle = 0;
    let launchProgress = 0;
    let shakeTimer = 0;

    // Permanent 3D showcase base rotation (not flat to camera!)
    const baseRotY = -0.32; // ~-18.3 degrees showing right extruded edge
    const baseRotX = 0.16;  // ~9.2 degrees looking slightly down onto top bevel
    const baseRotZ = -0.06; // slight cyber tilt

    return {
      update: (delta: number, time: number) => {
        const state = stateRef.current;

        if (entranceScale < 0.999) {
          entranceScale += (1.0 - entranceScale) * 0.08;
          rootGroup.scale.set(entranceScale * 0.65, entranceScale * 0.65, entranceScale * 0.65);
        }

        // Gyroscopic 3D breathing and dynamic pointer responsiveness
        const floatY = Math.sin(time * 1.2) * 0.07;
        const dynamicRotY = baseRotY + Math.sin(time * 0.8) * 0.1 + pointerTarget.current.x * 0.35;
        const dynamicRotX = baseRotX + Math.cos(time * 0.9) * 0.06 + pointerTarget.current.y * 0.25;
        const dynamicRotZ = baseRotZ + Math.sin(time * 0.6) * 0.03;

        shieldMesh.rotation.x += (dynamicRotX - shieldMesh.rotation.x) * 0.08;
        shieldMesh.rotation.y += (dynamicRotY - shieldMesh.rotation.y) * 0.08;
        shieldMesh.rotation.z += (dynamicRotZ - shieldMesh.rotation.z) * 0.08;
        shieldMesh.position.y = floatY;

        camera.position.y = scrollOffset.current * 0.5;

        // Specular moving highlight across bevels
        pointLight.position.x = Math.cos(time * 0.9) * 2.8;
        pointLight.position.y = Math.sin(time * 0.9) * 2.2;
        pointLight.position.z = 2.0;

        // Scanning beam cycle
        const beamCycle = (time % 3.5) / 3.5;
        beamMesh.position.y = 1.25 - beamCycle * 2.5;
        beamMat.opacity = state.armed ? 0.9 : 0.6;

        // Revolve chain links around 3D tilted planetary orbit
        const spinSpeed = state.armed ? 2.5 : 1.0;
        chainAngle += delta * 0.35 * spinSpeed;
        chainMesh.rotation.z = chainAngle;

        if (state.launching) {
          launchProgress = Math.min(1, launchProgress + delta * 2.5);
          const contracted = chainRadius * (1 - launchProgress * 0.35);
          updateChainPositions(contracted);
          const pulse = 1 + Math.sin(launchProgress * Math.PI) * 0.15;
          shieldMesh.scale.set(pulse, pulse, pulse);
        } else if (launchProgress > 0) {
          launchProgress = Math.max(0, launchProgress - delta * 2);
          updateChainPositions(chainRadius);
          shieldMesh.scale.set(1, 1, 1);
        }

        if (state.invalid) {
          shakeTimer += delta * 24;
          shieldMesh.position.x = Math.sin(shakeTimer) * 0.12;
          shieldMat.emissive.setHex(0xef4444);
          shieldMat.emissiveIntensity = 0.8;
        } else {
          shakeTimer = 0;
          shieldMesh.position.x = 0;
          if (state.valid) {
            shieldMat.emissive.setHex(0x10b981);
            shieldMat.emissiveIntensity = 0.75;
          } else {
            shieldMat.emissive.setHex(0x0d9488);
            shieldMat.emissiveIntensity = state.armed ? 0.55 : 0.28;
          }
        }

        // Update 3D orbiting nodes with genuine depth travel
        const posAttr = lineGeo.attributes.position as THREE.BufferAttribute;
        const positions = posAttr.array as Float32Array;
        let lineIdx = 0;

        for (let i = 0; i < nodeCount; i++) {
          const nodeSpeed = 0.4 + (i % 3) * 0.12;
          const nodeAngle = time * nodeSpeed + (i / nodeCount) * Math.PI * 2;
          const radiusX = 2.15 + (i % 2) * 0.3;
          const radiusY = 1.65 + ((i + 1) % 2) * 0.25;
          const nx = Math.cos(nodeAngle) * radiusX;
          const ny = Math.sin(nodeAngle) * radiusY;
          const nz = Math.sin(nodeAngle * 1.4 + i) * 0.85;

          dummy.position.set(nx, ny, nz);
          dummy.scale.setScalar(0.9 + Math.sin(time * 2 + i) * 0.15);
          dummy.updateMatrix();
          nodesMesh.setMatrixAt(i, dummy.matrix);

          if (lineIdx < maxLines && i % 2 === 0) {
            positions[lineIdx * 6] = nx;
            positions[lineIdx * 6 + 1] = ny;
            positions[lineIdx * 6 + 2] = nz;
            positions[lineIdx * 6 + 3] = nx * 0.35;
            positions[lineIdx * 6 + 4] = ny * 0.35;
            positions[lineIdx * 6 + 5] = nz * 0.2;
            lineIdx++;
          }
        }
        nodesMesh.instanceMatrix.needsUpdate = true;

        for (let i = lineIdx * 6; i < maxLines * 6; i++) {
          positions[i] = 0;
        }
        posAttr.needsUpdate = true;

        // Floating particles
        const pPositions = particles.geometry.attributes.position.array as Float32Array;
        for (let i = 0; i < particleCount; i++) {
          pPositions[i * 3 + 1] += pVel[i] * delta * 0.5;
          if (pPositions[i * 3 + 1] > 2.8) {
            pPositions[i * 3 + 1] = -2.8;
          }
        }
        particles.geometry.attributes.position.needsUpdate = true;
      },
      onDestroy: () => {
        shieldGeo.dispose();
        innerGeo.dispose();
        edgesGeo.dispose();
        innerEdgesGeo.dispose();
        checkGeo.dispose();
        beamGeo.dispose();
        linkGeo.dispose();
        nodeGeo.dispose();
        lineGeo.dispose();
        pGeo.dispose();
        beamTex.dispose();
      },
    };
  };

  return (
    <ThreeCanvas
      onInit={handleInit}
      fallback={<ShieldFallback3D />}
      className="hero-shield-3d"
      style={{ width: "100%", height: "100%", minHeight: "26rem" }}
      ariaLabel="Interactive 3D security shield with chain and orbital nodes"
    />
  );
}
