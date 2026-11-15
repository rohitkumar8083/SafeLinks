import * as THREE from "three";

export function createShieldShape(): THREE.Shape {
  const shape = new THREE.Shape();
  shape.moveTo(0, 1.25);
  shape.quadraticCurveTo(0.5, 1.3, 0.95, 1.15);
  shape.quadraticCurveTo(1.05, 0.2, 0.85, -0.2);
  shape.quadraticCurveTo(0.5, -0.9, 0, -1.35);
  shape.quadraticCurveTo(-0.5, -0.9, -0.85, -0.2);
  shape.quadraticCurveTo(-1.05, 0.2, -0.95, 1.15);
  shape.quadraticCurveTo(-0.5, 1.3, 0, 1.25);
  return shape;
}

export function createInnerShieldShape(): THREE.Shape {
  const shape = new THREE.Shape();
  shape.moveTo(0, 1.05);
  shape.quadraticCurveTo(0.4, 1.1, 0.76, 0.96);
  shape.quadraticCurveTo(0.85, 0.16, 0.68, -0.16);
  shape.quadraticCurveTo(0.4, -0.72, 0, -1.08);
  shape.quadraticCurveTo(-0.4, -0.72, -0.68, -0.16);
  shape.quadraticCurveTo(-0.85, 0.16, -0.76, 0.96);
  shape.quadraticCurveTo(-0.4, 1.1, 0, 1.05);
  return shape;
}

export const shieldExtrudeSettings: THREE.ExtrudeGeometryOptions = {
  depth: 0.42,
  bevelEnabled: true,
  bevelSegments: 8,
  steps: 2,
  bevelSize: 0.08,
  bevelThickness: 0.09,
};

export const innerShieldExtrudeSettings: THREE.ExtrudeGeometryOptions = {
  depth: 0.08,
  bevelEnabled: true,
  bevelSegments: 4,
  steps: 1,
  bevelSize: 0.03,
  bevelThickness: 0.03,
};

export function createCheckMarkGeometry(): THREE.TubeGeometry {
  const curve = new THREE.CurvePath<THREE.Vector3>();
  const p1 = new THREE.Vector3(-0.32, 0.02, 0.28);
  const p2 = new THREE.Vector3(-0.08, -0.24, 0.28);
  const p3 = new THREE.Vector3(0.38, 0.32, 0.28);
  curve.add(new THREE.LineCurve3(p1, p2));
  curve.add(new THREE.LineCurve3(p2, p3));
  return new THREE.TubeGeometry(curve, 24, 0.068, 12, false);
}

export function createExclamationGeometry(): { stem: THREE.TubeGeometry; dot: THREE.SphereGeometry } {
  const curve = new THREE.LineCurve3(new THREE.Vector3(0, 0.35, 0.28), new THREE.Vector3(0, -0.08, 0.28));
  const stem = new THREE.TubeGeometry(curve, 16, 0.065, 12, false);
  const dot = new THREE.SphereGeometry(0.08, 16, 16);
  return { stem, dot };
}

export function createQuestionMarkGeometry(): { stem: THREE.TubeGeometry; dot: THREE.SphereGeometry } {
  const curve = new THREE.CatmullRomCurve3([
    new THREE.Vector3(-0.22, 0.2, 0.28),
    new THREE.Vector3(0, 0.42, 0.28),
    new THREE.Vector3(0.2, 0.28, 0.28),
    new THREE.Vector3(0.04, 0.08, 0.28),
    new THREE.Vector3(0, -0.06, 0.28),
  ]);
  const stem = new THREE.TubeGeometry(curve, 24, 0.062, 12, false);
  const dot = new THREE.SphereGeometry(0.075, 16, 16);
  return { stem, dot };
}

export function createFresnelMaterial(color: THREE.ColorRepresentation = 0x2dd4bf): THREE.ShaderMaterial {
  return new THREE.ShaderMaterial({
    uniforms: {
      glowColor: { value: new THREE.Color(color) },
      coefficient: { value: 0.12 },
      power: { value: 1.6 },
    },
    vertexShader: `
      varying vec3 vNormal;
      varying vec3 vPositionNormal;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        vPositionNormal = normalize((modelViewMatrix * vec4(position, 1.0)).xyz);
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform vec3 glowColor;
      uniform float coefficient;
      uniform float power;
      varying vec3 vNormal;
      varying vec3 vPositionNormal;
      void main() {
        float intensity = pow(coefficient + abs(dot(vPositionNormal, vNormal)), power);
        gl_FragColor = vec4(glowColor, clamp(intensity * 0.85, 0.0, 1.0));
      }
    `,
    side: THREE.BackSide,
    blending: THREE.AdditiveBlending,
    transparent: true,
    depthWrite: false,
  });
}

export function createParticleTexture(): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    gradient.addColorStop(0, "rgba(255, 255, 255, 1)");
    gradient.addColorStop(0.3, "rgba(45, 212, 191, 0.85)");
    gradient.addColorStop(0.7, "rgba(45, 212, 191, 0.25)");
    gradient.addColorStop(1, "rgba(0, 0, 0, 0)");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 64, 64);
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

export function createFracturedShieldGeometries(): {
  leftGeo: THREE.ExtrudeGeometry;
  rightGeo: THREE.ExtrudeGeometry;
} {
  // Left half shape with jagged central fissure
  const left = new THREE.Shape();
  left.moveTo(-0.02, 1.25);
  left.quadraticCurveTo(-0.5, 1.3, -0.95, 1.15);
  left.quadraticCurveTo(-1.05, 0.2, -0.85, -0.2);
  left.quadraticCurveTo(-0.5, -0.9, -0.02, -1.35);
  // Jagged crack going up
  left.lineTo(-0.09, -0.75);
  left.lineTo(0.02, -0.28);
  left.lineTo(-0.08, 0.18);
  left.lineTo(0.04, 0.65);
  left.lineTo(-0.06, 0.95);
  left.lineTo(-0.02, 1.25);

  // Right half shape with matching jagged fissure
  const right = new THREE.Shape();
  right.moveTo(0.02, 1.25);
  right.lineTo(0.08, 0.95);
  right.lineTo(-0.02, 0.65);
  right.lineTo(0.1, 0.18);
  right.lineTo(0.0, -0.28);
  right.lineTo(0.11, -0.75);
  right.lineTo(0.02, -1.35);
  // Outer right curve
  right.quadraticCurveTo(0.5, -0.9, 0.85, -0.2);
  right.quadraticCurveTo(1.05, 0.2, 0.95, 1.15);
  right.quadraticCurveTo(0.5, 1.3, 0.02, 1.25);

  const leftGeo = new THREE.ExtrudeGeometry(left, shieldExtrudeSettings);
  const rightGeo = new THREE.ExtrudeGeometry(right, shieldExtrudeSettings);
  leftGeo.center();
  rightGeo.center();

  return { leftGeo, rightGeo };
}

export function createXMarkGeometry(): { bar1: THREE.TubeGeometry; bar2: THREE.TubeGeometry } {
  const c1 = new THREE.LineCurve3(new THREE.Vector3(-0.32, 0.32, 0.32), new THREE.Vector3(0.32, -0.32, 0.32));
  const c2 = new THREE.LineCurve3(new THREE.Vector3(0.32, 0.32, 0.32), new THREE.Vector3(-0.32, -0.32, 0.32));
  const bar1 = new THREE.TubeGeometry(c1, 16, 0.075, 12, false);
  const bar2 = new THREE.TubeGeometry(c2, 16, 0.075, 12, false);
  return { bar1, bar2 };
}
