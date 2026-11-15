# SafeLinks Frontend Handover Documentation

## 1. Project Context & Prime Directive

SafeLinks is a security intelligence web application that evaluates URLs across phishing, malware, domain age, SSL integrity, reputation feeds, and structural heuristics. 

### The Prime Directive: Strict Figma Design Lock
The Figma Make design is **final, approved, and locked**. 
- Resting UI, colors, typography, border-radii, glassmorphism blur, layout grids, and spacing are strictly preserved.
- All additions in Part 4, Part 5, and Part 6 are strictly **additive** and must look as if authored by the original Figma designer.
- In **Reduced Effects** mode (`safelinks:effects:v1 = "reduced"` or `prefers-reduced-motion`), the app completely falls back to the clean static presentation without canvases or continuous animation loops.

---

## 2. Directory Structure & Architecture

```text
frontend/
├── _handover/
│   ├── baseline/                # Baseline screenshots before modifications
│   │   ├── home_desktop.png
│   │   ├── home_mobile.png
│   │   ├── about_desktop.png
│   │   └── history_desktop.png
│   └── post_p6/                 # Verification screenshots post Part 6
├── public/
├── src/
│   ├── app/
│   │   ├── components/
│   │   │   ├── layout.tsx       # Header, navigation, logo, footer, theme & effects toggle
│   │   │   ├── shared.tsx       # UrlScanForm, VerdictBadge
│   │   │   └── ui.tsx           # Button, Input, Card, Badge, Skeleton, Progress, Tooltip, Alert, Modal
│   │   ├── pages/
│   │   │   ├── Home.tsx         # Hero, trust strip, feature cards, steps, recent activity, FAQ
│   │   │   ├── Report.tsx       # Security report, verdict summary, gauge, checks, ML chart, domain info
│   │   │   ├── History.tsx      # Local scan history table, cards, clear modal
│   │   │   ├── About.tsx        # Detection layers explanation, score levels, limits
│   │   │   └── NotFound.tsx     # 404 lost link page
│   │   ├── App.tsx              # App provider shell (Theme, Toaster, Router)
│   │   ├── routes.tsx           # HashRouter routing table
│   │   └── theme.tsx            # ThemeProvider (dark, light, system)
│   ├── components/
│   │   ├── fx/                  # Part 5: Additive motion layer components
│   │   │   ├── AnimatedGrid.tsx
│   │   │   ├── ParticleBackdrop.tsx
│   │   │   ├── GlowCursor.tsx
│   │   │   ├── SpotlightBorder.tsx
│   │   │   ├── TiltCard.tsx
│   │   │   ├── MagneticButton.tsx
│   │   │   ├── Reveal.tsx
│   │   │   ├── CountUp.tsx
│   │   │   ├── TextScramble.tsx
│   │   │   ├── GradientBlobs.tsx
│   │   │   ├── NoiseOverlay.tsx
│   │   │   └── index.ts
│   │   ├── three/               # Part 6: Three.js WebGL visuals & fallbacks
│   │   │   ├── ThreeCanvas.tsx  # Renderer lifecycle, resize, pause, fallback
│   │   │   ├── ShieldFallback3D.tsx # CSS 3D 5-layer shield fallback
│   │   │   ├── HeroShield.tsx   # 3D interactive hero shield
│   │   │   ├── VerdictOrb.tsx   # 3D verdict summary shield / scanning orb
│   │   │   └── shieldGeometry.ts# Procedural extruded shield & symbol geometries
│   │   └── scan/
│   │       └── ScanConstellation.tsx # 8-node interactive SVG constellation
│   ├── lib/
│   │   ├── api/                 # Part 3: Contract types, mock client, real HTTP client
│   │   │   ├── client.ts
│   │   │   ├── errors.ts
│   │   │   ├── index.ts
│   │   │   ├── mock.ts
│   │   │   ├── schemas.ts
│   │   │   └── types.ts
│   │   ├── hooks/               # Part 4: Integration hooks
│   │   │   ├── useHistory.ts    # localStorage 'safelinks:history:v1', cache & fallback
│   │   │   └── useScan.ts       # 1500ms polling, backoff, 90s timeout, slow banner
│   │   ├── motion/              # Part 5: Tokens & capability detection
│   │   │   ├── tokens.ts
│   │   │   └── useCapabilities.ts # reducedMotion, coarsePointer, lowPower, webgl
│   │   └── utils/
│   │       ├── format.ts
│   │       ├── url.ts
│   │       └── verdict.ts
│   ├── config.ts                # Environment and mock toggle configuration
│   ├── index.css                # Design tokens, CSS variables, glassmorphism, animations
│   ├── main.tsx                 # React DOM mount point
│   └── vite-env.d.ts
├── package.json
├── tsconfig.json
└── vite.config.ts
```

---

## 3. Design System & Tokens

### CSS Variables
- **Primary Teal**: `hsl(173 80% 32%)` (Light) / `hsl(173 80% 40%)` (Dark)
- **Accent Violet**: `hsl(262 70% 55%)` (Light) / `hsl(262 83% 66%)` (Dark)
- **Verdict Tones**:
  - `safe`: `hsl(142 71% 35% / 45%)`
  - `caution`: `hsl(38 92% 42% / 50%)`
  - `danger`: `hsl(0 76% 52% / 60%)`
  - `orange`: `hsl(24 90% 45% / 58%)`
  - `unknown`: `hsl(215 16% 45% / 60%)`
- **Surfaces**:
  - Glass Card: `border: 1px solid var(--border); background: var(--card); backdrop-filter: blur(18px);`
- **Typography**: Inter (UI / headings), JetBrains Mono (URLs, code, scores).

---

## 4. Phase Breakdown & Implementation Status

### Phase 1: Audit & Baseline
- Inspected complete codebase and configuration files.
- Captured baseline screenshots in `_handover/baseline/`.
- Documented git status: git CLI not available on runner environment; baseline snapshot persisted on disk.

### Phase 2: Part 4 — Application Integration
- `useScan.ts`: Polling at 1500ms with backoff (1.5s, 3s, 6s), 90s timeout, visibility pause, strict-mode safe.
- `useHistory.ts`: LocalStorage `safelinks:history:v1`, 50-item FIFO history, 20-item report cache, in-memory fallback.
- `UrlScanForm`: Connected to `scanApi.createScan()`, input disabled on loading, inline validation error handling.
- `Report.tsx`: Connected to live scan results, dynamic check list, severity-ranked sorting, Recharts feature explanation, recommendations, actions (Print, JSON, Share).
- Verified with 7 mock test scenarios: `google.com`, `paypal-secure-login.xyz`, `unknown-site.com`, `fail-test.com`, `example-shop.com`, `ratelimit.com`, `offline.com`.

### Phase 3: Part 5 — Motion & Animations
- `tokens.ts`: Standardized durations (fast 150ms, base 250ms, slow 500ms, hero 900ms) and `easeOutExpo` easing.
- `useCapabilities.ts`: Detects `reducedMotion`, `coarsePointer`, `lowPower`, and `webgl`.
- Background FX: `AnimatedGrid` (perspective scrolling floor), `ParticleBackdrop` (2D canvas connected dots), `GradientBlobs`, `NoiseOverlay`.
- Interactive FX: `TiltCard` (3D hover tilt & glare), `MagneticButton` (pointer pull, shimmer sweep, tap ripple), `Reveal` (in-view fade-up), `CountUp`, `TextScramble` (defang toggle & URL scramble).
- UI Animations: Header scroll blur, active nav pill (`layoutId`), mobile sheet stagger, card hover lift, check sweep line, high-risk vignette pulse.

### Phase 4: Part 6 — 3D & Scanning Visuals
- `ThreeCanvas.tsx`: Managed WebGLRenderer lifecycle, DPR clamp (1.5 on lowPower, 2.0 max), pause on hidden tab or offscreen intersection, clean resource disposal, fallback rendering.
- `ShieldFallback3D.tsx`: 5-layer stacked SVG shield outlines at varying translateZ depths with perspective, tilting with pointer or scroll.
- `HeroShield.tsx`: Three.js procedural extruded shield with Fresnel rim glow, sweeping scan beam, 24-link rotating chain ring, 10 orbital network nodes, particle dust, and form state responsiveness (`armed`, `valid`, `invalid`, `launching`).
- `VerdictOrb.tsx`: SummaryCard 3D shield with states for scanning (wireframe icosahedron & expanding rings), likely safe, suspicious, likely malicious (shard burst & pulse), and unknown.
- `ScanConstellation.tsx`: 8-node interactive SVG constellation ring with radar sweep, status badges, connecting beam lines, and click-to-scroll card highlighting.

---

## 5. Phase 5: Verification & Quality Assurance Report

### Automated Checks
1. **TypeScript Typecheck**:
   - Command: `tsc --noEmit`
   - Result: **0 errors**, fully clean compilation across all components, hooks, and types.
2. **Production Bundle Build**:
   - Command: `vite build`
   - Result: **Passed** (built in 1.02s), generating production bundle assets in `dist/`.

### Visual Verification & Screenshots
All post-P6 screenshots were captured at multiple breakpoints using headless Microsoft Edge and are stored in `frontend/_handover/post_p6/`:
- `home_desktop.png` (1440x1100): Full desktop hero with 3D HeroShield, background perspective grid, particle backdrop, gradient shimmer, and tilt cards.
- `home_tablet.png` (768x1024): Responsive layout at tablet breakpoint.
- `home_mobile.png` (390x844): Mobile view with stacked columns, responsive form, and mobile navigation drawer.
- `report_desktop.png` (1440x1200): Report page for safe verdict featuring 3D VerdictOrb, interactive SVG ScanConstellation, gauge countup, and domain info.
- `report_phishing_desktop.png` (1440x1200): Phishing verdict showing high-risk red perimeter vignette, shattered orb animation, and threat warnings.
- `report_mobile.png` (390x844): Mobile report view with responsive reordered layout.
- `about_desktop.png` (1440x1100): About page with 8 interactive tilt check cards and score explainer.
- `history_desktop.png` (1440x900): Scan history table with smooth row transitions and floating empty state icon.

### Accessibility, Performance & Fallback Verification
- **Effects Toggle**: Available directly in the header next to Theme control (`Full` / `Reduced`). Toggling modes adds/removes `.effects-reduced` on `document.documentElement` and persists to `localStorage`.
- **Reduced Motion & Design Lock Compliance**: When `effectsMode === "reduced"` or `prefers-reduced-motion` is enabled:
  - Three.js canvases and particle backdrops are unmounted.
  - Background grid and cursor glows are hidden.
  - Animated progress stripes and scan sweeps are disabled.
  - The hero shield and verdict orb fall back to the exact Figma Make resting SVG shields.
- **Resource Cleanup**: All Three.js geometries, materials, textures, and renderers are explicitly disposed upon component unmount, preventing GPU memory leaks.
- **Rendering Throttling**: Tab visibility and viewport intersection observers automatically freeze animation loops when offscreen or minimized.

---

## 6. How to Run & Test

```bash
# Frontend dev server (port 5173)
cd frontend
npm run dev

# Frontend production build
cd frontend
npm run build

# Backend server (port 8000)
cd BACKEND
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
