# SafeLinks 🛡️

SafeLinks is a modern, high-performance security intelligence platform designed to evaluate URLs across phishing indicators, malware distributions, domain reputation, age heuristics, SSL integrity, and URL structural patterns before you ever open them on your device.

---

## 🌟 Key Features

* **3D Interactive Visualizer**: Procedurally extruded Three.js shields with dynamic perspective, multi-stage specular lighting, planetary chain rings, orbital nodes, and particle dust.
* **Dual Verdict Archetypes**:
  * **Verified Safe (Low Risk)**: Crystalline emerald shield with gleaming 3D checkmark, defensive orbital laser ring, positive security badges, and quick safe launch.
  * **Threat Detected (High Risk)**: High-impact fractured 3D cyber shield with jagged fissure, luminous 3D 'X' symbol, orbiting crimson laser rings, tumbling 3D crystal shards, and emergency "Go Back to Safety" control.
* **8-Point Constellation Analysis**: Interactive SVG constellation ring visualizing checks across Phishing, Malware, Reputation, Domain, SSL, and URL Structure with dynamic collision-free tooltips.
* **Machine Learning Phishing Model**: 34 lexical and structural URL features evaluated via a calibrated Random Forest classifier with feature impact attribution charts.
* **Comprehensive External Intelligence**: Google Safe Browsing v4, VirusTotal v3, and live WHOIS/RDAP age resolution with aggressive caching and graceful fallbacks.
* **Privacy & Safety First**: Automatic URL defanging toggle, zero-execution sandboxed evaluations, and full offline mock mode.

---

## 📂 Project Structure

```text
SafeLinks/
├── BACKEND/                  # Python FastAPI Backend
│   ├── app/
│   │   ├── api/v1/          # Endpoints (scans, health, config)
│   │   ├── core/            # Config, logging, security, cache
│   │   ├── intelligence/    # Google Safe Browsing, VirusTotal, WHOIS/RDAP
│   │   ├── ml/              # Feature extraction & trained model
│   │   └── scoring/         # Rules engine & verdict aggregation
│   └── tests/               # Test suites & fixtures
│
└── frontend/                 # React 19 + TypeScript + Vite + Tailwind CSS
    └── src/
        ├── app/             # Pages (Home, Report, History, About)
        ├── components/
        │   ├── fx/          # Additive motion (TiltCard, Grid, Blobs)
        │   ├── scan/        # Interactive SVG Constellation
        │   └── three/       # Three.js 3D Shields & Verdict Visuals
        └── lib/             # API client, polling hooks, local history
```

---

## 🚀 Quick Start

### 1. Backend (FastAPI)

```bash
cd BACKEND
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Swagger API docs available at: `http://127.0.0.1:8000/docs`

### 2. Frontend (Vite + React)

```bash
cd frontend
npm install
npm run dev
```
Web app will be running at: `http://127.0.0.1:5173/`

---

## 🔒 Security & Privacy

SafeLinks inspects URLs strictly through metadata, lexical heuristics, external intelligence feeds, and machine learning models. Links are never requested or opened on your device.
