# SafeLinks API

SafeLinks is a high-performance, asynchronous URL security analysis engine built with **FastAPI** and **Python 3.11+**. Given any target URL, SafeLinks orchestrates a multi-vector risk evaluation across lexical structure, machine learning classification, domain age & WHOIS, SSL/TLS certificates, redirect paths, and external threat intelligence feeds (Google Safe Browsing, VirusTotal, and abuse.ch URLhaus).

It powers the SafeLinks web application (React frontend built in Figma Make) via a strictly versioned REST API conforming field-for-field to the SafeLinks Shared API Contract v1.

---

## Table of Contents
- [Architecture Overview](#architecture-overview)
  - [Folder Map](#folder-map)
  - [Request Lifecycle](#request-lifecycle)
  - [Trust Boundaries & SSRF Defense](#trust-boundaries--ssrf-defense)
- [Quickstart](#quickstart)
  - [Prerequisites](#prerequisites)
  - [Local Setup (PowerShell - Windows)](#local-setup-powershell---windows)
  - [Local Setup (Bash - Linux / macOS)](#local-setup-bash---linux--macos)
- [Environment Variables](#environment-variables)
- [External Threat Intelligence Setup](#external-threat-intelligence-setup)
  - [1. Google Safe Browsing (v4)](#1-google-safe-browsing-v4)
  - [2. VirusTotal (v3)](#2-virustotal-v3)
  - [3. abuse.ch URLhaus](#3-abusech-urlhaus)
- [Machine Learning Pipeline](#machine-learning-pipeline)
  - [Dataset Acquisition & Preparation](#dataset-acquisition--preparation)
  - [Model Training & Calibration](#model-training--calibration)
  - [Occlusion Feature Attribution](#occlusion-feature-attribution)
  - [Dataset Bias & Limitations](#dataset-bias--limitations)
  - [Missing Model Fallback](#missing-model-fallback)
- [API Reference](#api-reference)
  - [1. Health Check (`GET /api/v1/health`)](#1-health-check-get-apiv1health)
  - [2. Submit URL Scan (`POST /api/v1/scans`)](#2-submit-url-scan-post-apiv1scans)
  - [3. Poll Scan Results (`GET /api/v1/scans/{scan_id}`)](#3-poll-scan-results-get-apiv1scansscan_id)
  - [Error Responses](#error-responses)
- [Production Deployment](#production-deployment)
  - [Docker Container Build & Run](#docker-container-build--run)
  - [Cloud Run / Render / Railway Deployment](#cloud-run--render--railway-deployment)
  - [Resource Sizing Recommendations](#resource-sizing-recommendations)
- [Assumptions & Limitations](#assumptions--limitations)

---

## Architecture Overview

### Folder Map

```text
BACKEND/
├── Dockerfile                  # Multi-stage production container build (non-root appuser)
├── .dockerignore               # Optimized Docker context excludes
├── .env.example                # Canonical environment variable specification
├── .gitignore                  # Git ignore rules
├── pyproject.toml              # Ruff and pytest configuration
├── requirements.txt            # Locked production dependencies
├── requirements-dev.txt        # Development, testing, and linting tools
├── README.md                   # Complete service documentation (this file)
├── app/
│   ├── main.py                 # FastAPI app factory, lifespan, CORS, and routers
│   ├── config.py               # Pydantic Settings loaded from environment
│   ├── constants.py            # Global contract constants and check ordering
│   ├── api/
│   │   ├── deps.py             # Dependency injection providers
│   │   └── v1/
│   │       ├── router.py       # Aggregated v1 API router
│   │       ├── routes_health.py# Health check endpoint
│   │       └── routes_scans.py # Scan submission and polling endpoints
│   ├── core/
│   │   ├── async_rate_limiter.py # Sliding-window minute and UTC-day limiter
│   │   ├── cache.py            # Thread-safe in-memory TTL threat intel cache
│   │   ├── errors.py           # Custom exception hierarchy and HTTP handlers
│   │   ├── http_client.py      # Shared HTTPX client with connection pooling
│   │   ├── logging.py          # Structured standard library logging
│   │   ├── middleware.py       # Request ID & Cache-Control: no-store middleware
│   │   ├── rate_limit.py       # SlowAPI client IP rate limiter and 429 handler
│   │   └── ssrf_guard.py       # Strict IP parsing, DNS resolution, and SSRF guard
│   ├── data/
│   │   ├── brands.py           # High-value brand names for spoof detection
│   │   ├── risky_tlds.py       # High-abuse top-level domains
│   │   ├── shorteners.py       # URL shortener domain catalog
│   │   ├── suspicious_keywords.py # Phishing credential & urgency keywords
│   │   └── trusted_domains.py  # Major platform allowlist for score dampening
│   ├── ml/
│   │   ├── features.py         # 34 pure lexical feature extractors (shared train/inference)
│   │   ├── prepare_dataset.py  # Dataset normalization, balance, and path synthesis CLI
│   │   ├── train.py            # GroupShuffleSplit training, comparison, and calibration CLI
│   │   ├── predict.py          # Calibrated inference engine with occlusion attribution
│   │   ├── data/               # Raw training data inputs and processed CSV
│   │   │   └── README.md       # Dataset sourcing and download instructions
│   │   └── model/              # Persisted joblib model and training metadata JSON
│   ├── repositories/
│   │   └── scan_repo.py        # In-memory repository with TTL purge and LRU eviction
│   ├── schemas/
│   │   ├── errors.py           # RFC 7807 compliant contract error models
│   │   └── scan.py             # Shared API contract v1 Pydantic models and enums
│   └── services/
│       ├── context.py          # Immutable per-scan execution context
│       ├── recommendations.py  # Actionable user advice generation
│       ├── risk_scoring.py     # Deterministic risk scoring, floors, and confidence
│       ├── scan_orchestrator.py# Async check fan-out and lifecycle management
│       ├── url_normalizer.py   # Scheme enforcement, domain punycode, and normalization
│       └── checks/
│           ├── base.py         # Abstract check definition and outcome schema
│           ├── registry.py     # Check registration and mode-based ordering
│           ├── url_structure.py# Structural and lexical heuristic analysis
│           ├── ml_phishing.py  # Trained machine learning model inference
│           ├── domain_age.py   # RDAP & WHOIS domain registration age check
│           ├── ssl_certificate.py # TLS certificate validity and expiry inspection
│           ├── redirect_chain.py  # Multi-hop redirect tracking and destination check
│           ├── google_safe_browsing.py # Google Safe Browsing Lookup API v4
│           ├── virustotal.py   # VirusTotal v3 URL analysis with polling & rate limit
│           └── urlhaus.py      # abuse.ch URLhaus malware database lookup
├── scripts/
│   ├── make_synthetic_dataset.py # Generates fallback synthetic dataset for training
│   └── smoke_test.py           # Interactive CLI smoke test against live server
└── tests/                      # Full pytest test suite (59 unit and integration tests)
```

### Request Lifecycle

```text
[ Client Request ]
       │  POST /api/v1/scans {"url": "https://example.com", "mode": "full"}
       ▼
[ Middleware ] ─── Attaches/echoes X-Request-ID, sets Cache-Control: no-store
       │
[ SlowAPI Limiter ] ─── Enforces per-client-IP rate limits (default: 10/min)
       │
[ URL Normalizer ] ─── Validates scheme (http/https), normalizes host, path, punycode
       │
[ SSRF Guard Pre-Check ] ─── Resolves DNS; rejects private/loopback/metadata IPs -> 422
       │
[ Scan Repository ] ─── Persists scan with status: "pending", 8 checks registered
       │
[ HTTP 202 Accepted ] ─── Immediate response with scan_id and initial snapshot
       │
       ├────────────────────────────────────────┐ (Background Task via asyncio)
       ▼                                        ▼
[ Orchestrator Fan-Out ]                 [ Client Polls GET /api/v1/scans/{id} ]
   ├── url_structure (sync)                     │ Returns status: "processing"
   ├── ml_phishing (async thread)               │ until status: "done"
   ├── domain_age (async whois/rdap)            │
   ├── ssl_certificate (async TLS handshake)    │
   ├── redirect_chain (async HTTP crawl + SSRF) │
   ├── google_safe_browsing (HTTP API)          │
   ├── virustotal (HTTP API + rate limiter)     │
   └── urlhaus (HTTP API)                       │
       │                                        │
[ Aggregate Outcomes ]                          │
       │                                        │
[ Risk Scoring Engine ]                         │
   ├── Hard floors (GSB, VT, URLhaus)           │
   ├── Soft weights renormalization             │
   ├── Trusted domain dampening                 │
   └── Confidence & summary generation          │
       │                                        │
[ Recommendations Engine ]                      │
       │                                        │
[ Persist Completed Scan ] ◄────────────────────┘
   Scan status: "done", final score, verdict, confidence, checks, recommendations
```

### Trust Boundaries & SSRF Defense
1. **Scheme Validation**: Strictly allows only `http` and `https`. Schemes such as `ftp://`, `file://`, `data:`, or `javascript:` are immediately rejected with HTTP 422 `UNSUPPORTED_SCHEME`.
2. **SSRF Guard**: Before any network connection is attempted, all target hostnames are resolved to IP addresses via DNS. Any destination belonging to RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local/cloud metadata (`169.254.169.254`, `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), or IPv4-mapped IPv6 ranges is rejected with HTTP 422 `BLOCKED_TARGET`.
3. **Redirect Hop Verification**: The crawler re-checks each redirect hop against the SSRF guard before following headers, preventing DNS rebinding and open redirect exploitation.
4. **Trusted Domain Dampening**: Known legitimate platform domains (e.g. `google.com`, `microsoft.com`, `apple.com`) receive a 50% dampening on heuristic/ML structural scores unless a hard threat intelligence hit (Google Safe Browsing, VirusTotal >= 5, or active URLhaus listing) is present.

---

## Quickstart

### Prerequisites
- **Python 3.11** or **Python 3.12** installed on your system.
- Network access to resolve domain names and fetch threat intelligence APIs (optional).

### Local Setup (PowerShell - Windows)

```powershell
# 1. Navigate to the BACKEND directory
cd d:\SafeLinks\BACKEND

# 2. Create virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install production and development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 5. Configure environment variables
Copy-Item .env.example .env

# 6. Train the phishing detection ML model
python -m scripts.make_synthetic_dataset
python -m app.ml.train --data app/ml/data/urls.csv --out app/ml/model --seed 42

# 7. Run the test suite
pytest -v

# 8. Start the FastAPI development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Local Setup (Bash - Linux / macOS)

```bash
# 1. Navigate to the BACKEND directory
cd BACKEND

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Install production and development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 5. Configure environment variables
cp .env.example .env

# 6. Train the phishing detection ML model
python -m scripts.make_synthetic_dataset
python -m app.ml.train --data app/ml/data/urls.csv --out app/ml/model --seed 42

# 7. Run the test suite
pytest -v

# 8. Start the FastAPI development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## Environment Variables

All settings are managed via `pydantic-settings` in `app/config.py` and can be overridden by creating a `.env` file in `BACKEND/`:

| Variable | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `APP_NAME` | string | `SafeLinks API` | No | Application display name returned in docs |
| `APP_VERSION` | string | `1.0.0` | No | API version string reported at `/api/v1/health` |
| `ENVIRONMENT` | string | `dev` | No | Runtime mode (`dev` or `prod`) |
| `LOG_LEVEL` | string | `INFO` | No | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `HOST` | string | `0.0.0.0` | No | Network interface for uvicorn |
| `PORT` | integer | `8000` | No | TCP port for uvicorn |
| `ALLOWED_ORIGINS` | string | `*` | No | Comma-separated list of allowed CORS origins (`*` allows all) |
| `ALLOWED_ORIGIN_REGEX` | string | `None` | No | Optional regex matching frontend preview domains |
| `TRUST_PROXY_HEADERS` | boolean | `false` | No | When `true`, uses `X-Forwarded-For` for client rate limiting |
| `GOOGLE_SAFE_BROWSING_API_KEY`| string | `None` | No | Google Safe Browsing Lookup v4 API Key |
| `VIRUSTOTAL_API_KEY` | string | `None` | No | VirusTotal v3 REST API Key |
| `URLHAUS_AUTH_KEY` | string | `None` | No | abuse.ch URLhaus Auth Key (optional for queries) |
| `SCAN_TTL_MINUTES` | integer | `60` | No | Scan retention duration before in-memory expiration |
| `MAX_STORED_SCANS` | integer | `5000` | No | Maximum in-memory scans stored before LRU eviction |
| `MAX_CONCURRENT_SCANS` | integer | `20` | No | Maximum concurrent asynchronous scan executions |
| `RATE_LIMIT_SCANS_PER_MINUTE` | integer | `10` | No | Max scan submissions per minute per client IP |
| `RATE_LIMIT_READS_PER_MINUTE` | integer | `120` | No | Max scan read/poll requests per minute per client IP |
| `CHECK_TIMEOUT_SECONDS` | integer | `12` | No | Timeout in seconds for individual check modules |
| `OVERALL_SCAN_TIMEOUT_SECONDS`| integer | `45` | No | Max duration for complete scan lifecycle |
| `HTTP_TIMEOUT_SECONDS` | integer | `8` | No | Network timeout for outbound HTTP crawler requests |
| `MAX_REDIRECTS` | integer | `5` | No | Maximum followed redirect hops |
| `CACHE_TTL_SECONDS` | integer | `3600` | No | TTL for cached external threat intelligence results |
| `VT_REQUESTS_PER_MINUTE` | integer | `4` | No | Rate limit for VirusTotal requests per minute |
| `VT_REQUESTS_PER_DAY` | integer | `500` | No | Rate limit for VirusTotal requests per UTC day |
| `VT_MAX_WAIT_SECONDS` | integer | `20` | No | Max wait duration for VirusTotal analysis polling |
| `MODEL_PATH` | string | `app/ml/model/phishing_model.joblib` | No | Path to trained scikit-learn model artifact |

---

## External Threat Intelligence Setup

SafeLinks works completely out-of-the-box without external API keys (running lexical, ML, domain age, SSL, and redirect checks). Configuring threat intelligence feeds adds authoritative multi-engine threat detection:

### 1. Google Safe Browsing (v4)
- **What it covers**: Billions of URLs checked against Google's anti-malware and social engineering blacklists.
- **Quota**: 10,000 queries per day (Free tier).
- **How to get a key**:
  1. Open [Google Cloud Console Credentials](https://console.cloud.google.com/apis/credentials).
  2. Create or select a Google Cloud project.
  3. Navigate to **APIs & Services > Library**, search for **Safe Browsing APIs**, and click **Enable**.
  4. Go to **Credentials > Create Credentials > API Key**.
  5. Add to `.env`: `GOOGLE_SAFE_BROWSING_API_KEY=AIzaSy...`

### 2. VirusTotal (v3)
- **What it covers**: Aggregates 70+ antivirus and URL reputation scanners worldwide.
- **Quota**: 4 requests/minute, 500 requests/day (Free Community tier).
- **How to get a key**:
  1. Register a free account at [VirusTotal Signup](https://www.virustotal.com/gui/join-us).
  2. Confirm your email address and log in.
  3. Click your user avatar in the top-right corner and select **API Key**.
  4. Copy your 64-character hexadecimal key.
  5. Add to `.env`: `VIRUSTOTAL_API_KEY=your_64_char_key...`

### 3. abuse.ch URLhaus
- **What it covers**: High-confidence community database of URLs used for malware distribution.
- **Quota**: Unlimited community queries.
- **How to get a key**:
  1. URL querying does not strictly require an auth key, but registered researchers can obtain an Auth-Key from [URLhaus API](https://urlhaus.abuse.ch/api/).
  2. Add to `.env`: `URLHAUS_AUTH_KEY=your_key...` (or leave empty; SafeLinks will still query the public endpoint).

---

## Machine Learning Pipeline

SafeLinks uses a calibrated ensemble model trained exclusively on **34 lexical and structural features** extracted by `app.ml.features.extract_features(url: str) -> dict`. This function performs zero network requests and never raises an exception even on malformed inputs.

### Dataset Acquisition & Preparation
To train on production datasets:
1. Download a phishing URL feed (e.g., [OpenPhish Feed](https://openphish.com/feed.txt) or [PhishTank CSV](https://data.phishtank.com/data/online-valid.csv)) to `app/ml/data/raw/phishing.txt`.
2. Download the Tranco top-sites ranking from [Tranco List](https://tranco-list.eu/) to `app/ml/data/raw/benign_domains.csv`.
3. Run the dataset preparation CLI:
   ```bash
   python -m app.ml.prepare_dataset --phishing app/ml/data/raw/phishing.txt --benign app/ml/data/raw/benign_domains.csv --out app/ml/data/urls.csv --ratio 1.0
   ```
   *Note: The preparation script synthesizes realistic deep paths (`/account`, `/login`, `/products/123`, etc.) for benign domains to ensure the classifier does not erroneously learn that "presence of a path" indicates phishing.*

### Model Training & Calibration
Train candidate models with GroupShuffleSplit domain-level partitioning:
```bash
python -m app.ml.train --data app/ml/data/urls.csv --out app/ml/model --seed 42
```
- Trains `LogisticRegression` (with `StandardScaler`), `RandomForest` (300 estimators, balanced class weights), and `HistGradientBoosting`.
- Selects the best performing model by ROC-AUC (tie-breaking on PR-AUC).
- Calibrates probabilities using `CalibratedClassifierCV` (isotonic if > 5000 samples, else sigmoid).
- Exports `phishing_model.joblib` and comprehensive training summary `metadata.json`.

### Occlusion Feature Attribution
For each prediction, SafeLinks explains the output using **feature occlusion**:
1. Computes the baseline probability $P_{\text{orig}}$.
2. Synthesizes 34 variations, each substituting one feature with its dataset training median.
3. Calculates raw impact: $\text{impact}_i = P_{\text{orig}} - P_{\text{occluded}, i}$.
4. Normalizes impacts into the range $[-1.0, 1.0]$ and returns the top 8 influential features in the response contract.

### Dataset Bias & Limitations
- **Lexical Boundaries**: Pure lexical models evaluate structure, not page content. Novel phishing domains crafted with benign-looking URL structures may evade lexical detection (which is why SafeLinks combines ML with WHOIS, SSL, and multi-engine threat intelligence).
- **Domain Memorization**: Group-splitting by registered domain prevents data leakage between train and test sets. ROC-AUC scores exceeding 0.995 on synthetic datasets trigger a warning in the training CLI noting dataset bias.

### Missing Model Fallback
If `app/ml/model/phishing_model.joblib` is absent:
- The service starts normally and logs a warning.
- `/api/v1/health` reports `"ml_model_loaded": false`.
- The `ml_phishing` check returns `status: "skipped"` with title `"Model not loaded"`.
- The risk scoring engine automatically renormalizes remaining check weights without penalty.

---

## API Reference

All requests accept and return JSON. Every response includes:
- `Cache-Control: no-store`
- `X-Request-ID: <uuidv4>`

### 1. Health Check (`GET /api/v1/health`)
Returns backend operational status, version, and ML model readiness.

```bash
curl -X GET http://127.0.0.1:8000/api/v1/health
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "ml_model_loaded": true
}
```

---

### 2. Submit URL Scan (`POST /api/v1/scans`)
Submits a URL for asynchronous analysis. Modes: `"quick"` (structure + ML) or `"full"` (all 8 vectors).

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/test", "mode": "full"}'
```

**Response (202 Accepted):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "submitted_url": "https://example.com/test",
  "normalized_url": "https://example.com/test"
}
```

---

### 3. Poll Scan Results (`GET /api/v1/scans/{scan_id}`)
Poll the scan status until `status` becomes `"completed"` (or `"failed"`).

```bash
curl -X GET http://127.0.0.1:8000/api/v1/scans/550e8400-e29b-41d4-a716-446655440000
```

**Response (200 OK - Completed Report):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "submitted_url": "https://example.com/test",
  "normalized_url": "https://example.com/test",
  "created_at": "2026-11-02T15:00:00Z",
  "completed_at": "2026-11-02T15:00:02Z",
  "progress": {
    "completed_checks": 8,
    "total_checks": 8
  },
  "checks": [
    {
      "id": "url_structure",
      "name": "URL Structure & Lexical Heuristics",
      "category": "url_structure",
      "status": "done",
      "severity": "info",
      "title": "Standard URL structure",
      "detail": "No suspicious tokens or structural anomalies identified",
      "evidence": ["Host length: 11 characters"],
      "source": "SafeLinks Heuristic Engine"
    },
    {
      "id": "ml_phishing",
      "name": "Machine Learning Phishing Classifier",
      "category": "phishing",
      "status": "done",
      "severity": "info",
      "title": "Low phishing probability",
      "detail": "Model evaluated phishing risk at 1.2%",
      "evidence": ["Lexical probability: 1.2%"],
      "source": "SafeLinks ML Engine"
    },
    {
      "id": "domain_age",
      "name": "Domain Registration & Age",
      "category": "domain",
      "status": "done",
      "severity": "info",
      "title": "Established domain",
      "detail": "Domain was registered 3000 days ago",
      "evidence": ["Registration: 2000-01-01"],
      "source": "WHOIS / RDAP Protocol"
    },
    {
      "id": "ssl_certificate",
      "name": "SSL/TLS Certificate Verification",
      "category": "ssl",
      "status": "done",
      "severity": "info",
      "title": "Valid SSL certificate",
      "detail": "Certificate is valid and active",
      "evidence": ["Issuer: DigiCert Inc"],
      "source": "TLS Handshake Inspector"
    },
    {
      "id": "redirect_chain",
      "name": "HTTP Redirect Chain Inspection",
      "category": "reputation",
      "status": "done",
      "severity": "info",
      "title": "Direct destination",
      "detail": "URL resolves directly without redirect hops",
      "evidence": ["Direct 200 OK"],
      "source": "SafeLinks Safe Crawler"
    },
    {
      "id": "google_safe_browsing",
      "name": "Google Safe Browsing",
      "category": "reputation",
      "status": "skipped",
      "severity": "info",
      "title": "Not configured",
      "detail": "Google Safe Browsing API key was not configured on this instance.",
      "evidence": [],
      "source": "Google Safe Browsing Lookup v4"
    },
    {
      "id": "virustotal",
      "name": "VirusTotal Intelligence",
      "category": "reputation",
      "status": "skipped",
      "severity": "info",
      "title": "Not configured",
      "detail": "VirusTotal API key was not configured on this instance.",
      "evidence": [],
      "source": "VirusTotal v3 API"
    },
    {
      "id": "urlhaus",
      "name": "abuse.ch URLhaus",
      "category": "malware",
      "status": "done",
      "severity": "info",
      "title": "Clean on URLhaus",
      "detail": "URL is not listed in abuse.ch URLhaus malware database",
      "evidence": ["No malicious listings found"],
      "source": "abuse.ch URLhaus Database"
    }
  ],
  "result": {
    "risk_score": 0,
    "verdict": "likely_safe",
    "confidence": 0.85,
    "summary": "All security indicators are clean. No threats were identified across analyzed vectors.",
    "recommendations": [
      "The analyzed URL exhibits established domain trust and valid security certificates."
    ],
    "ml": {
      "phishing_probability": 0.012,
      "model_version": "2026.11.02-random_forest",
      "top_features": []
    },
    "domain_info": {
      "domain": "example.com",
      "age_days": 3000,
      "registrar": "Example Registrar",
      "ssl": {
        "valid": true,
        "issuer": "DigiCert Inc",
        "expires_at": "2027-01-01T00:00:00Z",
        "days_remaining": 365
      }
    }
  },
  "error": null
}
      "data": {}
    },
    {
      "id": "google_safe_browsing",
      "status": "skipped",
      "severity": "info",
      "title": "Not configured",
      "detail": "Google Safe Browsing API key was not configured on this instance.",
      "evidence": [],
      "data": {}
    },
    {
      "id": "virustotal",
      "status": "skipped",
      "severity": "info",
      "title": "Not configured",
      "detail": "VirusTotal API key was not configured on this instance.",
      "evidence": [],
      "data": {}
    },
    {
      "id": "urlhaus",
      "status": "done",
      "severity": "info",
      "title": "Clean on URLhaus",
      "detail": "URL is not listed in abuse.ch URLhaus malware database",
      "evidence": ["No malicious listings found"],
      "data": {}
    }
  ],
  "recommendations": [
    "The analyzed URL exhibits established domain trust and valid security certificates."
  ]
}
```

---

### Error Responses

#### 422 Unprocessable Entity (`BLOCKED_TARGET`)
```json
{
  "error": {
    "code": "BLOCKED_TARGET",
    "message": "Host '127.0.0.1' resolved to blocked target IP: 127.0.0.1",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

#### 422 Unprocessable Entity (`UNSUPPORTED_SCHEME`)
```json
{
  "error": {
    "code": "UNSUPPORTED_SCHEME",
    "message": "Unsupported scheme 'ftp'. Only 'http' and 'https' are allowed.",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

#### 429 Too Many Requests (`RATE_LIMITED`)
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Rate limit exceeded. Please try again shortly.",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

---

## Production Deployment

### Docker Container Build & Run

The included `Dockerfile` uses a multi-stage Debian-slim build, installs no development tools into the runner image, drops root privileges to `appuser` (UID 10001), and includes a native Python `HEALTHCHECK`.

```bash
# Build production image
docker build -t safelinks-api:latest -f Dockerfile .

# Run container binding to port 8000
docker run -d \
  --name safelinks-backend \
  -p 8000:8000 \
  --env-file .env \
  safelinks-api:latest

# Check container health status
docker inspect --format='{{json .State.Health.Status}}' safelinks-backend
```

### Cloud Run / Render / Railway Deployment
SafeLinks dynamically reads `$PORT` (defaulting to 8000) and binds to `0.0.0.0`. It deploys without code modification on container platforms:
- **Google Cloud Run**:
  ```bash
  gcloud run deploy safelinks-api \
    --source . \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --set-env-vars ENVIRONMENT=prod,ALLOWED_ORIGINS="*"
  ```
- **Render / Railway**: Connect your Git repository, set the root directory to `BACKEND`, specify Docker as the runtime, and set the environment variables in the dashboard.

### Resource Sizing Recommendations
- **CPU**: 1 vCPU (minimum 0.5 vCPU).
- **Memory**: 512 MiB to 1 GiB RAM (scikit-learn model and in-memory caches require ~150 MiB baseline).

---

## Assumptions & Limitations

1. **In-Memory Storage**: By default, scans are retained in a thread-safe in-memory repository with an automatic TTL purge (`SCAN_TTL_MINUTES=60`) and LRU cap (`MAX_STORED_SCANS=5000`). Server restarts clear scan history. Production multi-instance deployments can implement a Redis or PostgreSQL scan repository with zero API changes.
2. **Single-Instance Rate Limiting**: The built-in SlowAPI rate limiter tracks client IPs in process memory. In horizontally scaled environments behind a load balancer, configure Redis storage for SlowAPI or enforce limits at the API Gateway / Cloudflare layer.
3. **External Free-Tier Quotas**: VirusTotal free API keys permit 4 requests/minute and 500 requests/day. SafeLinks includes an asynchronous sliding-window limiter and 1-hour cache to respect this quota without throwing unhandled exceptions.
4. **Lexical ML Bounds**: The ML classifier operates purely on lexical features for performance and safety. It does not render DOM or download file payloads.
5. **Non-Commercial Feed Terms**: VirusTotal Community and OpenPhish Free feeds have specific non-commercial or attribution terms. For commercial SaaS deployments, ensure enterprise licenses are procured.
