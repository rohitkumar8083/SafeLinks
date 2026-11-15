# =============================================================================
# Stage 1: Build virtual environment with production dependencies
# =============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into an isolated virtual environment
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# =============================================================================
# Stage 2: Runtime image (minimal, non-root)
# =============================================================================
FROM python:3.12-slim AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PORT=8000

# Create non-root system user and group (uid 10001)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

WORKDIR /app

# Copy isolated virtual environment from builder
COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv

# Copy application source code (including pre-trained ML model if present)
COPY --chown=appuser:appgroup app /app/app

# Drop root privileges
USER appuser

# Expose default port (overridable via $PORT on Cloud Run / Render / Railway)
EXPOSE 8000

# Healthcheck hitting /api/v1/health using native python standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request, sys; \
port = os.environ.get('PORT', '8000'); \
url = f'http://127.0.0.1:{port}/api/v1/health'; \
sys.exit(0 if urllib.request.urlopen(url).getcode() == 200 else 1)"

# Start uvicorn server binding to 0.0.0.0 and dynamic $PORT
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
