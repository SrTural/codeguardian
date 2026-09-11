# ============================================================
# CodeGuardian - Production Dockerfile
# ============================================================

FROM python:3.12-slim

LABEL maintainer="Tural Dadashov"
LABEL description="Local-first, AI-powered code security scanner"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --no-cache-dir --upgrade pip

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# VERIFY uvicorn is installed (debug)
RUN python -c "import uvicorn; print('uvicorn version:', uvicorn.__version__)"

# Copy application
COPY app/ ./app/

# Non-root user
RUN groupadd -g 1000 codeguardian \
    && useradd -m -u 1000 -g codeguardian codeguardian \
    && chown -R codeguardian:codeguardian /app

USER codeguardian

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]