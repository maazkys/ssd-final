# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Builder
# Purpose: Install dependencies in an isolated stage (no build tools in prod)
# CIS Docker Benchmark: 4.1, 4.2
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copy only requirements first (layer cache optimization)
COPY src/requirements.txt .

# Install to a local directory (not system) — isolates from prod image
RUN pip install --prefix=/install -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Production image
# CIS Docker Benchmark: 4.1 (non-root), 4.6 (HEALTHCHECK), 4.9 (read-only FS)
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS production

# Metadata labels (traceability)
LABEL org.opencontainers.image.title="secureapp-mvp"
LABEL org.opencontainers.image.description="CYC386 Secure Application"
LABEL org.opencontainers.image.version="1.0.0"
LABEL security.cis-benchmark="applied"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# ── Security hardening ───────────────────────────────────────────────────────
# CIS 4.1: Create non-root user — never run as root
RUN groupadd -r -g 1001 appgroup && \
    useradd -r -u 1001 -g appgroup -s /sbin/nologin -M appuser

# Remove unnecessary packages (reduce attack surface)
RUN apt-get update && \
    apt-get remove --purge -y \
        wget curl netcat-traditional telnet gcc make && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source
COPY src/ .

# Set restrictive file permissions
RUN chown -R appuser:appgroup /app && \
    chmod -R 550 /app

# Create writable dir for logs only (rest of FS is read-only)
RUN mkdir -p /app/logs && chown appuser:appgroup /app/logs

# ── Drop to non-root user ────────────────────────────────────────────────────
USER appuser

EXPOSE 8000

# CIS 4.6: HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1

# CIS 4.5: Use ENTRYPOINT not shell form (prevents shell injection)
ENTRYPOINT ["uvicorn", "main:app"]
CMD ["--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers"]
