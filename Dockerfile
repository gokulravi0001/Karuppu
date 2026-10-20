# Multi-stage security-hardened Dockerfile for Discord Security Bot
FROM python:3.11-slim as builder

WORKDIR /install

# Install build dependencies if needed for compiled packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Final production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies for health checking
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed wheels from builder
COPY --from=builder /install /usr/local

# Create non-root user and persistent data directory
RUN groupadd -r botgroup && useradd -r -g botgroup -u 10001 botuser \
    && mkdir -p /app/data /app/logs \
    && chown -R botuser:botgroup /app

# Copy application code
COPY src/ /app/src/
COPY config.yaml /app/config.yaml

# Set permissions and switch to non-root user
RUN chown -R botuser:botgroup /app
USER botuser

# Environment settings
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8080/health || exit 1

CMD ["python", "-m", "src.bot"]
