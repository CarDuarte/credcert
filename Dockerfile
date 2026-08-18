# syntax=docker/dockerfile:1

# --- Stage 1: build dependencies in a throwaway layer with build tools ---
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --- Stage 2: minimal runtime image ---
FROM python:3.12-slim AS runtime

# Metadata for provenance / vulnerability-scanner context.
LABEL org.opencontainers.image.title="CredTrace" \
      org.opencontainers.image.description="Credential usage / blast-radius tracker (metadata only)" \
      org.opencontainers.image.source="https://github.com/your-org/credtrace"

# Least privilege: run as a dedicated, unprivileged, non-login user -- never root.
RUN groupadd --gid 10001 credtrace && \
    useradd --uid 10001 --gid credtrace --shell /usr/sbin/nologin --no-create-home credtrace

WORKDIR /app

# Only the installed packages come from the builder stage -- no compilers,
# headers, or package-manager caches end up in the final image.
COPY --from=builder /root/.local /home/credtrace/.local
ENV PATH="/home/credtrace/.local/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

COPY app/ ./app/
COPY scripts/ ./scripts/

# App writes SQLite data (dev/demo only) under /app/data; owned by the
# unprivileged user so the process never needs root to run.
RUN mkdir -p /app/data && chown -R credtrace:credtrace /app

USER credtrace

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else sys.exit(1)"

# No shell form, no CMD-as-string: avoids an accidental shell-injection
# surface and ensures signals (SIGTERM on `docker stop`) reach uvicorn
# directly for a clean shutdown.
#
# --forwarded-allow-ips=* trusts X-Forwarded-* headers from any peer, which
# is only safe because this container is expected to sit behind a TLS-
# terminating reverse proxy that is the sole thing able to reach it. If you
# expose this container directly to untrusted networks, replace "*" with
# the proxy's actual IP/CIDR.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
