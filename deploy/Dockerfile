# FireWatch application image — uv-based multi-stage build.
#
# Stage 1 (builder): installs the full uv workspace (all packages + source
#   plugins) into /app/.venv so the runtime stage gets a complete, runnable
#   virtual-env without build tools.
# Stage 2 (runtime): copies only /app/.venv + source tree; runs
#   `firewatch run --host 127.0.0.1 --port 8000` on loopback so the
#   ADR-0026 bind guard passes with NO API key set.
#
# Security notes:
# - API binds loopback only; the nginx sidecar (network_mode: service:firewatch)
#   is the sole host-exposed surface (ADR-0026 Decision 1).
# - No secrets baked in; all config via env vars / mounted volumes.
# - Runs as non-root (UID 1001) inside the container.

# --------------------------------------------------------------------------
# Stage 1: builder
# --------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv (pinned digest tag; bump to update).
COPY --from=ghcr.io/astral-sh/uv:0.5 /uv /usr/local/bin/uv

# Copy workspace manifests first so layer cache survives source-only edits.
COPY pyproject.toml uv.lock ./
COPY packages/ ./packages/

# Sync the full workspace into a local .venv (no build isolation for speed).
# UV_COMPILE_BYTECODE compiles .pyc at build time — faster cold starts.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Install all workspace packages (firewatch-cli, firewatch-core, firewatch-api,
# firewatch-sdk, and all source plugins).  --all-packages installs every member
# of the uv workspace, so source plugins register their entry points and are
# discoverable by `firewatch_core.loader.load_source_plugins()` at runtime.
# --no-dev excludes test/lint tooling not needed in the image.
RUN uv sync --frozen --no-dev --all-packages

# --------------------------------------------------------------------------
# Stage 2: runtime
# --------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

# curl is needed for the Docker healthcheck probe (see docker-compose.yml).
# systemd provides the journalctl binary the SDK's JournaldReader shells out
# to (firewatch_sdk.localhost.journald — issue #5): reading the HOST's
# journal from inside this container (deploy/docker-compose.host-logs.yml)
# requires journalctl to exist in the image; the journal DATA itself is never
# baked in — it is bind-mounted read-only at runtime (see that compose
# override and deploy/README.md). --no-install-recommends keeps this to the
# systemd package itself, skipping dbus/cryptsetup/etc. Measured image-size
# delta: see deploy/README.md ("journald image size").
# Installed before dropping to non-root so apt has permissions.
RUN apt-get update && apt-get install -y --no-install-recommends curl systemd \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (minimal privilege — ADR-0026).
RUN adduser --disabled-password --uid 1001 firewatch

# Copy the complete virtual-env and source tree from the builder.
COPY --from=builder --chown=firewatch:firewatch /app/.venv /app/.venv
COPY --from=builder --chown=firewatch:firewatch /app/packages /app/packages
COPY --chown=firewatch:firewatch pyproject.toml uv.lock ./

# Give the firewatch user write access to the working directory so it can
# create the SQLite event store (firewatch_events.db) and the MMDB geo-data
# directory.  The data/ subdirectory is mounted as a named volume in compose;
# we also own it here so the volume mount inherits the correct ownership.
RUN chown firewatch:firewatch /app && mkdir -p /app/data && chown firewatch:firewatch /app/data

# Put the venv bin directory first so `firewatch` resolves correctly.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=0

USER firewatch

# Data directory for the SQLite event store (mounted as a named volume in
# docker-compose.yml so data survives container restarts).
VOLUME ["/app/data"]

# Port 8000 is bound on loopback only; the nginx sidecar (running in the
# same network namespace via network_mode: service:firewatch) reaches it at
# 127.0.0.1:8000 and is the only externally-reachable port.
EXPOSE 8000

# --host 127.0.0.1 satisfies the ADR-0026 bind guard without an API key.
# --config /app/data/firewatch_config.json puts the SQLite DB and MMDB geo-
# data files inside the named volume so they survive container restarts.
ENTRYPOINT ["firewatch", "run", "--host", "127.0.0.1", "--port", "8000", "--config", "/app/data/firewatch_config.json"]
