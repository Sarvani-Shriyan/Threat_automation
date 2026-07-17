# ── Stage 0: pull the uv binary from the official image ────────────────────
FROM ghcr.io/astral-sh/uv:latest AS uv-bin

# ── Stage 1: production image ───────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Inject uv and uvx into the system PATH
COPY --from=uv-bin /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Pre-compile .pyc files during install so first-run import is instant
    UV_COMPILE_BYTECODE=1 \
    # Use copy link mode — avoids hard-link issues across filesystem boundaries
    UV_LINK_MODE=copy \
    # Install directly into the container's system Python (no venv needed)
    UV_SYSTEM_PYTHON=1

# ── Dependency layer (only rebuilds when pyproject.toml / uv.lock change) ──
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ── Application layer ───────────────────────────────────────────────────────
COPY . .

# Shared data volume mount point — populated at runtime via compose
RUN mkdir -p /app/data
