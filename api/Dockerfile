FROM python:3.12-slim

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}
# Standalone image: no SSR frontend in front of the API, so bind all
# interfaces (the unified image keeps the loopback default instead).
ENV API_HOST=0.0.0.0

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency metadata first (lockfile included for reproducible builds)
COPY pyproject.toml uv.lock ./

# Install dependencies exactly as locked
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /data

# JSON API (bind 0.0.0.0 via API_HOST when running the API standalone) and
# the internal sshd-facing API.
EXPOSE 8000 8081

# Run the already-built venv directly — `uv run` would re-sync the environment
# at startup (including the dev group), requiring network egress at runtime.
CMD ["/app/.venv/bin/python", "main.py"]
