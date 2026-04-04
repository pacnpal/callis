FROM python:3.12-slim

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency metadata first; uv.lock is optional but recommended for reproducible builds
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /data /audit

EXPOSE 8080 8081

CMD ["uv", "run", "python", "main.py"]
