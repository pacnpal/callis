FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /data /audit

EXPOSE 8080 8081

CMD ["uv", "run", "python", "main.py"]
