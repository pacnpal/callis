FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml ./

# Install dependencies
RUN uv sync --no-dev --no-install-project

# Copy application code
COPY . .

# Create data directory
RUN mkdir -p /data /audit

EXPOSE 8080 8081

CMD ["uv", "run", "python", "main.py"]
