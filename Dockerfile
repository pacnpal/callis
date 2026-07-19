# --- Stage 1: frontend build (Node exists ONLY here as a toolchain — the
# runtime stage receives compiled assets plus the bare `node` binary needed to
# run the SSR server). `npm ci` against the committed package-lock.json makes
# the build reproducible, mirroring `uv sync --frozen` for Python.
FROM node:22-bookworm-slim AS webbuild

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build && printf '{"type":"module"}\n' > build/package.json

# --- Stage 2: runtime ---
FROM python:3.12-slim

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

# Install system dependencies: OpenSSH server, supervisor, curl, openssl.
# libstdc++6 is required by the Node runtime binary copied below.
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server curl supervisor openssl libstdc++6 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /etc/ssh/host_keys /var/run/sshd /var/log/callis

# Node runtime binary for the compiled SvelteKit SSR server (no npm, no
# node_modules — the build output from stage 1 is fully self-contained).
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.11.29 /uv /usr/local/bin/uv

# --- API setup ---
WORKDIR /app
# Copy the lockfile alongside pyproject and install with --frozen so builds
# are reproducible: the image always gets exactly the locked versions.
COPY api/pyproject.toml api/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY api/ .
RUN mkdir -p /data /app/static

# --- Web (SSR) setup ---
COPY --from=webbuild /frontend/build /app/web

# --- SSHD setup ---
COPY sshd/sshd_config /etc/ssh/sshd_config
COPY sshd/auth-keys.sh /etc/ssh/auth-keys.sh
COPY sshd/callis-cmd.sh /etc/ssh/callis-cmd.sh
COPY sshd/banner.txt /etc/ssh/banner.txt
RUN chmod 0755 /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh && \
    chown root:root /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh /etc/ssh/sshd_config

# --- Supervisor config ---
COPY supervisord.conf /etc/supervisor/conf.d/callis.conf

# --- Entrypoint ---
COPY sshd/entrypoint.sh /entrypoint-sshd.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh /entrypoint-sshd.sh

EXPOSE 8080 22

ENTRYPOINT ["/entrypoint.sh"]
