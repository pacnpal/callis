FROM python:3.12-slim

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

# Install system dependencies: OpenSSH server, supervisor, curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server curl supervisor && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /etc/ssh/host_keys /var/run/sshd /var/log/callis

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.6.12 /uv /usr/local/bin/uv

# --- API setup ---
WORKDIR /app
COPY api/pyproject.toml api/uv.lock* ./
RUN uv sync --no-dev --no-install-project
COPY api/ .
RUN mkdir -p /data /audit /app/static

# --- SSHD setup ---
COPY sshd/sshd_config /etc/ssh/sshd_config
COPY sshd/auth-keys.sh /etc/ssh/auth-keys.sh
COPY sshd/callis-cmd.sh /etc/ssh/callis-cmd.sh
COPY sshd/banner.txt /etc/ssh/banner.txt
RUN chmod 0755 /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh && \
    chown root:root /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh /etc/ssh/sshd_config

# --- Version file ---
COPY .version /app/.version

# --- Supervisor config ---
COPY supervisord.conf /etc/supervisor/conf.d/callis.conf

# --- Entrypoint ---
COPY sshd/entrypoint.sh /entrypoint-sshd.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh /entrypoint-sshd.sh

EXPOSE 8080 22

ENTRYPOINT ["/entrypoint.sh"]
