FROM alpine:3.20

RUN apk add --no-cache openssh curl && \
    mkdir -p /etc/ssh/host_keys /var/log /var/run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY auth-keys.sh /etc/ssh/auth-keys.sh
COPY banner.txt /etc/ssh/banner.txt
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0755 /etc/ssh/auth-keys.sh /entrypoint.sh && \
    chown root:root /etc/ssh/auth-keys.sh /etc/ssh/sshd_config

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
