FROM alpine:3.24

RUN apk add --no-cache openssh curl openssl && \
    mkdir -p /etc/ssh/host_keys /var/log /var/run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY auth-keys.sh /etc/ssh/auth-keys.sh
COPY callis-cmd.sh /etc/ssh/callis-cmd.sh
COPY ensure-user.sh /etc/ssh/ensure-user.sh
COPY user-sync.sh /etc/ssh/user-sync.sh
COPY banner.txt /etc/ssh/banner.txt
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0755 /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh /etc/ssh/ensure-user.sh /etc/ssh/user-sync.sh /entrypoint.sh && \
    chown root:root /etc/ssh/auth-keys.sh /etc/ssh/callis-cmd.sh /etc/ssh/ensure-user.sh /etc/ssh/user-sync.sh /etc/ssh/sshd_config

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
