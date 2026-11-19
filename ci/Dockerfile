# Disposable systemd-enabled test target that looks like a small web + mail VPS:
#   - openssh-server (ssh.service, key + password login possible)
#   - nginx on :80                     (the "website")
#   - a stand-in service on :587       (the "mail submission port")
#   - ciadmin: non-root sudo user (the operator), nokey: user without an SSH key
#   - svcdemo: a system account that still has a login shell
ARG BASE=ubuntu:24.04
FROM ${BASE}

ENV DEBIAN_FRONTEND=noninteractive \
    container=docker

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus openssh-server sudo python3 python3-apt \
      iproute2 nginx ca-certificates cron procps curl \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY fake-submission.service /etc/systemd/system/fake-submission.service

# Classic ssh.service (not socket activation) so the reload path is exercised,
# and drop units that make no sense in a container.
RUN systemctl disable ssh.socket 2>/dev/null || true \
 && systemctl enable ssh.service nginx.service fake-submission.service cron.service \
 && systemctl mask getty.target systemd-logind.service systemd-remount-fs.service 2>/dev/null || true

RUN useradd -m -s /bin/bash ciadmin \
 && printf 'ciadmin ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ciadmin \
 && chmod 0440 /etc/sudoers.d/ciadmin \
 && useradd -m -s /bin/bash nokey \
 && useradd -r -s /bin/bash -d /var/lib/svcdemo svcdemo

# Make the starting point resemble a fresh VPS (loose cron permissions).
RUN chmod 0644 /etc/crontab

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
