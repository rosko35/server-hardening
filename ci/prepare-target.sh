#!/usr/bin/env bash
# Wait for the test container to boot, then give the operator account an SSH
# key (for Ansible) and a password (so the test can prove password login is
# refused after hardening and allowed again after rollback).
set -euo pipefail
cd "$(dirname "$0")/.."

: "${CI_PASSWORD:?CI_PASSWORD must be set}"

echo "Waiting for systemd in the container..."
state=unknown
for _ in $(seq 1 90); do
  state=$(docker exec target systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd state: $state"
docker exec target systemctl --failed --no-pager || true

mkdir -p ci/.ssh
[ -f ci/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -C ci-operator -f ci/.ssh/id_ed25519

docker exec target install -d -m 0700 -o ciadmin -g ciadmin /home/ciadmin/.ssh
docker cp ci/.ssh/id_ed25519.pub target:/home/ciadmin/.ssh/authorized_keys
docker exec target chown ciadmin:ciadmin /home/ciadmin/.ssh/authorized_keys
docker exec target chmod 0600 /home/ciadmin/.ssh/authorized_keys
printf 'ciadmin:%s\n' "$CI_PASSWORD" | docker exec -i target chpasswd

echo "Waiting for sshd..."
for _ in $(seq 1 30); do
  if ssh -i ci/.ssh/id_ed25519 -p 2222 -o BatchMode=yes -o ConnectTimeout=3 \
       -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ciadmin@127.0.0.1 true 2>/dev/null; then
    echo "SSH with key: OK"
    exit 0
  fi
  sleep 1
done
echo "::error::sshd in the container never accepted the key"
docker exec target journalctl -u ssh --no-pager -n 50 || true
exit 1
