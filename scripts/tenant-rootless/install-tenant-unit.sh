#!/usr/bin/env bash
# Render and install the systemd --user unit for a tenant rootless daemon.
# Runs as the tenant operator user (systemd --user), not as root.
set -euo pipefail

usage() {
  echo "usage: $0 <tenant> <data-root> <exec-root> <socket> [unit-dir]" >&2
  exit 2
}

[ $# -ge 4 ] || usage
TENANT="$1"
DATA_ROOT="$2"
EXEC_ROOT="$3"
SOCKET="$4"
UNIT_DIR="${5:-${HOME}/.config/systemd/user}"

PROFILE="spanel-tenant-${TENANT}"
UNIT="${UNIT_DIR}/spanel-tenant-${TENANT}.service"
mkdir -p "${UNIT_DIR}"

cat > "${UNIT}" <<EOF
[Unit]
Description=Rootless Docker daemon for tenant ${TENANT}
After=network.target

[Service]
Type=simple
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=0
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP=false
Environment=XDG_RUNTIME_DIR=/run/user/%U
Environment=DOCKER_HOST=unix:${SOCKET}
ExecStartPre=/usr/bin/mkdir -p $(dirname "${SOCKET}") ${DATA_ROOT} ${EXEC_ROOT}
ExecStart=/usr/bin/aa-exec -p ${PROFILE} -- /usr/bin/dockerd-rootless.sh \\
  --iptables=false --ip6tables=false \\
  --data-root=${DATA_ROOT} \\
  --exec-root=${EXEC_ROOT} \\
  --host=unix://${SOCKET}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
echo "installed ${UNIT}"
