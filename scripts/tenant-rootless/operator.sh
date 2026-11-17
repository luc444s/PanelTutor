#!/usr/bin/env bash
# Host operator script for the tenant-rootless runtime (A.SPEC 0096).
#
# HOST-LEVEL ACTIONS -- out of reach of the Generator task.  This script is a
# deliverable template; its execution on spanel.lab (user creation, AppArmor
# load, nftables, cgroup delegation, runsc registration) is reported as a GAP
# with the exact commands.  It must be reviewed and approved (risk: high)
# before being run as root.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<EOF
usage: $0 <setup|teardown> <tenant> [proxy-ip] [published-ports]

Examples:
  $0 setup   acme 192.168.18.11 18085,18086
  $0 teardown acme
EOF
  exit 2
}

[ $# -ge 2 ] || usage
ACTION="$1"
TENANT="$2"
PROXY_IP="${3:-192.168.18.11}"
PUBLISHED_PORTS="${4:-18085}"

if ! [[ "${TENANT}" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; then
  echo "invalid tenant id: ${TENANT}" >&2
  exit 2
fi

PROFILE="spanel-tenant-${TENANT}"
USER="spanel-t-${TENANT}"
DATA_ROOT="/var/lib/spanel/tenants/${TENANT}/docker"
EXEC_ROOT="/run/spanel/tenants/${TENANT}/docker"
SOCKET="/run/spanel/tenants/${TENANT}/docker.sock"
APPARMOR_FILE="${HERE}/apparmor/spanel-tenant.in"
NFT_FILE="${HERE}/nftables/tenant.nft.in"

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 3; }
}

render_apparmor() {
  local out="$1"
  sed -e "s/@TENANT@/${TENANT}/g" \
      -e "s|@DATA_ROOT@|${DATA_ROOT}|g" \
      -e "s|@EXEC_ROOT@|${EXEC_ROOT}|g" \
      -e "s|@SOCKET@|${SOCKET}|g" \
      "${APPARMOR_FILE}" > "${out}"
}

render_nft() {
  local out="$1"
  sed -e "s/@TENANT@/${TENANT}/g" \
      -e "s/@PROXY_IP@/${PROXY_IP}/g" \
      -e "s/@PUBLISHED_PORTS@/${PUBLISHED_PORTS}/g" \
      -e "s/@TENANT_IP@/10.99.0.0\/24/g" \
      "${NFT_FILE}" > "${out}"
}

setup() {
  require_root
  echo "==> creating system user and disjoint subuid/subgid range"
  useradd --system --home-dir "/var/lib/spanel/tenants/${TENANT}" --shell /usr/sbin/nologin "${USER}"
  # Ranges MUST be disjoint across tenants; assign from your allocator.
  usermod --add-subuids 200000-265535 --add-subgids 200000-265535 "${USER}"

  echo "==> cgroup v2 delegation to user.slice"
  mkdir -p "/etc/systemd/system/user@${USER}.service.d"
  cat > "/etc/systemd/system/user@${USER}.service.d/delegate.conf" <<EOF
[Service]
Delegate=cpu cpuset io memory pids
EOF

  echo "==> loading AppArmor profile"
  render_apparmor "/etc/apparmor.d/${PROFILE}"
  apparmor_parser -r -W "/etc/apparmor.d/${PROFILE}"

  echo "==> applying nftables"
  render_nft "/etc/nftables.d/${TENANT}.nft"
  nft -f "/etc/nftables.d/${TENANT}.nft"

  echo "==> installing and starting the systemd --user unit"
  mkdir -p "${SOCKET%/*}" "${DATA_ROOT}" "${EXEC_ROOT}"
  chown "spanel:${TENANT}" "${SOCKET%/*}"
  install -d -o "${USER}" -g "${USER}" "${DATA_ROOT}" "${EXEC_ROOT}"
  # Run as the tenant operator user via: machinectl shell ${USER}@ ...
  "${HERE}/install-tenant-unit.sh" "${TENANT}" "${DATA_ROOT}" "${EXEC_ROOT}" "${SOCKET}"
  systemctl --user --machine="${USER}@" enable --now "spanel-tenant-${TENANT}.service"

  echo "==> socket health"
  docker -H "unix:${SOCKET}" info --format '{{.SecurityOptions}}'
}

teardown() {
  require_root
  echo "==> stopping daemon"
  systemctl --user --machine="${USER}@" stop "spanel-tenant-${TENANT}.service" || true
  echo "==> removing AppArmor profile"
  apparmor_parser -R "/etc/apparmor.d/${PROFILE}" || true
  echo "==> removing nftables rules"
  nft delete table "inet spanel_tenant_${TENANT}" || true
  rm -f "/etc/apparmor.d/${PROFILE}" "/etc/nftables.d/${TENANT}.nft"
  echo "==> data-root preserved; user preserved (manual userdel after review)"
}

case "${ACTION}" in
  setup) setup ;;
  teardown) teardown ;;
  *) usage ;;
esac
