#!/usr/bin/env bash
# Start one tenant's rootless Docker daemon confined by its AppArmor profile.
# Evidence: spike on spanel.lab, 2026-11-17 (A.SPEC 0096).
#
# Usage:
#   dockerd-rootless-tenant.sh <tenant> <data-root> <exec-root> <socket>
#
# This is a TEMPLATE/OPERATOR script.  Running it on the host (creating users,
# loading AppArmor, delegating cgroups) is out of reach of this task; the exact
# invocation is reported as a GAP by the Generator.
set -euo pipefail

usage() {
  echo "usage: $0 <tenant> <data-root> <exec-root> <socket>" >&2
  exit 2
}

[ $# -eq 4 ] || usage
TENANT="$1"
DATA_ROOT="$2"
EXEC_ROOT="$3"
SOCKET="$4"

PROFILE="spanel-tenant-${TENANT}"
if ! [[ "${TENANT}" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]]; then
  echo "invalid tenant id: ${TENANT}" >&2
  exit 2
fi

for binary in aa-exec dockerd-rootless.sh rootlesskit; do
  if ! command -v "${binary}" >/dev/null 2>&1; then
    echo "missing prerequisite: ${binary}" >&2
    exit 3
  fi
done

# The daemon cannot read /sys/kernel/security/apparmor/profiles, so the flag
# --security-opt apparmor= is ignored.  Confinement is applied by launching the
# daemon itself under aa-exec; every container inherits the label (I5).
if ! aa-exec -p "${PROFILE}" -- true 2>/dev/null; then
  echo "AppArmor profile is not loaded: ${PROFILE}" >&2
  exit 4
fi

# Spike findings (do NOT change without re-spiking):
#  - DETACH_NETNS=1  -> netlink: operation not permitted on bridge creation
#  - --bridge=none   -> Compose cannot create its project network
#  - slirp sandbox/seccomp=false are required for the unprivileged netns
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DOCKERD_ROOTLESS_ROOTLESSKIT_DETACH_NETNS=0
export DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SANDBOX=false
export DOCKERD_ROOTLESS_ROOTLESSKIT_SLIRP4NETNS_SECCOMP=false

mkdir -p "$(dirname "${SOCKET}")" "${DATA_ROOT}" "${EXEC_ROOT}"

exec aa-exec -p "${PROFILE}" -- dockerd-rootless.sh \
  --iptables=false \
  --ip6tables=false \
  --data-root="${DATA_ROOT}" \
  --exec-root="${EXEC_ROOT}" \
  --host="unix://${SOCKET}"
