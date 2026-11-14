#!/usr/bin/env bash
set -euo pipefail
# This root-owned, non-writable script executes as a dedicated yarp-vrrp user.
# The standby needs a reachable node-local data-plane address. Never probe
# the VIP only: it is absent on BACKUP. No production script is executed here.
data_ip="${DATA_PLANE_IP:-}"
: "${data_ip:?DATA_PLANE_IP required}"
[[ "$data_ip" =~ ^[0-9.]+$ ]] || { echo 'Invalid IPv4 data IP' >&2; exit 2; }
exec /usr/bin/curl --noproxy '*' --fail --silent --show-error --max-time 2 \\
  --output /dev/null "http://${data_ip}/gateway/health/ready"
