#!/usr/bin/env bash
# Executed by unprivileged dedicated gateway-vrrp; own script root:root 0755.
set -euo pipefail
ready_url="$(cat /etc/gatewaycore-yarp/ready-url)"
[[ "$ready_url" =~ ^https?://([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}/gateway/health/ready$ ]] || {
  echo 'Invalid literal data-plane readiness URL' >&2; exit 2;
}
exec /usr/bin/curl --silent --show-error --fail --max-time 2 --output /dev/null "$ready_url"
