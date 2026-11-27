#!/usr/bin/env bash
# Offline, plan-only by default. Execute locally under site change control.
set -euo pipefail
usage(){ echo 'Usage: install-vip-service.sh agent|provider|controller executable config user [scope policy provider journal] [--apply]' >&2; exit 2; }
[[ $# -ge 4 ]] || usage
role=$1; binary=$2; config=$3; account=$4; shift 4
apply=false
if [[ $# -gt 0 && "${@: -1}" == --apply ]]; then apply=true; set -- "${@:1:$(($#-1))}"; fi
safe_path(){ [[ "$1" =~ ^/[A-Za-z0-9_./-]+$ && "$1" != *'/../'* && "$1" != */.. && "$1" != *'/./'* ]] || { echo 'Absolute simple local paths required' >&2; exit 2; }; }
safe_path "$binary"; safe_path "$config"
[[ -f "$binary" && -x "$binary" && ! -L "$binary" && -f "$config" && ! -L "$config" ]] || { echo 'Existing executable and config required' >&2; exit 2; }
[[ "$account" =~ ^[a-z_][a-z0-9_-]*$ ]] || usage
case "$role" in
 agent) [[ $# == 0 && "$account" == root ]] || usage; name=gatewaycore-vip-node-agent; args="--vip-node-agent $config"; boot=true;;
 provider) [[ $# == 0 && "$account" != root ]] || usage; name=gatewaycore-vip-fence-provider; args="--vip-redfish-provider $config"; boot=false;;
 controller) [[ $# == 4 && "$account" != root && "$1" =~ ^[A-F0-9]{64}$ ]] || usage
  scope=$1; policy=$2; provider=$3; journal=$4
  for path in "$policy" "$provider" "$journal"; do safe_path "$path"; done
  [[ -f "$policy" && ! -L "$policy" && -f "$provider" && ! -L "$provider" && -d "$(dirname "$journal")" && ! -L "$journal" ]] || usage
  name=gatewaycore-vip-controller; args="--vip-owner $config $scope automatic-policy $policy $provider $journal"; boot=false;;
 *) usage;;
esac
unit=$(cat <<EOF
[Unit]
Description=GatewayCore independent VIP $role
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=$account
ExecStart=$binary $args
Restart=no
TimeoutStopSec=150
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
)
printf '%s\n' "$unit"
if ! "$apply"; then echo 'PLAN ONLY: no files or services changed'; exit 0; fi
[[ $(id -u) == 0 ]] || { echo 'Elevated local installation required' >&2; exit 1; }
id "$account" >/dev/null
target="/etc/systemd/system/$name.service"
[[ ! -e "$target" && ! -L "$target" ]] || { echo 'Existing service; refuse overwrite' >&2; exit 1; }
if systemctl cat "$name.service" >/dev/null 2>&1; then echo 'Existing unit; refuse overwrite' >&2; exit 1; fi
if [[ "$role" == agent ]]; then
  # Require independently configured gateway service to be stopped and disabled.
  gateway=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); p=s["supervisorConfig"]; print(json.load(open(p))["serviceName"])' "$config")
  [[ "$gateway" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*\.service$ ]] || usage
  [[ $(systemctl show -p LoadState --value "$gateway") == loaded && $(systemctl show -p ActiveState --value "$gateway") == inactive && $(systemctl is-enabled "$gateway" 2>/dev/null || true) == disabled ]] || { echo 'Dedicated gateway must be installed, stopped and disabled' >&2; exit 1; }
fi
(umask 022; set -o noclobber; printf '%s\n' "$unit" > "$target")
systemctl daemon-reload
if "$boot"; then systemctl enable "$name.service"; fi
echo 'Installed; not started. Verify protected credentials and approved topology before starting.'
