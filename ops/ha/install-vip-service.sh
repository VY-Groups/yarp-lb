#!/usr/bin/env bash
# Offline, plan-only by default. Execute locally under site change control.
set -euo pipefail
usage(){ echo 'Usage: install-vip-service.sh agent|provider|controller executable config user [scope policy provider journal [approved-policy-sha256]] [--apply]' >&2; exit 2; }
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
 controller) [[ ( $# == 4 || $# == 5 ) && "$account" != root && "$1" =~ ^[A-F0-9]{64}$ ]] || usage
  scope=$1; policy=$2; provider=$3; journal=$4
  for path in "$policy" "$provider" "$journal"; do safe_path "$path"; done
  [[ -f "$policy" && ! -L "$policy" && -f "$provider" && ! -L "$provider" && -d "$(dirname "$journal")" && ! -L "$journal" ]] || usage
  name=gatewaycore-vip-controller; args="--vip-owner $config $scope automatic-policy $policy $provider $journal"
  if [[ $# == 5 ]]; then
    [[ "$5" =~ ^[A-Fa-f0-9]{64}$ ]] || usage
    args+=" $5"
  fi
  boot=false;;
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
# Independent writer and provider must not share an effective OS identity.
# Check UID rather than account spelling, including UID-zero aliases.
if [[ "$role" != agent ]]; then
  uid=$(id -u "$account")
  [[ "$uid" =~ ^[0-9]+$ && "$uid" != 0 ]] || { echo 'Independent VIP role requires a non-root UID' >&2; exit 1; }
  peer=gatewaycore-vip-controller.service
  if [[ "$role" == controller ]]; then peer=gatewaycore-vip-fence-provider.service; fi
  peer_load=$(systemctl show -p LoadState --value "$peer") || { echo 'Cannot inspect independent peer registration' >&2; exit 1; }
  case "$peer_load" in
    not-found) ;;
    loaded)
      peer_user=$(systemctl show -p User --value "$peer")
      [[ -n "$peer_user" ]] || { echo 'Independent peer identity missing' >&2; exit 1; }
      peer_uid=$(id -u "$peer_user") || { echo 'Independent peer identity unresolved' >&2; exit 1; }
      [[ "$peer_uid" =~ ^[0-9]+$ && "$peer_uid" != 0 && "$peer_uid" != "$uid" ]] || { echo 'Independent VIP roles require distinct non-root UIDs' >&2; exit 1; }
      ;;
    *) echo 'Unexpected independent peer registration state' >&2; exit 1;;
  esac
fi
if [[ "$role" == agent ]]; then
  # Require independently configured gateway service to be stopped and disabled.
  gateway=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); p=s["supervisorConfig"]; print(json.load(open(p))["serviceName"])' "$config")
  [[ "$gateway" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*\.service$ ]] || usage
  [[ $(systemctl show -p LoadState --value "$gateway") == loaded && $(systemctl show -p ActiveState --value "$gateway") == inactive && $(systemctl is-enabled "$gateway" 2>/dev/null || true) == disabled ]] || { echo 'Dedicated gateway must be installed, stopped and disabled' >&2; exit 1; }
fi
(umask 022; set -o noclobber; printf '%s\n' "$unit" > "$target")
# Capture exact registration identity. A changed/replaced file, unit alias or
# drop-in is not ours to remove or certify as the intended service.
created_identity=$(stat -c '%d:%i' -- "$target")
registration_matches(){
  [[ -f "$target" && ! -L "$target" ]] &&
  [[ $(stat -c '%d:%i' -- "$target") == "$created_identity" ]] &&
  cmp -s -- "$target" <(printf '%s\n' "$unit")
}

# Own only the newly created unit. An unsuccessful reload/enable must not
# leave a privileged agent silently registered for the next boot.
rollback_registration(){
  local rc=$?
  trap - EXIT
  if ((rc == 0)); then return; fi
  set +e
  local cleanup_failed=0
  if ! registration_matches; then
    echo 'Unexpected changed unit; independent reconciliation required; registration preserved' >&2
    exit "$rc"
  fi
  # A failed/unknown systemctl read is not proof the service is stopped.
  local active_state
  active_state=$(systemctl show -p ActiveState --value "$name.service" 2>/dev/null) || active_state=
  if [[ "$active_state" != inactive && "$active_state" != failed ]]; then
    echo 'Unexpected or unknown unit state; independent reconciliation required' >&2
    exit "$rc"
  fi
  if ! registration_matches; then
    echo 'Unexpected changed unit; independent reconciliation required; registration preserved' >&2
    exit "$rc"
  fi
  if "$boot"; then systemctl disable "$name.service" >/dev/null 2>&1 || cleanup_failed=1; fi
  if registration_matches; then
    rm -f -- "$target" || cleanup_failed=1
  else
    echo 'Unexpected changed unit; independent reconciliation required; registration preserved' >&2
    exit "$rc"
  fi
  systemctl daemon-reload || cleanup_failed=1
  if ((cleanup_failed)); then
    echo 'Registration rollback unconfirmed; inspect the exact unit and enablement before retrying' >&2
  else
    echo 'Registration failed; newly created unit rolled back' >&2
  fi
  exit "$rc"
}
trap rollback_registration EXIT
systemctl daemon-reload
if "$boot"; then systemctl enable "$name.service"; fi
expected_state=disabled
if "$boot"; then expected_state=enabled; fi
if ! registration_matches || ! [[ $(systemctl show -p FragmentPath --value "$name.service") == "$target" &&
   -z $(systemctl show -p DropInPaths --value "$name.service") &&
   $(systemctl show -p LoadState --value "$name.service") == loaded &&
   $(systemctl show -p ActiveState --value "$name.service") == inactive &&
   $(systemctl show -p User --value "$name.service") == "$account" &&
   $(systemctl is-enabled "$name.service" 2>/dev/null || true) == "$expected_state" ]]; then
  echo 'Installed service state not confirmed' >&2; exit 1
fi
trap - EXIT
echo 'Installed; not started. Verify protected credentials and approved topology before starting.'
