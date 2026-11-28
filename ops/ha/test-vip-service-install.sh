#!/usr/bin/env bash
# Disposable hosted-runner acceptance: register real systemd units without starting them.
set -euo pipefail
[[ $(id -u) == 0 && "$GITHUB_ACTIONS" == true && "$RUNNER_ENVIRONMENT" == github-hosted ]] || exit 2
here=$(cd "$(dirname "$0")" && pwd)
names=(gatewaycore-vip-ci-gateway gatewaycore-vip-node-agent gatewaycore-vip-fence-provider gatewaycore-vip-controller)
for name in "${names[@]}"; do
  target="/etc/systemd/system/$name.service"
  [[ ! -e "$target" && ! -L "$target" ]] || { echo "Pre-existing unit: $name" >&2; exit 1; }
  if systemctl cat "$name.service" >/dev/null 2>&1; then echo "Pre-existing unit: $name" >&2; exit 1; fi
done
d=$(mktemp -d)
cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  for name in "${names[@]}"; do
    if systemctl is-active --quiet "$name.service"; then
      echo "Unexpected running fixture: $name" >&2; rc=1; systemctl stop "$name.service" || rc=1
    fi
    if [[ -f "/etc/systemd/system/$name.service" ]]; then
      systemctl disable "$name.service" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$name.service" || rc=1
    fi
  done
  systemctl daemon-reload || rc=1
  rm -rf "$d" || rc=1
  exit "$rc"
}
trap cleanup EXIT
chmod 700 "$d"
printf '{"serviceName":"gatewaycore-vip-ci-gateway.service"}\n' > "$d/supervisor.json"
printf '{"supervisorConfig":"%s/supervisor.json"}\n' "$d" > "$d/config.json"
printf '{}\n' > "$d/policy.json"
printf '{}\n' > "$d/provider.json"
printf '[Unit]\nDescription=Disposable stopped gateway fixture\n[Service]\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/gatewaycore-vip-ci-gateway.service
systemctl daemon-reload
# Inject a failure AFTER real systemd enablement. The shipping installer must
# return failure, remove only its newly registered unit and undo enablement.
systemctl(){
  if [[ "${1:-}" == enable && "${2:-}" == gatewaycore-vip-node-agent.service ]]; then
    command systemctl "$@" || return
    return 97
  fi
  command systemctl "$@"
}
export -f systemctl
if output=$(bash "$here/install-vip-service.sh" agent /usr/bin/true "$d/config.json" root --apply 2>&1); then
  echo 'Failed enablement reported success' >&2; exit 1
fi
unset -f systemctl
grep -q 'Registration failed; newly created unit rolled back' <<<"$output"
[[ ! -e /etc/systemd/system/gatewaycore-vip-node-agent.service ]]
[[ ! -L /etc/systemd/system/multi-user.target.wants/gatewaycore-vip-node-agent.service ]]
! systemctl cat gatewaycore-vip-node-agent.service >/dev/null 2>&1
[[ $(systemctl show -p LoadState --value gatewaycore-vip-ci-gateway.service) == loaded ]]
echo 'PASS: failed real systemd enablement rolled back without modifying the gateway fixture'

# If another administrator replaces the registration while enablement fails,
# the installer must preserve the changed unit and report manual reconciliation.
systemctl(){
  if [[ "${1:-}" == enable && "${2:-}" == gatewaycore-vip-node-agent.service ]]; then
    command systemctl "$@" || return
    printf '\n# independently changed fixture\n' >> /etc/systemd/system/gatewaycore-vip-node-agent.service
    return 97
  fi
  command systemctl "$@"
}
export -f systemctl
if output=$(bash "$here/install-vip-service.sh" agent /usr/bin/true "$d/config.json" root --apply 2>&1); then
  echo 'Changed registration reported success' >&2; exit 1
fi
unset -f systemctl
grep -q 'registration preserved' <<<"$output"
grep -Fx '# independently changed fixture' /etc/systemd/system/gatewaycore-vip-node-agent.service
# Only the disposable fixture owns this synthetic change.
systemctl disable gatewaycore-vip-node-agent.service
rm /etc/systemd/system/gatewaycore-vip-node-agent.service
systemctl daemon-reload
echo 'PASS: changed stopped registration preserved and manual reconciliation required'

for role in agent provider controller; do
  case "$role" in
    agent) name=gatewaycore-vip-node-agent; account=root; enabled=enabled; args=();;
    provider) name=gatewaycore-vip-fence-provider; account=nobody; enabled=disabled; args=();;
    controller) name=gatewaycore-vip-controller; account=daemon; enabled=disabled
      scope=$(printf '%064d' 0 | tr 0 A)
      args=("$scope" "$d/policy.json" "$d/provider.json" "$d/journal.json");;
  esac
  bash "$here/install-vip-service.sh" "$role" /usr/bin/true "$d/config.json" "$account" "${args[@]}" | grep -q 'PLAN ONLY'
  [[ ! -e "/etc/systemd/system/$name.service" ]]
  if [[ "$role" == controller ]]; then
    if output=$(bash "$here/install-vip-service.sh" controller /usr/bin/true "$d/config.json" nobody "${args[@]}" --apply 2>&1); then
      echo 'Shared provider/controller UID admitted' >&2; exit 1
    fi
    grep -q 'distinct non-root UIDs' <<<"$output"
    [[ ! -e "/etc/systemd/system/$name.service" ]]
    [[ $(systemctl show -p User --value gatewaycore-vip-fence-provider.service) == nobody ]]
    echo 'PASS: shared authority UID refused without changing provider or registering controller'
  fi
  bash "$here/install-vip-service.sh" "$role" /usr/bin/true "$d/config.json" "$account" "${args[@]}" --apply
  [[ $(systemctl show -p LoadState --value "$name.service") == loaded ]]
  [[ $(systemctl show -p ActiveState --value "$name.service") == inactive ]]
  [[ $(systemctl show -p User --value "$name.service") == "$account" ]]
  [[ $(systemctl is-enabled "$name.service" 2>/dev/null || true) == "$enabled" ]]
  [[ $(systemctl show -p Restart --value "$name.service") == no ]]
  case "$role" in
    agent) expected="--vip-node-agent $d/config.json";;
    provider) expected="--vip-redfish-provider $d/config.json";;
    controller) expected="--vip-owner $d/config.json $scope automatic-policy $d/policy.json $d/provider.json $d/journal.json";;
  esac
  grep -Fx "ExecStart=/usr/bin/true $expected" "/etc/systemd/system/$name.service"
  if output=$(bash "$here/install-vip-service.sh" "$role" /usr/bin/true "$d/config.json" "$account" "${args[@]}" --apply 2>&1); then
    echo 'Existing unit overwrite was not refused' >&2; exit 1
  fi
  grep -q 'Existing service' <<<"$output"
  echo "PASS: systemd $role registration, exact identity/command/start mode, stopped state and overwrite refusal"
done
