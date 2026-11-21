#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this acceptance as root (the GitHub Actions caller uses passwordless sudo)." >&2
  exit 2
fi
if ! command -v systemctl >/dev/null || ! systemctl show-environment >/dev/null 2>&1; then
  echo "A running systemd system manager is required for this acceptance." >&2
  exit 2
fi

repo_root="$(pwd)"
app_source="$repo_root/bin/Release/net10.0"
repository_root="$(cd "$repo_root/.." && pwd)"
service_template="$repository_root/ops/systemd/gatewaycore-yarp.service"
dotnet_path="$(command -v dotnet || true)"
if [[ ! -x "$dotnet_path" && -x /usr/share/dotnet/dotnet ]]; then
  dotnet_path=/usr/share/dotnet/dotnet
fi
if [[ ! -f "$app_source/GatewayCoreYarp.dll" ]]; then
  echo "Build the shipping Control Center before systemd acceptance." >&2
  exit 2
fi
if [[ ! -f "$service_template" ]]; then
  echo "The shipped systemd unit template is missing." >&2
  exit 2
fi
if [[ -z "$dotnet_path" || ! -x "$dotnet_path" ]]; then
  echo "The installed .NET runtime executable is unavailable." >&2
  exit 2
fi

id="$(openssl rand -hex 6)"
unit="gatewaycore-dp-test-${id}.service"
service_user="gatewaycore-dp-${id}"
service_group="$service_user"
app_dir="/opt/gatewaycore-dp-test-${id}"
state_dir="/var/lib/gatewaycore-dp-test-${id}"
log_dir="/var/log/gatewaycore-dp-test-${id}"
unit_path="/run/systemd/system/$unit"
dotnet_real_path="$(readlink -f "$dotnet_path")"
dotnet_root="$(dirname "$dotnet_real_path")"
service_port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
created_user=0

cleanup() {
  systemctl stop "$unit" >/dev/null 2>&1 || true
  rm -f "$unit_path"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$app_dir" "$state_dir" "$log_dir"
  if [[ "$created_user" -eq 1 ]]; then
    userdel "$service_user" >/dev/null 2>&1 || true
    groupdel "$service_group" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 143' INT TERM

useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$service_user"
created_user=1
install -d -o root -g root -m 0755 "$app_dir"
cp -a "$app_source/." "$app_dir/"
if [[ "$dotnet_root" == /root/* || "$dotnet_root" == /home/* ]]; then
  # ProtectHome=yes hides per-user SDK installations. Copy only the host and
  # shared runtimes beneath /opt so the service still observes that safeguard.
  runtime_copy="$app_dir/dotnet-runtime"
  install -d -o root -g root -m 0755 "$runtime_copy"
  cp -a "$dotnet_root/dotnet" "$dotnet_root/host" "$dotnet_root/shared" "$runtime_copy/"
  dotnet_path="$runtime_copy/dotnet"
  dotnet_root="$runtime_copy"
fi
install -d -o "$service_user" -g "$service_group" -m 0700 \
  "$state_dir" "$state_dir/config" "$state_dir/secrets" "$log_dir"

cat > "$state_dir/config/appsettings.json" <<'JSON'
{"Logging":{"LogLevel":{"Default":"Warning","Yarp.ReverseProxy":"Warning"}},"ReverseProxy":{"Routes":{},"Clusters":{}}}
JSON
chown "$service_user:$service_group" "$state_dir/config/appsettings.json"
chmod 0600 "$state_dir/config/appsettings.json"

openssl req -x509 -newkey rsa:3072 -keyout "$state_dir/secrets/protection.key" \
  -out "$state_dir/secrets/protection.crt" -days 7 -nodes \
  -subj "/CN=GatewayCore systemd acceptance ${id}" \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,keyEncipherment' >/dev/null 2>&1
openssl rand -hex 32 > "$state_dir/secrets/protection.password"
openssl pkcs12 -export -out "$state_dir/secrets/protection.pfx" \
  -inkey "$state_dir/secrets/protection.key" -in "$state_dir/secrets/protection.crt" \
  -passout "file:$state_dir/secrets/protection.password" >/dev/null 2>&1
rm -f "$state_dir/secrets/protection.key" "$state_dir/secrets/protection.crt"
chown -R "$service_user:$service_group" "$state_dir"
chmod 0700 "$state_dir" "$state_dir/config" "$state_dir/secrets"
chmod 0600 "$state_dir/config/appsettings.json" \
  "$state_dir/secrets/protection.password" "$state_dir/secrets/protection.pfx"

python3 - "$service_template" "$unit_path" "$service_user" "$service_group" \
  "$app_dir" "$state_dir" "$log_dir" "$service_port" "$dotnet_path" "$dotnet_root" <<'PY'
import pathlib
import sys

template_path, output_path, user, group, app, state, logs, port, dotnet, dotnet_root = sys.argv[1:]
text = pathlib.Path(template_path).read_text()
replacements = {
    "User=gateway-gateway": f"User={user}",
    "Group=gateway-gateway": f"Group={group}",
    "WorkingDirectory=/opt/gatewaycore-yarp/current": f"WorkingDirectory={app}",
    "ExecStart=/usr/bin/dotnet /opt/gatewaycore-yarp/current/GatewayCoreYarp.dll":
        f"ExecStart={dotnet} {app}/GatewayCoreYarp.dll",
    "Environment=YARP_LISTENERS_CONFIG_FILE=/etc/gatewaycore-yarp/listeners.json": "",
    "Environment=YARP_CONTROL_PLANE_DIR=/var/lib/gatewaycore-yarp/control-plane":
        f"Environment=YARP_CONTROL_PLANE_DIR={state}",
    "Environment=YARP_RUNTIME_CONFIG_PATH=/var/lib/gatewaycore-yarp/control-plane/config/appsettings.json":
        f"Environment=YARP_RUNTIME_CONFIG_PATH={state}/config/appsettings.json",
    "Environment=YARP_LINUX_DP_CERT_PFX_PATH=/etc/gatewaycore-yarp/secrets/dp-protection.pfx":
        f"Environment=YARP_LINUX_DP_CERT_PFX_PATH={state}/secrets/protection.pfx",
    "Environment=YARP_LINUX_DP_CERT_PASSWORD_FILE=/etc/gatewaycore-yarp/secrets/dp-pfx-password":
        f"Environment=YARP_LINUX_DP_CERT_PASSWORD_FILE={state}/secrets/protection.password",
    "ReadWritePaths=/var/lib/gatewaycore-yarp /var/log/gatewaycore-yarp":
        f"ReadWritePaths={state} {logs}",
}
for original, replacement in replacements.items():
    if text.count(original) != 1:
        raise SystemExit(f"Expected exactly one template directive: {original}")
    text = text.replace(original, replacement)
environment = "Environment=ASPNETCORE_ENVIRONMENT=Production"
if text.count(environment) != 1:
    raise SystemExit("Expected exactly one Production environment directive")
text = text.replace(environment,
    environment + f"\nEnvironment=ASPNETCORE_URLS=http://127.0.0.1:{port}" +
    f"\nEnvironment=DOTNET_ROOT={dotnet_root}" +
    f"\nEnvironment=DOTNET_CLI_HOME={state}/dotnet-home")
pathlib.Path(output_path).write_text(text)
PY
chmod 0644 "$unit_path"
for required_directive in \
  "User=$service_user" \
  "Group=$service_group" \
  "UMask=0077" \
  "NoNewPrivileges=yes" \
  "PrivateTmp=yes" \
  "ProtectSystem=strict" \
  "ProtectHome=yes" \
  "ReadWritePaths=$state_dir $log_dir"; do
  if ! grep -Fqx "$required_directive" "$unit_path"; then
    echo "The temporary systemd unit lost required template hardening: $required_directive" >&2
    exit 1
  fi
done
systemd-analyze verify "$unit_path"
systemctl daemon-reload
if ! systemctl start "$unit"; then
  systemctl status --no-pager "$unit" || true
  journalctl --no-pager -u "$unit" -n 25 || true
  echo "Could not start the temporary systemd acceptance service." >&2
  exit 1
fi

ready=0
for _ in $(seq 1 100); do
  if curl --silent --show-error --fail "http://127.0.0.1:${service_port}/gateway/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! systemctl is-active --quiet "$unit"; then
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  systemctl status --no-pager "$unit" || true
  journalctl --no-pager -u "$unit" -n 25 || true
  echo "Production Control Center did not become healthy under systemd." >&2
  exit 1
fi

key_dir="$state_dir/data-protection-keys"
mapfile -t key_files < <(find "$key_dir" -maxdepth 1 -type f -name 'key-*.xml' -print | sort)
if [[ "${#key_files[@]}" -eq 0 ]]; then
  echo "systemd service did not persist a Data Protection key." >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$state_dir")" != 700 || "$(stat -c '%a' "$key_dir")" != 700 ]]; then
  echo "systemd service state/key directories are not owner-only." >&2
  exit 1
fi
for key_file in "${key_files[@]}"; do
  if ! grep -q '<encryptedSecret' "$key_file" || grep -q '<masterKey' "$key_file"; then
    echo "Persisted Data Protection XML is not certificate-wrapped." >&2
    exit 1
  fi
done
if [[ "$(stat -c '%a' "$state_dir/config/appsettings.json")" != 600 ||
      "$(stat -c '%a' "$state_dir/secrets/protection.pfx")" != 600 ||
      "$(stat -c '%a' "$state_dir/secrets/protection.password")" != 600 ]]; then
  echo "systemd service configuration or key-wrap secrets are not owner-only." >&2
  exit 1
fi

cookie_jar="$state_dir/session.cookies"
bootstrap_payload='{"username":"systemd_dp_admin","password":"systemd-dp-acceptance-password-123","email":"systemd-dp@example.invalid"}'
printf '%s' "$bootstrap_payload" | curl --silent --show-error --fail --cookie-jar "$cookie_jar" \
  -H 'Content-Type: application/json' \
  --data-binary @- \
  "http://127.0.0.1:${service_port}/admin/api/bootstrap" >/dev/null
check_session() {
  local result
  result="$(curl --silent --show-error --fail --cookie "$cookie_jar" \
    "http://127.0.0.1:${service_port}/admin/api/session")"
  python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["authenticated"] is True and v["username"] == "systemd_dp_admin"' <<< "$result"
}
check_session
before_key_ids="$(printf '%s\n' "${key_files[@]}")"

systemctl restart "$unit"
ready=0
for _ in $(seq 1 100); do
  if curl --silent --show-error --fail "http://127.0.0.1:${service_port}/gateway/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! systemctl is-active --quiet "$unit"; then
    break
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  systemctl status --no-pager "$unit" || true
  journalctl --no-pager -u "$unit" -n 25 || true
  echo "Production Control Center did not recover after systemd restart." >&2
  exit 1
fi
check_session
after_key_ids="$(find "$key_dir" -maxdepth 1 -type f -name 'key-*.xml' -print | sort)"
if [[ "$before_key_ids" != "$after_key_ids" ]]; then
  echo "systemd restart changed or lost the persisted Data Protection key ring." >&2
  exit 1
fi

echo "PASS: shipped Control Center starts under systemd as an unprivileged service identity"
echo "PASS: systemd service persists only certificate-wrapped Data Protection keys in mode-0700 state"
echo "PASS: pre-restart authenticated cookie remains valid after systemctl restart"
