#!/usr/bin/env bash
# LAB ONLY. Builds the real GatewayCore application; no production services.
set -euo pipefail
cd "$(dirname "$0")"
for command in docker openssl curl; do
  command -v "$command" >/dev/null || { echo "MISSING: $command" >&2; exit 2; }
done
docker compose version >/dev/null
if [[ -n "${TEST_BIND_IP:-}" ]]; then
  if [[ ! "${TEST_BIND_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "TEST_BIND_IP must be an explicit IPv4 address" >&2; exit 2
  fi
  if [[ "${TEST_BIND_IP}" == "0.0.0.0" ]]; then
    echo "Wildcard bind is refused. Select a test VLAN interface address." >&2; exit 2
  fi
fi
mkdir -p certs
chmod 0700 certs
if [[ ! -f certs/server.crt || ! -f certs/server.key ]]; then
  [[ ! -e certs/server.crt && ! -e certs/server.key ]] || {
    echo "Incomplete TLS identity; refusing to overwrite. Restore the pair." >&2; exit 2;
  }
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -days 7 -keyout certs/server.key -out certs/server.crt
fi
chmod 0600 certs/server.key
docker compose -f compose.yml config --quiet
docker compose -f compose.yml up -d --build
echo 'Started test-only stack; checking endpoints...'
ready=0
for attempt in $(seq 1 90); do
  if curl --noproxy '*' --silent --show-error --fail --max-time 2 \
     http://127.0.0.1:18080/api/identity >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
if [[ "$ready" != "1" ]]; then
  docker compose -f compose.yml ps
  docker compose -f compose.yml logs --tail=80 gateway-a gateway-b ingress
  echo 'NO-GO: gateway did not become ready' >&2; exit 1
fi
curl --noproxy '*' --fail --silent --show-error --cacert certs/server.crt \
  https://127.0.0.1:18443/api/identity >/dev/null
for url in /dashboard /gateway/metrics; do
  status=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:18080$url")
  [[ "$status" == "403" ]] || {
    echo "NO-GO: restricted endpoint $url exposed (HTTP $status)" >&2; exit 1;
  }
done
echo 'LAB PASS: http://127.0.0.1:18080/api/identity'
echo 'LAB PASS: https://127.0.0.1:18443/api/identity (trust certs/server.crt)'
echo 'Run: ./smoke.sh ; stop: docker compose -f compose.yml down'
