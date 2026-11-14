#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v curl >/dev/null
[[ -f certs/server.crt ]] || { echo 'Run install.sh first' >&2; exit 2; }
for protocol in http https; do
  if [[ "$protocol" == http ]]; then
    url="http://127.0.0.1:18080"
    options=()
  else
    url="https://127.0.0.1:18443"
    options=(--cacert certs/server.crt)
  fi
  for route in /api/identity /api/body/1048576; do
    status=$(curl --noproxy '*' --silent --show-error --max-time 10 \
      "${options[@]}" -o /dev/null -w '%{http_code}' "$url$route")
    [[ "$status" == 200 ]] || { echo "FAIL $url$route: $status" >&2; exit 1; }
  done
  for private in /dashboard /gateway/metrics; do
    status=$(curl --noproxy '*' --silent --show-error --max-time 10 \
      "${options[@]}" -o /dev/null -w '%{http_code}' "$url$private")
    [[ "$status" == 403 ]] || { echo "FAIL private $url$private: $status" >&2; exit 1; }
  done
done
echo 'PASS HTTP/HTTPS routes and private path isolation'
echo 'Example throughput: oha -z 30s -c 50 -q 200 --no-tui http://127.0.0.1:18080/api/body/1048576'
