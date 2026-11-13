#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
DIR="$PWD/artifacts/waf-crs"
mkdir -p "$DIR"
COMPOSE="$ROOT/integrations/WafCrs/compose.lab.yml"
function teardown {
  docker compose -f "$COMPOSE" logs --no-color >"$DIR/docker-compose.log" 2>&1 || true
  docker compose -f "$COMPOSE" down --remove-orphans --volumes || true
}
trap teardown EXIT
docker compose -f "$COMPOSE" config --quiet
docker compose -f "$COMPOSE" up --detach
ready=0
for i in $(seq 1 150); do
  code="$(curl --silent --max-time 2 -w '%{http_code}' "http://127.0.0.1:18888/" -o "$DIR/benign-body.txt" || true)"
  printf '%s\n' "$code" > "$DIR/last-benign-status.txt"
  if [[ "$code" == "200" ]]; then
    ready=1; break
  fi
  sleep 0.6
done
if [[ "$ready" != "1" ]]; then
  echo "WAF did not forward a benign request" >&2; exit 1
fi
grep -q 'YARP-WAF-CI-BENIGN' "$DIR/benign-body.txt"
echo "PASS: benign HTTP request proxied through ModSecurity CRS"
xss_code="$(curl --silent --show-error --max-time 8 -o "$DIR/xss-response.txt" \
  -w '%{http_code}' --get --data-urlencode \
  'q=<script>alert(1)</script>' "http://127.0.0.1:18888/")"
printf '%s\n' "$xss_code" > "$DIR/xss-http-status.txt"
if [[ "$xss_code" != "403" ]]; then
  echo "FAIL: expected OWASP CRS XSS attack HTTP 403; got $xss_code" >&2
  exit 1
fi
echo "PASS: XSS blocked by real ModSecurity/CRS rules (HTTP 403)"
# Compose 'port' output is not proof of a host port binding; inspect Docker's
# actual NetworkSettings.Ports and reject any published HostIp/HostPort.
app_id="$(docker compose -f "$COMPOSE" ps --quiet protected-app)"
docker inspect "$app_id" --format '{{json .NetworkSettings.Ports}}' > "$DIR/backend-bindings.json"
python3 - "$DIR/backend-bindings.json" <<'PY'
import json,sys
bindings=json.load(open(sys.argv[1],encoding='utf-8'))
assert all(not rows for rows in bindings.values()), f'Backend exposed on host: {bindings}'
print('PASS: Docker confirms no backend HostIp/HostPort bindings')
PY
docker compose -f "$COMPOSE" images > "$DIR/images.txt"
echo "WAF_CRS_LAB_PASS"
