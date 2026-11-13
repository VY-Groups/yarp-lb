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
# A small, deliberately chosen corpus beyond the original XSS smoke test.
# CRS rule IDs and severities are version-dependent; CI verifies actual blocking.
for entry in \
  "sqli|id=1' UNION SELECT password FROM users--" \
  "traversal|file=../../../../etc/passwd"; do
  name="${entry%%|*}"
  payload="${entry#*|}"
  code="$(curl --silent --show-error --max-time 8 --get --data-urlencode "$payload" \
    -o "$DIR/$name-response.txt" -w '%{http_code}' "http://127.0.0.1:18888/")"
  printf '%s\n' "$code" > "$DIR/$name-http-status.txt"
  if [[ "$code" != "403" ]]; then
    echo "FAIL: $name expected CRS 403, received $code" >&2; exit 1
  fi
  echo "PASS: CRS blocks $name payload"
done
# Ordinary parameterized URLs must not be blocked by the generic CRS rules.
benign_code="$(curl --silent --show-error --max-time 8 --get \
  --data-urlencode "q=books-and-cats" --data-urlencode "page=2" \
  -o "$DIR/benign-query.txt" -w '%{http_code}' "http://127.0.0.1:18888/")"
[[ "$benign_code" == "200" ]] || { echo "FAIL: false positive on benign query" >&2; exit 1; }
# Reject bodies above the configured 128 KiB total body cap.
head -c 180000 /dev/zero > "$DIR/oversized-request.bin"
body_code="$(curl --silent --show-error --max-time 10 -X POST \
  --data-binary "@$DIR/oversized-request.bin" -o "$DIR/body-response.txt" \
  -w '%{http_code}' "http://127.0.0.1:18888/" || true)"
printf '%s\n' "$body_code" > "$DIR/body-limit-status.txt"
# ModSecurity 3 nginx connector returns 403 for SecRequestBodyLimitAction
# Reject (other frontends may use 413). Require the explicit engine diagnostic
# to distinguish a real size-limit rejection from unrelated anomaly blocking.
docker compose -f "$COMPOSE" logs --no-color waf > "$DIR/blocking-audit.log" 2>&1 || true
if [[ "$body_code" != "403" && "$body_code" != "413" ]]; then
  echo "FAIL: oversized request was not rejected; got $body_code" >&2; exit 1
fi
if ! grep -q 'Request body limit is marked to reject the request' "$DIR/blocking-audit.log"; then
  echo "FAIL: expected ModSecurity body-limit rejection diagnostic absent" >&2; exit 1
fi
echo "PASS: oversized request rejected by configured ModSecurity body limit (HTTP $body_code)"
# Detection-only deployment must allow the same attack to reach the backend;
# this is not proof of useful alerts until its audit is reviewed and tuned.
WAF_MODE=DetectionOnly docker compose -f "$COMPOSE" up -d --force-recreate --no-deps waf
ready=0
for i in $(seq 1 90); do
  if [[ "$(curl --silent --max-time 2 -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:18888/" || true)" == "200" ]]; then ready=1; break; fi
  sleep 0.6
done
[[ "$ready" == 1 ]] || { echo "FAIL: WAF detection-only restart not ready" >&2; exit 1; }
observe_code="$(curl --silent --show-error --max-time 8 --get \
  --data-urlencode 'q=<script>alert(1)</script>' \
  -o "$DIR/detection-only-response.txt" -w '%{http_code}' "http://127.0.0.1:18888/")"
printf '%s\n' "$observe_code" > "$DIR/detection-only-status.txt"
[[ "$observe_code" == 200 ]] || { echo "FAIL: detection-only did not forward payload" >&2; exit 1; }
docker compose -f "$COMPOSE" logs --no-color waf > "$DIR/detection-only-audit.log" 2>&1 || true
echo "PASS: CRS attack corpus, body cap, benign query and detection-only forwarding"
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
