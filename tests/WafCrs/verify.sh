#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
DIR="$PWD/artifacts/waf-crs"
mkdir -p "$DIR"
COMPOSE="$ROOT/integrations/WafCrs/compose.lab.yml"
# An explicitly chosen image must be immutable, from the expected upstream.
# Omitted selection remains a rolling-tag disposable lab, never production.
if [[ -n "${WAF_IMAGE:-}" && ! "$WAF_IMAGE" =~ ^owasp/modsecurity-crs@sha256:[a-f0-9]{64}$ ]]; then
  echo "WAF_IMAGE must be an upstream repository digest" >&2
  exit 64
fi
for phase in direct blocking detection proxy-only restored; do
  rm -f "$DIR/benchmark-$phase.json"
done
rm -f "$DIR/benchmark-summary.json" "$DIR/waf-selected-image.txt"
# Clear only this run's known synthetic result files; never count stale
# evidence from an earlier invocation as a successful observation.
for result in last-benign-status json-http-status xml-http-status large-json-http-status pkix-der-http-status benign-query-http-status unicode-query-http-status cookie-query-http-status xss-http-status sqli-http-status traversal-http-status; do
  rm -f "$DIR/$result.txt"
done
rm -f "$DIR/blocking-corpus-report.json"
write_corpus_report() {
  python3 - "$DIR" "$1" <<'PY'
import json, pathlib, sys

directory = pathlib.Path(sys.argv[1])
strict = sys.argv[2] == "1"
# Body-limit policy, readiness retries and detection-only checks have
# separate assertions; do not mix them into the classification matrix.
cases = (
    ("benign-http", "/", "benign", "last-benign-status"),
    ("benign-json", "/acceptance", "benign", "json-http-status"),
    ("benign-xml", "/acceptance", "benign", "xml-http-status"),
    ("benign-large-json", "/acceptance", "benign", "large-json-http-status"),
    ("benign-pkix-der", "/acceptance", "benign", "pkix-der-http-status"),
    ("benign-query", "/", "benign", "benign-query-http-status"),
    ("benign-unicode-query", "/", "benign", "unicode-query-http-status"),
    ("benign-cookie-query", "/", "benign", "cookie-query-http-status"),
    ("xss", "/", "malicious", "xss-http-status"),
    ("sqli", "/", "malicious", "sqli-http-status"),
    ("traversal", "/", "malicious", "traversal-http-status"),
)
rows = []
matrices = {}
# Severity is the fixed fixture's ground truth; do not misrepresent it as
# upstream CRS severity or inferred risk from an HTTP response.
severity = {"xss": "high", "sqli": "high", "traversal": "high"}
severity_matrices = {}
for name, route, expected, file_name in cases:
    file = directory / (file_name + ".txt")
    status = file.read_text(encoding="utf-8").strip() if file.exists() else None
    if status == "200":
        outcome = "TN" if expected == "benign" else "FN"
    elif status == "403":
        outcome = "FP" if expected == "benign" else "TP"
    else:
        outcome = "missing" if status is None else "unexpected_status"
    counts = matrices.setdefault(route, dict.fromkeys(("TP", "TN", "FP", "FN", "missing", "unexpected_status"), 0))
    counts[outcome] += 1
    severity_name = severity.get(name, "none")
    severity_counts = severity_matrices.setdefault(
        route, {}).setdefault(severity_name,
                              dict.fromkeys(("TP", "TN", "FP", "FN", "missing", "unexpected_status"), 0))
    severity_counts[outcome] += 1
    rows.append({"case": name, "route": route, "expected": expected,
                 "groundTruthSeverity": severity_name,
                 "httpStatus": status, "outcome": outcome})
totals = {key: sum(counts[key] for counts in matrices.values())
          for key in ("TP", "TN", "FP", "FN", "missing", "unexpected_status")}
complete = totals["missing"] == totals["unexpected_status"] == 0
report = {"schemaVersion": 1, "scope": "synthetic-blocking-lab-only",
          "complete": complete, "cases": rows, "perRoute": matrices,
          "perRouteAndGroundTruthSeverity": severity_matrices, "totals": totals,
          "falsePositiveRate": totals["FP"] / (totals["FP"] + totals["TN"])
              if complete else None,
          "falseNegativeRate": totals["FN"] / (totals["FN"] + totals["TP"])
              if complete else None}
(directory / "blocking-corpus-report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if strict and (not complete or totals["FP"] or totals["FN"]):
    raise SystemExit("FAIL: synthetic WAF blocking corpus incomplete or misclassified")
PY
}
WAF_CERT_TMP=""  # Never act on an inherited environment value during cleanup.
function teardown {
  # Never upload a private disposable certificate key with the WAF artifacts.
  if [[ -n "${WAF_CERT_TMP:-}" ]]; then rm -rf -- "$WAF_CERT_TMP"; fi
  # Preserve missing/unexpected outcomes even after a fail-fast assertion.
  write_corpus_report 0 || true
  docker compose -f "$COMPOSE" logs --no-color >"$DIR/docker-compose.log" 2>&1 || true
  docker compose -f "$COMPOSE" down --remove-orphans --volumes || true
}
trap teardown EXIT
docker compose -f "$COMPOSE" config --quiet
WAF_MODE=On docker compose -f "$COMPOSE" up --detach
# Record the exact pulled WAF image, not just the mutable tag in Compose.
waf_id="$(docker compose -f "$COMPOSE" ps --quiet waf)"
waf_image_id="$(docker inspect "$waf_id" --format '{{.Image}}')"
printf '%s\n' "$waf_image_id" > "$DIR/waf-image-id.txt"
docker image inspect "$waf_image_id" --format '{{json .RepoDigests}}' > "$DIR/waf-image-digests.json"
# Freeze the exact pulled image for every subsequent mode change.
selected_digest="$(python3 - "$DIR/waf-image-digests.json" <<'PY'
import json, re, sys
digests = json.load(open(sys.argv[1], encoding="utf-8"))
matches = sorted(d for d in digests or [] if re.fullmatch(r"owasp/modsecurity-crs@sha256:[a-f0-9]{64}", d))
if len(matches) != 1:
    raise SystemExit("Missing or ambiguous upstream WAF repository digest")
print(matches[0])
PY
)"
if [[ -n "${WAF_IMAGE:-}" && "$WAF_IMAGE" != "$selected_digest" ]]; then
  echo "Pulled image does not match requested digest" >&2; exit 1
fi
export WAF_IMAGE="$selected_digest"
printf '%s\n' "$WAF_IMAGE" > "$DIR/waf-selected-image.txt"
assert_same_image() {
  local id
  id="$(docker compose -f "$COMPOSE" ps --quiet waf)"
  [[ "$(docker inspect "$id" --format '{{.Image}}')" == "$waf_image_id" ]] ||
    { echo "FAIL: immutable WAF image changed during mode switch" >&2; exit 1; }
}
benchmark() {
  local phase="$1"
  docker compose -f "$COMPOSE" --profile benchmark run --rm --no-deps -T benchmark "$phase" \
    > "$DIR/benchmark-$phase.json"
}
wait_waf() {
  local i
  for i in $(seq 1 90); do
    if [[ "$(curl --silent --max-time 2 -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:18888/ || true)" == 200 ]]; then return 0; fi
    sleep 0.6
  done
  echo "FAIL: WAF mode restart not ready" >&2; return 1
}
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
# Check a small, explicitly selected benign request corpus while CRS is in
# blocking mode. The backend returns only metadata and never reflects payloads.
assert_benign_post() {
  local name="$1" content_type="$2" payload_file="$3" response_file="$4"
  local status
  status="$(curl --silent --show-error --max-time 10 -X POST \
    -H "Content-Type: $content_type" --data-binary "@$payload_file" \
    -o "$response_file" -w '%{http_code}' "http://127.0.0.1:18888/acceptance")"
  printf '%s\n' "$status" > "$DIR/$name-http-status.txt"
  if [[ "$status" != "200" ]]; then
    echo "FAIL: benign $name request was blocked (HTTP $status)" >&2; exit 1
  fi
  python3 - "$response_file" "$payload_file" "$content_type" <<'PY'
import json, pathlib, sys
response = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
payload_bytes = pathlib.Path(sys.argv[2]).stat().st_size
content_type = sys.argv[3].split(";", 1)[0].strip().lower()
assert response == {"accepted": True, "contentType": content_type, "bytes": payload_bytes}, response
PY
  echo "PASS: benign $name request passed CRS and reached the bounded backend"
}

FIXTURES="$ROOT/tests/WafCrs/fixtures"
assert_benign_post json application/json "$FIXTURES/benign.json" "$DIR/json-response.json"
assert_benign_post xml application/xml "$FIXTURES/benign.xml" "$DIR/xml-response.json"
python3 - "$DIR/large-json.json" <<'PY'
import json, pathlib, sys
records = [
    {"id": i, "name": f"service-{i:04d}", "description": "ordinary inventory metadata " * 7}
    for i in range(128)
]
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({"records": records}, separators=(",", ":")), encoding="utf-8")
size = path.stat().st_size
assert 16_384 < size < 65_536, size
PY
assert_benign_post large-json application/json "$DIR/large-json.json" "$DIR/large-json-response.json"
# Use a real disposable, syntactically valid public X.509 DER leaf to exercise
# the CA/PKI upload content type. Its private key stays in a restricted,
# separately cleaned temporary directory, never in uploaded artifacts.
WAF_CERT_TMP="$(mktemp -d)"
chmod 700 "$WAF_CERT_TMP"
openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=Disposable WAF Acceptance Certificate" \
  -keyout "$WAF_CERT_TMP/private.key" -out "$WAF_CERT_TMP/public.pem" >/dev/null 2>&1
openssl x509 -in "$WAF_CERT_TMP/public.pem" -outform DER -out "$DIR/benign-cert.der"
assert_benign_post pkix-der application/pkix-cert "$DIR/benign-cert.der" "$DIR/pkix-der-response.json"
# A certificate upload outside the exact, approved lab endpoint must still
# hit the original CRS content-type policy. Fail if our exclusion is broad.
outside_pkix_code="$(curl --silent --show-error --max-time 8 -X POST \
  -H 'Content-Type: application/pkix-cert' \
  --data-binary "@$DIR/benign-cert.der" \
  -o "$DIR/outside-pkix-response.txt" -w '%{http_code}' "http://127.0.0.1:18888/not-allowed")"
printf '%s\n' "$outside_pkix_code" > "$DIR/outside-pkix-http-status.txt"
[[ "$outside_pkix_code" == "403" ]] ||
  { echo "FAIL: PKIX content-type exception unexpectedly escaped its exact route" >&2; exit 1; }
echo "PASS: PKIX exception applies only to the exact POST /acceptance route"
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
printf '%s\n' "$benign_code" > "$DIR/benign-query-http-status.txt"
[[ "$benign_code" == "200" ]] || { echo "FAIL: false positive on benign query" >&2; exit 1; }
unicode_code="$(curl --silent --show-error --max-time 8 --get \
  --data-urlencode 'q=café façade – legitimate inventory' \
  -o "$DIR/unicode-query.txt" -w '%{http_code}' "http://127.0.0.1:18888/")"
printf '%s\n' "$unicode_code" > "$DIR/unicode-query-http-status.txt"
[[ "$unicode_code" == "200" ]] || { echo "FAIL: false positive on benign Unicode query" >&2; exit 1; }
cookie_code="$(curl --silent --show-error --max-time 8 \
  -H 'Cookie: session=opaqueFixture; preference=en-US' \
  -o "$DIR/cookie-query.txt" -w '%{http_code}' "http://127.0.0.1:18888/")"
printf '%s\n' "$cookie_code" > "$DIR/cookie-query-http-status.txt"
[[ "$cookie_code" == "200" ]] || { echo "FAIL: false positive on benign cookie request" >&2; exit 1; }
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
# Matched request counts, concurrency and payloads from an isolated
# Docker-network client; the direct origin has no published host port.
benchmark direct
benchmark blocking
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
grep -Fxq 'YARP-WAF-CI-BENIGN' "$DIR/detection-only-response.txt" || { echo "FAIL: detection-only response did not come from the test backend" >&2; exit 1; }
# Require evidence that CRS actually detected the XSS, rather than merely allowing it.
docker compose -f "$COMPOSE" logs --no-color waf > "$DIR/detection-only-audit.log" 2>&1
if ! grep -Eq '\[id "941[0-9]{3}"\]' "$DIR/detection-only-audit.log"; then
  echo "FAIL: detection-only XSS lacks a CRS 941xxx rule diagnostic" >&2; exit 1
fi
# A detection-only restart must exercise the same image as the blocking phase.
observe_id="$(docker compose -f "$COMPOSE" ps --quiet waf)"
[[ "$(docker inspect "$observe_id" --format '{{.Image}}')" == "$waf_image_id" ]] || { echo "FAIL: WAF image changed between modes" >&2; exit 1; }
echo "PASS: CRS attack corpus, benign JSON/XML/large upload corpus, body cap, benign query and detection-only forwarding"
benchmark detection
# Proxy-only baseline is a disposable, isolated nginx mode, NOT a
# production bypass and NOT a YARP performance measurement.
WAF_MODE=Off docker compose -f "$COMPOSE" up -d --force-recreate --no-deps waf
wait_waf
assert_same_image
benchmark proxy-only
# Restore the blocking policy on the identical immutable image, then
# prove that benign traffic passes and a known malicious input is blocked.
WAF_MODE=On docker compose -f "$COMPOSE" up -d --force-recreate --no-deps waf
wait_waf
assert_same_image
restored_code="$(curl --silent --show-error --max-time 8 --get \
  --data-urlencode 'q=<script>alert(1)</script>' \
  -o "$DIR/restored-block-response.txt" -w '%{http_code}' http://127.0.0.1:18888/)"
[[ "$restored_code" == 403 ]] || { echo "FAIL: restored blocking policy did not block XSS" >&2; exit 1; }
benchmark restored
python3 - "$DIR" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
phases = ("direct", "proxy-only", "blocking", "detection", "restored")
rows = {p: json.loads((root / f"benchmark-{p}.json").read_text()) for p in phases}
assert all(v["complete"] and v["errors"] == 0 for v in rows.values())
assert len({(v["requests"], v["concurrency"], v["workload"]) for v in rows.values()}) == 1
report = {"schemaVersion": 1, "scope": "synthetic-lab-not-production-capacity",
          "wafImage": (root / "waf-selected-image.txt").read_text().strip(),
          "phases": rows}
(root / "benchmark-summary.json").write_text(json.dumps(report, indent=2) + "\n")
print("PASS: matched direct, nginx-only, blocking, detection and restored-mode benchmarks")
PY
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
write_corpus_report 1
echo "WAF_CRS_LAB_PASS"
