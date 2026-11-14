#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
: "${REDIS_PASSWORD:?set REDIS_PASSWORD to the CI-generated disposable value}"
compose=(docker compose -f compose.yml)
mkdir -p ../../../artifacts/ci-redis
log=../../../artifacts/ci-redis/check.log
exec > >(tee "$log") 2>&1
rcli() {
  local service="$1"; shift
  "${compose[@]}" exec -T "$service" redis-cli --raw --tls \
    --cacert /certs/ca.crt -h "$service" -p 6379 \
    --no-auth-warning -a "$REDIS_PASSWORD" "$@"
}
sentinel() {
  "${compose[@]}" exec -T sentinel-a redis-cli --raw --tls \
    --cacert /certs/ca.crt -h sentinel-a -p 26379 "$@"
}
ready=0
for i in $(seq 1 90); do
  if [[ "$(rcli redis-primary ping 2>/dev/null || true)" == PONG ]] &&
     [[ "$(rcli redis-replica ping 2>/dev/null || true)" == PONG ]]; then ready=1; break; fi
  sleep 1
done
[[ "$ready" == 1 ]] || { echo 'FAIL: Redis TLS primary/replica unavailable'; exit 1; }
echo "PASS: Redis nodes reachable on TLS-only port 6379"
# TLS without password must not permit data access.
noauth=$("${compose[@]}" exec -T redis-primary redis-cli --tls --cacert /certs/ca.crt -h redis-primary -p 6379 GET ci:unauthed 2>&1 || true)
grep -q 'NOAUTH' <<<"$noauth" || { echo "FAIL: missing NOAUTH denial"; exit 1; }
echo "PASS: anonymous Redis read denied"
rcli redis-primary ACL SETUSER ci_reader on '>lab-only-reader-secret' '~ci:*' '+get' >/dev/null
read_denied=$("${compose[@]}" exec -T redis-primary redis-cli --tls --cacert /certs/ca.crt -h redis-primary -p 6379 --user ci_reader --pass lab-only-reader-secret SET ci:notallowed foo 2>&1 || true)
grep -q 'NOPERM' <<<"$read_denied" || { echo "FAIL: read-only ACL allowed SET"; exit 1; }
echo "PASS: read-only ACL rejects SET"
eval_result=$("${compose[@]}" exec -T redis-primary redis-cli --raw --tls \
  --cacert /certs/ca.crt -h redis-primary -p 6379 -a "$REDIS_PASSWORD" \
  --eval /ci/cas_revision.lua ci:config , 0 1 deadbeef 300)
[[ "$eval_result" == 1 ]] || { echo "FAIL: initial CAS revision $eval_result"; exit 1; }
stale=$("${compose[@]}" exec -T redis-primary redis-cli --raw --tls \
  --cacert /certs/ca.crt -h redis-primary -p 6379 -a "$REDIS_PASSWORD" \
  --eval /ci/cas_revision.lua ci:config , 0 1 deadbeef 300 2>&1 || true)
grep -q 'STALE_REVISION' <<<"$stale" || { echo "FAIL: stale config write accepted"; exit 1; }
echo "PASS: atomic revision CAS rejects stale overwrites"
sync=0
for i in $(seq 1 40); do
  if [[ "$(rcli redis-replica HGET ci:config revision 2>/dev/null || true)" == 1 ]]; then sync=1; break; fi
  sleep 1
done
[[ "$sync" == 1 ]] || { echo "FAIL: Redis replica missing revision"; exit 1; }
echo "PASS: replica contains versioned config"
"${compose[@]}" kill -s SIGKILL redis-primary
echo "FAULT: primary SIGKILL delivered"
promoted=0
for i in $(seq 1 75); do
  role=$(rcli redis-replica ROLE 2>/dev/null | head -1 || true)
  if [[ "$role" == master ]]; then promoted=1; break; fi
  sleep 1
done
[[ "$promoted" == 1 ]] || { echo "FAIL: replica not promoted by Sentinel quorum"; exit 1; }
[[ "$(rcli redis-replica HGET ci:config revision)" == 1 ]] || { echo "FAIL: revision missing after failover"; exit 1; }
[[ "$(rcli redis-replica PING)" == PONG ]] || { echo "FAIL: new master unavailable"; exit 1; }
echo "PASS: Redis Sentinel TLS quorum promoted replica with retained revision"
echo "NOTE: no real application Redis integration or cross-host partition-safe quorum claimed."
