#!/usr/bin/env bash
# Disposable Ubuntu GitHub runner ONLY. A dump may contain secrets: never run on
# customer/CA machines or upload production-memory artifacts.
set -uo pipefail
pid="${1:?missing process id}"
out="${2:?missing output directory}"
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || exit 64
mkdir -p "$out"
{
  date -u +"%Y-%m-%dT%H:%M:%SZ"
  echo "pid=$pid"
  echo "=== process ==="
  ps -p "$pid" -o pid,ppid,stat,nlwp,rss,vsz,etime,cmd || true
  echo "=== system sockets ==="
  ss -s || true
  echo "=== established / time-wait counts ==="
  ss -tan state established | wc -l || true
  ss -tan state time-wait | wc -l || true
  echo "=== ephemeral port range ==="
  cat /proc/sys/net/ipv4/ip_local_port_range || true
  echo "=== open FD count ==="
  find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c || true
  echo "=== FD and OS limits ==="
  cat "/proc/$pid/limits" || true
  echo "=== process status ==="
  grep -E '^(Name|State|Threads|VmRSS|VmSize|FDSize|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' "/proc/$pid/status" || true
  echo "=== host memory ==="
  free -m || true
} > "$out/linux-snapshot.txt" 2>&1
# Address/port data are disposable loopback lab only. No production hosts.
(timeout -k 5s 15s ss -tanp > "$out/tcp-sockets.txt" 2>&1) || true
# Counter timeline is collected from START of load by the calling workflow.
# Capture stack report quickly before the heap dump potentially suspends runtime.
timeout -k 5s 40s dotnet-stack report --process-id "$pid" > "$out/managed-stacks.txt" 2>&1
echo "dotnet_stack_exit=$?" > "$out/stack-capture-status.txt"
# Prior 600-MiB Heap dumps timed out on suspended/high-contention test
# processes. Capture a smaller, complete Mini dump first; stack snapshots and
# pre-trigger counters remain the primary starvation evidence.
timeout -k 5s 65s dotnet-dump collect --process-id "$pid" --type Mini --output "$out/hang-mini.dmp" > "$out/dump-collect.log" 2>&1
dump_status=$?
echo "dotnet_dump_exit=$dump_status" > "$out/dump-capture-status.txt"
if [[ "$dump_status" != 0 ]]; then
  rm -f "$out/hang-mini.dmp" # timed-out dump is incomplete and unsafe to analyze
  echo "Dump capture failed or timed out; managed-stacks.txt remains usable" >> "$out/dump-collect.log"
fi
exit 0
