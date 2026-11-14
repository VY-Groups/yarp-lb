#!/usr/bin/env bash
# Read-only snapshots before/after ONE approved change. Does NOT set any values.
set -euo pipefail
[[ $# -eq 2 && "$1" =~ ^[a-zA-Z0-9_.:-]{1,32}$ ]] || { echo 'usage: $0 <NIC> <out-dir>' >&2; exit 64; }
nic=$1; out=$2; ip link show dev "$nic" >/dev/null
mkdir -p "$out"
{
 date -u --iso-8601=seconds
 ip -s -s link show dev "$nic"
 for mode in -g -l -k -x -S; do ethtool "$mode" "$nic" 2>&1 || true; done
 cat /proc/interrupts
 cat /proc/net/softnet_stat
 ss -s
 nstat -az 2>&1 || true
 for key in net.core.rmem_max net.core.wmem_max net.core.netdev_max_backlog net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max; do
  sysctl "$key" 2>&1 || true
 done
} > "$out/nic-$(date -u +%Y%m%dT%H%M%SZ).txt"
