# GatewayCore #109 physical multi-node acceptance

**Runs:** 2026-11-20; observer quorum (about 01:12–01:21 UTC) and AuthorityFence partition/restart (about 01:30–01:38 UTC).  
**Source:** main commit 47fbc0403d9bde5f7bcff62b1f55fd7730469623  
**Environment:** three disposable Amazon Linux 2023 EC2 hosts. The observer phase used two DNS authorities (Mumbai and Osaka) and three separately enrolled signed mTLS observers on three hosts, assigned three configured vantage groups. Actual geographic and network-path diversity was not independently verified. The AuthorityFence phase ran two DNS authorities (Mumbai and Osaka). Apache was the local readiness backend. Both phases used disposable .invalid zones.  
**Scope:** Physical multi-node observer-quorum and two-authority fencing behavior. Partial #109 acceptance, not production certification.

## Observer quorum results

| Scenario | DNS authority results (UDP and TCP) | Result |
|---|---|---|
| Three fresh authenticated reports from three configured groups | Both authorities returned authoritative NOERROR with the configured A address | PASS |
| Stop one observer and allow its report to expire | Both authorities continued returning authoritative NOERROR | PASS; two fresh configured groups remained |
| Stop a second observer from a distinct configured group and allow expiry | Both authorities returned authoritative SERVFAIL with no answers | PASS; quorum was below 2 |
| Restart observers and receive fresh reports | Both authorities returned authoritative NOERROR again | PASS |

## AuthorityFence results

| Scenario | DNS authority results (UDP and TCP) | Result |
|---|---|---|
| Two authorities exchange mutually authenticated, signed 2-of-2 snapshots | Both returned authoritative NOERROR with the configured A address | PASS |
| Add reciprocal temporary host-route blackholes for each peer's public /32; wait 11 seconds, beyond the configured 8-second lease | Both returned authoritative SERVFAIL with no answers | PASS |
| Remove both blackhole routes | Both returned authoritative NOERROR after fresh signed snapshots were exchanged | PASS |
| Keep the peer routes blocked while restarting the Osaka authority, retaining its protected epoch/replay files (mode 0600) | Both remained SERVFAIL; after route restoration and fresh snapshots, both recovered to NOERROR | PASS |

DNS responses were queried directly at each authority's public IP. The authority-fence test used the shipping listener on TCP 15444 and a disposable mutual-TLS CA, distinct authority signing keys, and independent epoch/replay state. The temporary route affected only the peer's public /32; SSH access and unrelated host routes stayed available.

## Cleanup and limits

All temporary GatewayCore binaries, configs, certificates, state, watchdogs and processes were removed. Temporary peer /32 blackhole routes were deleted and normal VPC gateway routes were restored. Apache remained active and returned HTTP 200 on all three hosts; ports 53 and 15444 were no longer listening. No AWS security-group, Apache, or system-service configuration was changed.

The observer groups are configured labels, not proof of independent geography or network paths. The AuthorityFence drill was a reversible host-route partition; it did not simulate switch, security-group, ISP, power, or physical NIC failure. Neither phase tested DNSSEC/public delegation, malicious-frame fuzzing, one-hour soak, 500 Mbps capacity, VRRP/ECMP, or annual 99.9% availability. Issue #109 remains open and production remains NO-GO.
