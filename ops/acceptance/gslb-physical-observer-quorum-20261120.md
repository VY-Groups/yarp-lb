# GatewayCore #109 physical observer-quorum acceptance

**Run:** 2026-11-20 01:12–01:21 UTC  
**Source:** main commit 47fbc0403d9bde5f7bcff62b1f55fd7730469623  
**Environment:** three disposable Amazon Linux 2023 EC2 hosts; two DNS authorities (Mumbai and Osaka), with three independently enrolled signed mTLS health observers across three hosts. Apache remained the observed backend on each host. The zone was gslb-acceptance.invalid.  
**Scope:** External DNS wire behavior and the merged signed asynchronous agent-report quorum. This is a partial #109 acceptance record, not a production certification.

## Results

| Scenario | DNS authority results (UDP and TCP) | Result |
|---|---|---|
| Three fresh, authenticated reports from three configured vantage groups | Both authorities returned authoritative NOERROR with the configured A address | PASS |
| Stop one observer and allow its report to expire | Both authorities continued returning authoritative NOERROR with the configured A address | PASS; two fresh groups remained |
| Stop a second observer with a distinct vantage group and allow expiry | Both authorities returned authoritative SERVFAIL with no answer | PASS; quorum was below 2 |
| Restart both observers and receive fresh reports | Both authorities returned authoritative NOERROR again | PASS |
| Stop all observers, restart the Osaka DNS authority with its local replay state retained | Both authorities stayed at authoritative SERVFAIL until new reports arrived | PASS |
| Restore the observers after the DNS restart | Both authorities returned authoritative NOERROR after fresh reports were accepted | PASS |

The test queried the public IPs of the two authorities directly. Loopback operator status on each authority showed all three agents fresh at baseline, zero attributed rejected reports, and the expected stale/missing transitions during observer outages. The DNS implementation and its tests came from the stated main commit; the temporary test fixture was generated locally and was not an Actions run.

## Cleanup and limits

All temporary GatewayCore binaries, configs, certificates, state, watchdogs and processes were removed. No AWS security-group, route, Apache, or system service configuration was changed. Post-cleanup checks found Apache active with HTTP 200 on all three hosts, no GatewayCore processes, and ports 53/15444 no longer listening.

This run did not configure or exercise AuthorityFence, a physical DNS-authority network partition, DNSSEC, a public delegated zone, malicious-frame fuzzing, one-hour soak, 500 Mbps capacity, VRRP/ECMP, or a 99.9% availability period. The observer quorum is an independently tested component behavior; it does not complete issue #109. Keep #109 open and production NO-GO pending its remaining acceptance criteria.
