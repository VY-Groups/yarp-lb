# EC2-backed functional checks — real Control Center gateway

Workflow: `.github/workflows/ec2-real-control-center.yml`. Entry points are **Actions → EC2-backed real Control Center functional checks → Run workflow** and the 00:30 IST nightly schedule. There are intentionally no pull-request/push triggers; no EC2 requests are made as part of source-code PR CI.

## Repository variables (Settings → Secrets and variables → Actions → Variables)

```text
BACKEND_A_HOST=ec2-3-108-65-15.ap-south-1.compute.amazonaws.com
BACKEND_B_HOST=ec2-65-0-11-186.ap-south-1.compute.amazonaws.com
```

These must be ordinary repository *variables*, not secrets. There are no AWS tokens, EC2 credentials, SSH keys, remote shell commands, destructive backend operations or deployments. If either backend is inaccessible, body identity is missing, or both return the same identity, the preflight **fails with BACKEND_UNREACHABLE** and the gateway build/load stages do not run.

A backend must return **HTTP 200 at /** and a body containing `backend <hostname> <time>`; each is fetched directly five times first. For the strict/relaxed TLS negative controls, both need an HTTPS listener serving a self-signed/untrusted certificate on port 443.

## Real product, not GatewayLab

GitHub Actions builds `control-center/SpeedSignYarp.csproj` from the checked-out SHA and runs `SpeedSignYarp.dll` on 127.0.0.1:18088. `tests/EC2Functional/ec2_functional.py` writes **the real application appsettings.json**, with hot reload enabled. It checks `/gateway/health` and uses the real cluster and load-balancing policies. A special GitHub-only, local-only compatibility mode stores ephemeral ASP.NET Data Protection keys outside ProgramData, solely so the Windows-first product can boot on the disposable Ubuntu runner. Normal production Windows DPAPI remains unchanged.

Security: admin paths remain loopback restricted; the CI never creates a real admin. The only certificate-relaxation path demands all of `GITHUB_ACTIONS=true`, `CI=true`, `YARP_EC2_LAB_MODE=1`, an explicit 127.0.0.1 HTTP bind, **both exact known hostname variables**, and an independent `YARP_EC2_LAB_TLS_RISK_ACK=1`. The handler validates the current config has **exactly two HTTPS root destinations at the allowlisted EC2 hosts** before disabling backend certificate verification, and logs a prominent warning. Without the flag, TLS verification is normal. Never deploy the test mode, test private keys or relaxed TLS in production or CA/eSign infrastructure.

## Traffic limits and test design

The harness enforces **8 maximum client worker threads**, **15-second per-request timeout**, **1,000 test-initiated HTTP requests per named test** and **8,000 total budgeted test requests** including preflight. Requests made independently by YARP's active health probes are included in gateway telemetry but not the harness's test-initiated budget; do not mistake that budget for an absolute EC2 ingress-count limit.

- **Preflight:** 5 direct HTTP 200 / correct-format responses to each backend; distinct backend identities.
- **T1:** 1,000 50/50 weighted random traffic; require 450–550 per backend.
- **T2:** independent 1,000-request 70/30 and 90/10 measurements; require backend A in 650–750 and 870–930 respectively.
- **T3:** 40 source IPs using actual `curl --interface 127.0.0.2` through `127.0.0.41`, 10 per address. Ensure stable rendezvous affinity, 11–29 IPs on each backend, unchanged mapping under spoofed `X-Forwarded-For`, no failures/reassignments of A addresses when B is removed from **live** config, then exact previous mapping after B is restored.
- **T4:** individually test 127.0.0.1:9 refused, an EC2 hostname port 81 blackhole, and an EC2 hostname port 22 invalid protocol. Generate at up to 20 requests/sec before `/gateway/metrics` shows bad destination active-health = -1; assert detection within 10, 15 and 15 seconds. Record any failures before ejection and require 300 consecutive identity-correct responses afterwards.
- **T5:** eight strict-validation HTTPS calls must fail with 502/503 and logged certificate errors, then prove the test-only bypass cannot activate without the independent risk ACK. Restart the real gateway with the approved loopback-only bypass and require another 1,000 requests within the 45–55% equal split. A bypass warning must be logged.
- **T6:** hot-change the real config from 50/50 to 90/10 at t=20s, require zero errors and 85–95% A share over the final 30s. **Constraint resolution:** 20 req/s × 60s = **1,200**, directly contradicting the hard **1,000 requests per test** cap. We preserve the safety cap and run **16 requests/sec for 60 seconds = 960 requests**. Measured latency is recorded, never used for pass/fail because GitHub runners are geographically remote from Mumbai.

Every named test writes one CSV with `timestamp,client_address,status,backend,latency_ms,error`, plus a complete JSON summary and GitHub Actions job-summary markdown. Artifacts are uploaded even on failure, retained for seven days. The job exits nonzero on any failed assertion. No synthetic "PASS" is reported without the completed Actions run and its artifacts.

## Explicitly NOT TESTED

- A real EC2 backend crash and recovery (no remote mutation allowed)
- Gateway process failover
- Performance/capacity SLAs (runner distance and variability make latency an observation only)
- Multi-host active–active HA, WAN partition tolerance or production certification

## Evidence status

Offline code/tests are checked in source-control CI. **The live EC2 workflow must be manually run or reach its scheduled execution before any EC2 functional scenario can truthfully be marked PASS.** GitHub connector API currently used in this conversation does not expose an Actions workflow-dispatch operation; do not substitute a PR/push trigger or claim an EC2 result without a run link. 
