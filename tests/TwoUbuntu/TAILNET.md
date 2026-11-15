# Optional manual two-VM private-overlay gateway failover test

The `.github/workflows/two-ubuntu-tailnet-failover.yml` workflow runs two **separate GitHub-hosted Ubuntu 24.04 virtual machines**, each hosting the actual GatewayCore application and two disposable HTTP website origins. It is intentionally **manual only** for live networking. The pull-request validation job checks scripts and target-address restrictions without requiring credentials.

## Required one-time network setup

Configure the repository's **encrypted Actions secrets** `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` for an appropriately scoped Tailscale OAuth client with `auth_keys` write permissions and a configured `tag:ci`. Restrict your Tailscale ACL/grants so the ephemeral CI-tagged nodes can talk **only to other CI-tagged nodes** on TCP 18080; deny access to production/admin/CA resources. Protect workflow dispatch permissions. Do not paste secrets into YAML, logs or chat.

The `tailscale/github-action@v4` action makes short-lived ephemeral nodes. Both GatewayCore containers bind their ports only on their host's Tailscale 100.64/10 interface, never publicly. The workflow publishes only ephemeral private IP and commit ID via same-run GitHub artifacts; the other job retrieves those artifacts with read-only `GITHUB_TOKEN`. A control artifact causes node A to `SIGKILL` its own **disposable** gateway container, then restore it on a later control artifact. No remote shell or privileged public control endpoint is created.

On node B an independent HAProxy executable acts as ingress for the two real VM IPs, using active `/gateway/health` probes. The test records *absolute failed requests*, the last failure offset from the start of the post-kill observation window, a final error-free tail, and direct node A/B availability before/after restart. No non-idempotent request retries are attempted.

## Evidence limitations

- This is a **cross-VM encrypted overlay simulation**, not a real VRRP VIP, BGP ECMP, LACP/physical NIC, production firewall, switch-fault, customer certificate, or on-prem power-loss test.
- The ingress and traffic-generator processes run on VM B. HAProxy may use direct WireGuard or relay through DERP depending on runner networking. Neither case reproduces your site's throughput or latency guarantees.
- The workflow doesn't issue 750 Mbps of 60-minute body traffic. The separate `two-ubuntu-gateway-load.yml` workflow can run a 60-minute *per-VM synthetic localhost* test, also not physical acceptance.
- Both workflows remain fail-closed on missing setup or failed commands. A pending/unexecuted manual workflow is **NOT TESTED**, never GO.

Sources: https://github.com/tailscale/github-action and https://www.haproxy.org/.

Your v1 physical readiness requirements in `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md` continue to apply.
