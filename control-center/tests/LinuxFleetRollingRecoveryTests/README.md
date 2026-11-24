# Linux fleet: staged certificate rotation and lost-key DR software rehearsal

This is a **real .NET 10 Data Protection** multi-process acceptance in two
separately provisioned **private Linux state roots**. It does not claim to be
two physical servers or to complete an active-active site failover.

The test and its production-relevant sequence are:

1. Source gateway A mints an old authentication cookie with an RSA 3072+,
   non-CA key-encipherment certificate, in its own .NET process.
2. Independently install the same *authorized* PFX in a separate owner-only
   secret directory on gateway B, with encrypted key XML staged using
   no-overwrite file inventory verification; B decrypts the original cookie
   in a new .NET process.
3. Pre-stage new+old certificate overlap on B while A remains old-only.
   Both can still read old sessions. Next stage new+old on A, then the
   designated source writer creates **one new key** with a later activation
   time. Wait for activation before issuing new sessions.
4. Replicate new ciphertext-only key XML to B (never overwrite/diverge).
   Fresh provider processes on A and B must decrypt both old and new cookies.
   The new token must refer to a **different actual Data Protection key ID**.
5. A rollback to the old certificate *retains the newly issued certificate as
   a decryption key*: old and new sessions must remain readable.
6. Remove B's previous wrapping PFX to simulate lost-key recovery. The
   intended overlapping configuration must fail closed. Restore encrypted
   PFX ciphertext from an independent protected 0700/0600 escrow root and
   verify that both generations of sessions can again be decrypted.
7. A provider using a different application isolation name must reject
   the same old cookie.

All PFX and password files in this test are ephemeral, private and
created within disposable GitHub Ubuntu runners; cookies are transmitted
to child processes by stdin and read from private pipes, never logged
or placed into command-line arguments.

**Limits:** These are separate OS processes but execute under the same
disposable CI user and on one runner. The test does *not* establish
network-safe two-host distribution, live health/traffic admission,
continuous writer/quorum fencing for rotation, loss of both active
wrapping keys, or recovery of an independently housed KMS/HSM. Service
traffic cutover while all gateways are actively serving, certified
signed rollout/rollback, and multi-host authorization still require
further software and operations acceptance before closing #48.
Physical two-host and site/SELinux proof stays under #36.

Run the CI contract via
`.github/workflows/linux-dp-fleet-rolling-dr.yml`; it is additionally
gated in the full Control Center Ubuntu job. It must not be run against
a production identity, real fleet key ring or customer certificate.

### Live HTTP rolling-restart rehearsal

The disposable CI fixture now starts two actual Kestrel child processes with real ASP.NET Core cookie authentication and distinct private key rings. It issues an old cookie, performs continuous authenticated requests while each node is drained, stopped, staged and restarted in turn, and verifies both old and newly rotated cookies on both nodes after staging. Requests are not retried. The harness explicitly serializes admission changes with in-flight probes; it does not exercise the product gateway's routing/drain API or concurrent new-login traffic during staging. It is a software rehearsal, not a physical-host, live writer quorum or full zero-downtime fleet acceptance assertion.

### Shipping YARP drain and active login traffic

The fixture builds and starts the actual shipping GatewayCore executable in Production mode with its own private state. It routes the cookie workload through a real RoundRobin proxy route and applies atomic private JSON configuration reloads with TrafficState=draining/active. Backend identity response headers prove both nodes are used and the drained node is excluded before its process stops. Continuous old-cookie requests and new-cookie issuance/verification run through the proxy throughout rotation, including a new-key cookie minted before the second node is restarted. The harness requires no request failures and verifies both cookie generations after convergence. This uses the shipping data plane and drain metadata, not the management approval API, a physical VIP or distributed writer/secret provisioning in the same test. Independent combined acceptance remains required.
