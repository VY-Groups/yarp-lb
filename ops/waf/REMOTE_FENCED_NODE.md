# Authenticated remote WAF node service — software candidate (#51)

**Scope:** An opt-in Linux-only local WAF agent with a separately trusted,
three-member etcd fencing verifier and pinned mutual TLS. The two-host
coordinator calls the fixed `RemoteNodeProvider` API rather than executing
remote commands, SSH or shell. Each participating node checks its **own**
lease at the mutation boundary. No site identity, customer CA, private key,
live policy, production endpoint or customer corpus is stored in the repo.

## Mandatory independent provisioning

1. Deploy a separately administered three-member etcd authority, with
   immutable approved per-member HTTPS host, leaf SHA-256 and numeric
   `memberId`. The independently operated CAS writer must attach a
   bounded live lease to the *exact* approved policy digest, revision and
   node pair. There is no locally generated lease/fallback in the agent.
2. Provision **distinct, purpose-limited** TLS client certs for each
   agent's read-only etcd verifier and the coordinator's agent-client
   connection; provision per-host server certs with SAN and serverAuth.
   Record exact controller and server leaf SHA-256 pins through a separate
   trust channel. Enforce network allowlists outside the agent.
3. On **each** WAF host, independently provision two reviewer P-256 SPKI
   public trust anchors and approvals, a signed WAF mode policy, a trusted
   monotonic floor outside the policy tree, and live shadow evidence for
   block mode. The agent uses `verify_signed_policy.verify` against the
   exact bytes before starting. A signed exception list is *not* silently
   ignored: this adapter refuses it until the signed exception rendering
   workflow is integrated into the effective WAF configuration.
4. Install and run only the approved Linux Docker Compose WAF image and
   exact known health listener. Use a dedicated service identity and an
   owner-only `0700` receipt directory; hold the externally managed etcd
   mTLS key separately from the controller identity. Keep the controller
   unprivileged relative to local Docker and node recovery receipts.

The independently provisioned `--etcd-members` file contains this
schema; the following data is **not a valid production inventory**:

```json
{
  "schemaVersion": 1,
  "fleet": "fleet-ci",
  "clusterId": "999",
  "endpoints": [
    {"url": "https://127.0.0.1:2379", "leafSha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "memberId": 1001},
    {"url": "https://127.0.0.2:2379", "leafSha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "memberId": 1002},
    {"url": "https://127.0.0.3:2379", "leafSha256": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "memberId": 1003}
  ]
}
```

Start the separately reviewed daemon on **each** host using
`ops/waf/waf_node_service.py` with the required flags. To inspect required
inputs without connecting to a production system:

```sh
python3 ops/waf/waf_node_service.py --help
```

The operator supplies --node-id, --node-a, --node-b, --policy, two
--approval files, two --reviewer-key name=public.pem values,
--minimum-revision-file, --observed-ruleset-sha256, optional required
--shadow-evidence-file for block mode, --compose, --image, --health-url,
--project-name, --receipt-dir, --etcd-members, --etcd-ca,
--etcd-certificate, --etcd-private-key, --tls-ca, --tls-certificate,
--tls-private-key, --controller-client-pin, --listen and --port.
Nonloopback bind is *refused* unless --allow-nonloopback is explicitly set.
No flag disables signature, policy expiry, actual image/rule observation
or external fencing verification.

On the controller, create a `RemoteNodeProvider` for each distinct
node with the exact server leaf pin and independently trusted client
mTLS identity; use the two providers with
`two_node_transaction.coordinate(..., fence=EtcdQuorumFence(...))`.
The coordinator itself also requires its own **separately authenticated**
live etcd verifier, not a static signed document or a locally generated
self-signed lease.

## Mutation behavior and deliberate limits

The agent accepts only fixed JSON actions: inspect, rule-digest, config,
smoke and apply with a signed-mode target or verified original rollback.
Every TLS response is bound to the approved server node ID; different
server/client leaf pins, wrong CA, malformed input, excessive payload,
incorrect node ID and revoked quorum do not authorize mutation.

The node also takes a nonblocking, owner-only Linux `flock` around the entire local Docker mutation, post-change verification and receipt commit. A concurrent agent process using the **same approved node receipt directory** cannot run a second mutation in parallel. Independently provision one stable receipt directory per WAF instance; configuring separate directories for the same WAF or allowing an orphan Docker subprocess to outlive the agent remains an operational correctness risk.\n\nThe node writes an exclusive owner-only, fsynced pre-mutation intent whose
name cannot be reused after process failure. A fully verified state
transition also gets a new-only durable result receipt. Both controller
and node retain unresolved journal files on hard crashes rather than
automatically replaying a non-idempotent change. No claim of atomic
distributed commit is made.

**Security gate still outstanding:** quorum attestation is checked
immediately before and after a local Docker operation, but the Docker
provider can remain in-flight while its lease expires or a competing
writer acquires a new epoch. An independently enforced exclusive writer
handoff and bounded operation/lease lifetime must be proven before this
agent can serve a production two-host transactional rollout. If either
host is unreachable or fencing is lost, leave an explicit unresolved
incident for independent reconciliation; never force an unsigned local
override.

The separate signed-exception include-graph activation/expiry, real
multi-host authority renewal/partition tests, Windows upstream integration,
representative native ModSecurity per-request audit custody, false
positive/negative corpus, matched p95/p99/CPU/allocations and rollback
under sustained traffic remain #51 **software acceptance requirements**.
Physical VRRP/ECMP and real-site capacity qualification remain #36.

## Disposable software acceptance

```sh
python3 -m unittest discover -s ops/waf -p test_mtls_fenced_node.py -v
python3 -m unittest discover -s ops/waf -p test_two_node_transaction.py -v
```

This suite generates a disposable real OpenSSL CA, distinct server/client
certificates, and actual localhost HTTPS listeners. It proves denial on
wrong server/client pin and node identity, post-start lease denial before
mutation, replay refusal, per-host durable receipts and two independent
TLS nodes with simulated second-node failure and compensation. Its WAF
provider is a fake local implementation: **not** Docker, a customer node,
a separate OS host, or full production acceptance. CI runs these checks
in `.github/workflows/waf-mtls-node.yml`. The existing real three-process
etcd acceptance workflow remains independently required.
