# Independently pinned etcd WAF CAS lease issuance (#51)

`ops/waf/etcd_cas_writer.py` supplies the previously missing
**one-shot authenticated authority writer** for a specifically approved
two-node WAF policy. It is a Python library, NOT a self-approving CLI,
lease-renewal service or production rollout controller. The privileged
caller must first verify both independent P-256 policy approvals, the
external monotonic revision floor and the approved ruleset digest using
`verify_signed_policy.py`. No software grants itself an approval.

## Trust and consistency

The writer uses **three distinct** operator-approved etcd endpoints,
each specifying hostname, exact 64-hex TLS leaf pin and independently
approved Raft member ID. HTTPS verifies CA and hostname plus leaf pin,
with a distinct local client-auth private key. It performs a current,
linearizable (`serializable:false`) read against all available members
before writing. At least two distinct trusted members must confirm the
lease key is **ABSENT**, and any reachable authenticated member which
disagrees with the approved identity or shows a pre-existing owner vetoes
the entire grant. A third node is never silently used as a substitute for
an invalid or contradicting member.

The writer grants an etcd TTL of **60–120 seconds**, then performs a
single atomic etcd Raft transaction comparing `CREATE_REVISION == 0`
before inserting a JSON value that contains the exact signed policy SHA,
approved node IDs, revision and freshly random 128-bit holder. It does
**not** update, revoke or steal an existing lease. A CAS race fails
closed. After a reported CAS success it performs the existing verifier's
fresh 2/3 read and TTL checks and binds exact holder and granted lease ID.
A failed post-CAS attestation attempts to revoke only the writer's newly
issued lease; when revocation cannot reach quorum, natural expiry is the
bounded fallback and **the incident is not reported as success**.

The writer's return record identifies the issued epoch. Treat this record
as sensitive operator evidence and never upload production holder IDs,
network details or operator certificates to CI. The agent and coordinator
each use independent *read-only* etcd identities to revalidate the epoch
and certificate/member bindings before mutations.

## Application limitation: renewal, expiry and handoff

This primitive deliberately does **not** renew a lease or transfer the
fence to another controller. Issuing a 120-second lease is not sufficient
to prove safe multi-minute Docker deployment, and an old local mutation
may remain in-flight after TTL expiry. The final software acceptance
still requires an independently reviewed renewing CAS authority,
durable epoch/intent records, authority handoff which waits for both
node agents to drain in-flight operations, crash recovery, expired-lease
fencing across every remote mutation, and live rollback integration.
Do not reuse a prior holder for a new grant or allow a new controller
to mutate nodes until their prior in-flight state is reconciled.

These unresolved requirements remain under #51, **not #36**. Physical
multi-host network tests, real site WAF corpus and traffic remain
separate operational acceptance. The new library is not permission to
close #51 or declare a release production GO.

## Acceptance

```sh
python3 -m unittest discover -s ops/waf -p test_etcd_cas_writer.py -v
python3 -m unittest discover -s ops/waf -p test_etcd_quorum_fence.py -v
```

The existing real three-process etcd TLS CI under
`.github/workflows/waf-etcd-quorum.yml` now uses the *same writer
implementation* to issue an actual Raft CAS lease, verifies a conflicting
writer cannot replace it, revokes it, rejects old-epoch mutation and
confirms a 2-of-3 outage denies authority. Synthetic and real disposable
runner evidence are not customer-site or physically independent host proof.
