# Independently authenticated Linux Data Protection recovery authority (#48)

This source adds a **separate** software-only authority candidate for
offline, signed DP key-ring restore. The code deliberately does NOT place
untrusted quorum authority inside the encrypted key ring, the transferred
checkpoint, or a local file supplied by the sender.

`ops/fleet/linux_dp_quorum_authority.py` exposes two distinct opt-in
interfaces:

- `RecoveryLeaseIssuer.issue_once()` runs a pinned-mTLS etcd v3
  `CREATE_REVISION == 0` transaction on a new 60–120-second lease
  **only after** at least two different, independently approved Raft
  members prove the recovery key absent using current linearizable reads.
  A reachable contradictory member vetoes the request. It never steals
  an existing lease or auto-renews an epoch. If post-CAS quorum attestation
  fails, it attempts to revoke only its own newly issued lease.
- `RecoveryFence.current(phase)` performs fresh linearizable TLS-pinned
  reads and lease TTL checks on the actual etcd members, validates their
  distinct approved member IDs, and rejects absent/replayed/replaced
  epochs, incorrect revision, foreign node IDs, expired leases and
  checkpoint mismatch. Every phase uses the same pinned original epoch;
  a stale earlier TTL response never overrides the newest decision.

All quorum metadata is scoped to
`/gatewaycore/linux-dp/recovery/<fleet>` and cannot be confused with
the separate WAF authority. The value schema is `schemaVersion=1`,
`kind="linux-dp"`, exact `senderNodeId`, `receiverNodeId`,
monotonically approved `revision`, SHA-256 of the externally approved
actual P-256 signed checkpoint bytes and a new 128-bit random holder.
**Never** use the hash alone instead of checking the P-256 signature
and independent external recovery revision floor. The existing
`LinuxDpEncryptedSnapshot` tool is still responsible for cryptographic
signature verification and restoring only into a previously absent
offline state directory.

## Support and trust boundary

An independently managed real three-member etcd cluster must enforce
TLS1.2+ CA and hostname checks, exact per-member certificate SHA-256
leaf pins and separately approved numeric Raft member IDs. Issue and
verification must use distinct narrowly scoped mTLS identities and
independently provisioned certificates. Never put the etcd private keys,
wrapping PFX, operator signer, signed customer checkpoint or live node
identity in the repository, CI artifacts, logs or a downloaded installer.

This library is **not yet invoked by the offline receiver** and has no
headless service-writer stop or runtime-promotion authority. It cannot
guarantee that an in-flight process or prior gateway has quiesced when
the lease expires, so a successful synthetic CAS test is not a live
fleet anti-split-brain acceptance. No override, local fallback,
emergency key export or production promotion path is provided.
Before #48 closure, integrate the fenced issuer/verifier with the
actual receiver and independently signed checkpoint; prove callback
order at all real restore boundaries, real three-member TLS partition
and lease rollover, service stop/restart and original cookie continuity
across separately authorized Windows/Linux identities. Physical
two-host and site-level exercises are #36.

## Reproducible current unit contracts

```sh
python3 -m unittest discover -s ops/fleet \
  -p test_linux_dp_quorum_authority.py -v
```

The fast Python tests use a mocked etcd transport for deliberate
split-brain, stale TTL, bad member/leaf pin, conflicting checkpoint,
namespace mismatch and CAS-replay fault injection. In addition,
`.github/workflows/waf-etcd-quorum.yml` starts an actual disposable
three-process etcd TLS Raft cluster; its extended `real_quorum.py`
executes **this DP authority** against those real endpoints, including
CAS write, separate read-only mTLS verifier, competing lease rejection,
revocation, epoch rollover and proof that a DP lease does not modify the
unrelated WAF lease. These real tests are required, not replaceable by
synthetic JSON assertions.

Neither disposable CI harness proves independently housed customer
servers, a production issuer/private-key store, external signer
custody, .NET receiver promotion or physical partition recovery.
`.github/workflows/linux-dp-quorum-authority.yml` separately
runs the synthetic contracts; the original key encryption, signed
restore, and Windows/Ubuntu service acceptance remain mandatory.
The actual receiver has **not** yet been wired to require this lease
at all recovery phases.
