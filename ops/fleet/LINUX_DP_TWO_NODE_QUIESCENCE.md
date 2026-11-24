# Two independently signed Linux Data Protection writer stop receipts (#48)

The previously merged DP recovery verifier established **read-only**
authorization against a distinct pinned three-member etcd Raft quorum, but
a valid lease alone did **not** prove source/destination service writers
stopped. This change requires **two different P-256 key identities** to
witness a stopped, runtime-masked local service under the exact same
approved DP recovery epoch before a nonloopback snapshot can be received.

## Operator actions, bounded offline only

1. Separately authorize a P-256 signed encrypted key-ring checkpoint,
   independently verified revision high-water, exact source/receiver
   identities and mTLS etcd quorum. Issue a new CAS DP recovery lease.
2. On each actual authorized Linux host, provision a different owner-private
   P-256 *signing* identity (not the wrapping key, TLS key, etcd writer key
   or checkpoint signer). Provision its public PEM on the receiving operator
   host in a distinct owner-private trust directory.
3. On each host independently call the privileged **offline** source-writer
   guard with that host's separately approved immutable systemd unit list:
   `python3 ops/fleet/linux_dp_quiescence.py --approved-offline
   --fleet-quorum-inventory /secure/etcd-members.json --fleet fleet-ci
   --sender-node-id gateway-a --receiver-node-id gateway-b
   --recovery-revision 43 --checkpoint-sha256 <APPROVED_CHECKPOINT_SHA256>
   --etcd-ca /secure/etcd/ca.pem
   --etcd-certificate /secure/etcd/reader.pem
   --etcd-private-key /secure/etcd/reader.key --node-id gateway-a
   --signing-private-key /secure/node-a/p256.key
   --output-receipt /secure/node-a/stop.receipt
   --writer-unit gatewaycore.service`.
   Repeat on gateway-b with its own distinct P-256 key/receipt and
   `--node-id gateway-b`; never reuse node-a's private identity.
4. Each guard calls the **real** Linux systemd manager with an explicit,
   sorted, allowlisted unit list: stop, `mask --runtime`, then inspect
   `ActiveState=inactive`, `SubState=dead`, `MainPID=0`, masked
   `UnitFileState`, a present unit, and `KillMode=control-group` or
   `KillMode=mixed`. `KillMode=process` or `none` can strand child
   key-ring writers even when the main PID has exited, so such units must
   be independently remediated before a receipt can be signed. After a fresh etcd quorum check,
   it creates an owner-only, new-only P-256 signature over the exact
   cluster/lease/holder, fleet, two node IDs, checkpoint SHA, revision,
   stopped units and at most 90 seconds of wall-clock validity.
   It never auto-unmasks a failed recovery; independent operator
   reconciliation is required.
5. Separately stage the two different signed receipts and pinned public
   PEM keys under owner-private directories outside the untrusted
   restore inbox, output state and approved executable bundle.
   A non-loopback `linux_dp_receive_restore.py` now requires these
   additional flags:
   `--sender-quiescence-receipt /secure/authority/a.receipt
   --receiver-quiescence-receipt /secure/authority/b.receipt
   --sender-quiescence-public-key /secure/authority/a.pub
   --receiver-quiescence-public-key /secure/authority/b.pub
   --sender-writer-units gatewaycore.service
   --receiver-writer-units gatewaycore.service`.
   It verifies *both* independent actual P-256 signatures and their
   exact source/receiver service inventory, nonce and revision at
   preflight, before and after transfer, before .NET signed restore and
   after restore. Missing, stale, duplicated, invalid or partial
   proof fails **before** network or production promotion.

## Real tests and boundaries

The dedicated Actions workflow
`.github/workflows/linux-dp-quiescence.yml` runs real disposable
OpenSSL P-256 key pairs and signatures, different node identities,
exact-epoch replay/tamper, live authenticated lease loss, missing/active
writer state, malformed units and remote receiver entry-point refusal.
The second job starts a real temporary systemd writer unit on an
isolated Ubuntu 24.04 runner, calls the actual stop and runtime-mask
commands, then confirms the unit's inactive/masked state and MainPID=0.
The independent 3-member real-etcd P256 recovery authority tests
remain required; the quiescence cryptographic fixtures use a fake
etcd method to inject negative transitions, not fake signatures.

**Not a production promotion contract:** a signed receipt proves that a
specific independently provisioned host identity attested to its
specified systemd unit state at the signed time. It cannot prove all
possible undocumented writers were included or prevent an authorized
local administrator from deliberately unmasking/restarting a unit
after signing. No automatic source/target lock renewal, zero-downtime
traffic drain, failover decision, durable multi-host promotion or
Windows SCM receipt equivalent is implemented by these helpers.
Owner must complete independent service role admission and
cross-service staged rotation/rollback before software #48 is
declared completed. Real two-host/customer environment verification
and SELinux host acceptance remain exclusively under #36.


### Unit-file precedence matters

A systemd `mask --runtime` command exiting zero **does not** prove
the effective unit is masked. Some administrator-installed unit files
under `/etc/systemd/system` can take precedence over the runtime
`/run/systemd/system` mask on the target manager. This was observed
in the real Ubuntu CI fixture: the actual service had
`ActiveState=inactive` and `MainPID=0` but still reported
`UnitFileState=disabled` after `mask --runtime` and daemon reload.
The witness correctly refused to sign that false fence.

The supported issuance path checks the **effective** `UnitFileState`,
`LoadState`, active/sub state and PID through the actual manager
after a fresh daemon reload. A packaged vendor unit with a lower
precedence definition can be runtime-masked; an incompatible custom
`/etc` unit is **NOT SUPPORTED** for this method and must use a
separately reviewed fail-closed host fencing implementation. Do not
substitute `mask --force`, rewrite existing administrator units, or
treat `disabled` as equivalent to `masked`. Even a signed witness
cannot protect against authorized administrator changes after issuance;
this remains an explicit operational/authority integration limit.

## Composed real cryptographic restore regression (PR #518)

The disposable `LinuxKeyProtectionTests` now drives
`linux_dp_real_restore_e2e.py` through the **same** source/receiver code
path used by the remote receiver. It creates distinct genuine OpenSSL
P-256 node signing keys, exact-epoch signed quiescence receipts, a private
CA plus mutually authenticated TLS sender/receiver certificates, an
actual certificate-wrapped key ring with an independent P-256 signed
checkpoint, and executes the published **real .NET 10** signed restore.
The test asserts all five recovery quorum phase callbacks, validates
the original cookie in a fresh .NET process, and refuses duplicate
non-overwriting restores.

**Test boundary:** only node receipt signatures, encrypted mTLS transfer,
snapshot verifier, original-cookie decrypt and execution are real. The
quorum phase responses are a deterministic test oracle, not an actual
three-member live etcd partition; systemd stop/mask responses are a
test fixture, not two independent hosts. Those separate actual etcd and
Ubuntu systemd tests remain mandatory. These tests may not be combined
into a claim of certified site-level HA or automatic production promotion.

P-256 signer public keys must have canonical uncompressed
`prime256v1` DER SubjectPublicKeyInfo. A separate curve or SPKI with
embedded matching OID bytes, compressed point, trailing bytes or
malformed ASN.1 fails before any writer service changes. Writer units
also require `KillMode=control-group` or `mixed`; merely stopped
`MainPID=0` under `KillMode=process` or `none` is not proof that
descendant key-ring writers stopped.

## Live quorum supervision while .NET restores a signed offline ring

The real remote receiver now calls
`ops/fleet/linux_dp_restore_watchdog.py` for the actual .NET 10 restore.
It launches the approved, tree-hash-pinned restore executable in a new
private POSIX process session, keeps stdout/stderr suppressed, and requires
fresh majority-quorum `before-signed-restore` reads and **both** original
P-256 signed writer receipts between bounded subprocess waits. Each
running-process Raft/receipt probe has an additional **three-second hard
supervisor budget**; a stuck HTTPS/quorum read fails closed and terminates
the entire restore process group rather than delaying cancellation until
sequential etcd member socket timeouts have elapsed. It never extends the independently approved epoch.

A majority-veto, changed Raft lease identity, expired signature, insufficient
runway, killed child, nonzero exit or watchdog deadline stops the entire
process group with SIGKILL. Both pre-launch and post-completion checks remain
mandatory. After an aborted restore, the ring is **NOT accepted as a live
node** even if the .NET helper had created a partial or complete offline
directory before being terminated. An independent operator must quarantine
and reconcile its inode, signed checkpoint and monotonic floor; the script
never auto-deletes a potentially trusted ring or unmasks gateway writers.

The disposable watchdog tests use actual Linux subprocesses and verify that
revocation and timeouts kill the worker before a delayed unauthorized disk
write. The complete real mTLS + P-256 signed checkpoint + .NET restore test
exercises the same watchdog call, but intentionally supplies a deterministic
quorum response oracle; this is **not** an independent live Raft failover test.
Other real 3-member TLS etcd and actual Ubuntu systemd service tests must also
pass. A local root administrator can defeat a local process controller; a
production threat model must physically separate the independent quorum and
writer-identity authorities.

This protects the offline restore process during the finite authorized
window; it does **not** implement rolling service handoff, extended automatic
lease renewal, enterprise signing-key custody or a zero-downtime promotion
decision. Those remain software obligations under #48, with real-site
acceptance reserved for #36.
