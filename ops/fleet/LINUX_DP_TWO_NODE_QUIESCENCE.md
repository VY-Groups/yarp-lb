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
