# One-shot authenticated Linux DP receive and signed restore (#48)

`ops/fleet/linux_dp_receive_restore.py` is an **explicit offline**
receiver which composes the already pinned mutual-TLS ciphertext transport
with the independently verified .NET 10 `LinuxDpEncryptedSnapshot restore`
command. It does not copy private RSA wrapping keys, sign a new recovery
manifest, advance the external revision floor, replay user cookies,
authorize an unfenced destination or start/promo a live gateway.

## Preconditions (must be proven independently)

- All Data Protection writers are stopped and **independently fenced** on
  source and target nodes. This tool neither negotiates quorum nor stops
  service-manager processes. A sender with a valid TLS certificate does not
  prove the snapshot's signer or revision.
- Independently issue a genuine **P-256 signed checkpoint** over the
  encrypted snapshot, approve a monotonic external high-water revision,
  and protect both the SPKI verification public key and revision floor
  outside the untrusted receiving archive. Keep the wrapping private key
  in a separately approved service identity/PKI store, not in the transport.
- Provision an owner-only 0700 receiving archive root and a distinct,
  still-offline 0700 destination Control Plane state root with NO
  `data-protection-keys` entry. Both must be disjoint from the exact
  externally approved .NET executable bundle.
- Publish the .NET 10 restore apphost into a trusted directory, with
  `LinuxDpEncryptedSnapshot` as executable and all framework-dependent
  DLL/deps/runtime-config files present. Do not run `dotnet run`, NuGet
  restore, a downloaded shell script, arbitrary command or a sender-supplied
  binary during recovery. Independently approve the exact canonical
  **complete directory tree** SHA-256 before starting. The receiver rejects
  symlinks, linked files, group/other-writable directories or files, and
  changes to the bundle before or after execution. The SHA domain is
  `GatewayCore.LinuxDp.PublishedRestoreBundle.v1\n`, followed by sorted
  UTF-8 member names and contents length-prefixed as in `tree_hash`.
- Separately provision distinct TLS client/server identities with CA,
  hostname and exact approved leaf SHA-256 pins. Restrict the TLS
  listener to a private ACL; require the source's explicit opt-in for any
  nonloopback listening address.

## Approved operator invocation

Example arguments shown here are placeholders, not a real identity.
Run only after recording a separate, authorized change:

```sh
python3 ops/fleet/linux_dp_receive_restore.py \
  --approved-offline \
  --server-url https://10.0.0.11:17443 \
  --server-cert-sha256 REPLACE_WITH_APPROVED_64_UPPER_HEX_LEAF \
  --destination-root /secure/dp-inbox \
  --state-root /var/lib/gatewaycore-yarp/offline-recovery-state \
  --label rev43 \
  --ca /secure/operator-pki/root.pem \
  --certificate /secure/operator-pki/receiver.pem \
  --private-key /secure/operator-pki/receiver.key \
  --trusted-public-key /secure/recovery-authority/trusted-verifier.pem \
  --minimum-revision-file /secure/recovery-authority/min-revision.txt \
  --restore-bundle /opt/gatewaycore/offline-dp-restore \
  --restore-bundle-sha256 REPLACE_WITH_APPROVED_64_UPPER_HEX_BUNDLE \
  --dotnet-runtime-root /usr/share/dotnet
```

There is no headless live deployment action, implicit recovery retry or
fail-open fallback. The TLS server cert is checked against both the CA/SAN
and exact leaf pin; the received bounded ZIP is non-overwriting and private.
The verified bytes land under `/secure/dp-inbox/rev43`. The signed,
still-untrusted checkpoint is **also** written atomically without overwrite
as owner-only `/secure/dp-inbox/.rev43.signed-checkpoint.json`: outside
the `rev43` snapshot state tree, because the independent .NET verifier
correctly refuses using any checkpoint from inside that tree to
self-authorize a restore. Only a valid P-256 signature under the separately
provisioned trusted verifier and external high-water floor can authenticate
this separate copy. The receiver never trusts the backup's checkpoint
simply because of its physical location. Only then is the
approved local .NET apphost executed with a fixed argument list, no shell,
bounded timeout and no private stdout/stderr collection. It must enforce
the **real** P-256 inventory signature and minimum revision; the Python
transport deliberately does not accept the manifest on the sender's claim.

An unsuccessful process exit or absent/unsafe restored encrypted key ring
is an error. The archived transfer may remain for incident review, but no
existing live DP ring is modified or overwritten. Even a successful offline
ring restore does not authorize it to be mounted by a gateway; wrapping-key
custody, multi-host cookie continuity, trust-floor commit, downstream
service restart and staged promotion must all pass an independently
reviewed runbook.

## Acceptance status

```sh
python3 -m unittest discover -s ops/fleet -p test_linux_dp_receive_restore.py -v
```

The new tests exercise **process orchestration and negative conditions**
with a deliberately synthetic fake restore subprocess: never mistake this
for a real cryptographic checkpoint or .NET acceptance. The separately
existing `LinuxKeyProtectionTests` runs the real .NET backup/signed
restore and cookie-continuity cases, and
`test_linux_dp_mtls_transport.py` runs real disposable OpenSSL mutual
TLS. A combined real two-host end-to-end restore and fleet promotion has
**not** been executed or implemented. Additional software work under #48:
authenticated fleet-wide quiescence/authority and transactional service
promotion, protected trust-floor commit, mixed Windows DPAPI/certificate
migration, secure identity rotation and lost-key/DR recovery. Physical
independent-host, service account, SELinux and site acceptance stay #36.

CI running these separate tests is NOT production GO or permission to
close #48.


## Combined cryptographic acceptance (disposable Linux CI, not site DR)

The actual `control-center/tests/LinuxKeyProtectionTests` suite now
invokes `ops/fleet/linux_dp_real_restore_e2e.py` after creating a
genuine RSA certificate-wrapped Linux Data Protection ring, issuing a
separate P-256 signed inventory checkpoint and committing its protected
external revision floor. It creates a real temporary OpenSSL CA and
different sender/receiver TLS leaf certificates, authenticates both
directions, downloads the encrypted snapshot through the real socket,
executes the **actual previously built .NET 10 apphost** rather than a
mock process, and checks the installed ring inventory matches the
original signed source. The test then starts a fresh .NET OS process
with independent recovery trust/floor and checks that the exact
original protected session remains decryptable. A second transfer is
denied without overwriting archive or destination. CI does not output
TLS private keys, auth cookies, checkpoint bytes or decrypted material.

The previous transport-only and mock process-contract regressions are
still run separately. Their PASS cannot replace this combined test.
The combined test is performed on a disposable **single Linux runner**:
it does not prove two different server service identities, actual
Windows DPAPI migration, cross-node trust-floor distribution, an
independently renewing fencing authority, real host key ACLs or
DR failover. Those missing SOFTWARE components stay under #48.

### Independent .NET runtime-root approval

For framework-dependent `.NET 10` apphosts installed outside the default
system runtime discovery locations, supply `--dotnet-runtime-root` only
after the receiver operator has approved the local installed .NET runtime.
The root must be absolute, non-symlinked, owned by the system or current
service identity, non-writable by groups/other users, and contain a single-
linked executable `dotnet` host of the approved ownership/mode. A
specially crafted inherited `DOTNET_ROOT` or `DOTNET_ROOT_X64` is
**never** forwarded to the signed recovery process. The receiver sets
both to the independently supplied and validated root, or omits both
and uses the system apphost discovery mechanism. It does not accept
a downloaded runtime from the snapshot sender. The disposable runner
resolves the actual host executable from its own installed image, then
passes that trust-bound root explicitly rather than copying a mutable
process environment.

Always confirm the .NET runtime version and vendor provenance during
offline installation or service-account provisioning; a protected path
alone is not a binary code-signing attestation. This is a software
recovery integration control, not production site DR evidence.


## Required external quorum for cross-host recovery

Any non-loopback sender URL requires ALL of these additional, independently
provisioned flags. A lone `--approved-offline` or trusted TLS leaf fingerprint
**cannot** authorize fleet recovery:

```sh
  --fleet-quorum-inventory /secure/authority/dp-etcd-members.json \
  --fleet fleet-prod \
  --sender-node-id gateway-a \
  --receiver-node-id gateway-b \
  --recovery-revision 43 \
  --checkpoint-sha256 REPLACE_WITH_INDEPENDENTLY_APPROVED_P256_CHECKPOINT_SHA256 \
  --etcd-ca /secure/etcd-reader/root.pem \
  --etcd-certificate /secure/etcd-reader/client.pem \
  --etcd-private-key /secure/etcd-reader/client.key
```

The owner-private, independently held JSON inventory uses this exact
schema (illustrative placeholder values, **not** real cluster identities):

```json
{
  "schemaVersion": 1,
  "fleet": "fleet-prod",
  "clusterId": "999",
  "endpoints": [
    {"url":"https://127.0.0.1:2379","leafSha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","memberId":1001},
    {"url":"https://127.0.0.2:2379","leafSha256":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","memberId":1002},
    {"url":"https://127.0.0.3:2379","leafSha256":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC","memberId":1003}
  ]
}
```

The source operator must separately verify the independently issued
P-256 signed checkpoint and epoch **before** provisioning the lease:
`RecoveryLeaseIssuer.issue_once()` can issue a one-shot CAS epoch but
does not sign a checkpoint, export a wrapping key, stop an active
service, renew a lease or make a gateway eligible for promotion.
The receiver's read-only etcd credential must be distinct from the
issuer's privileged CAS writer identity.

The receiver verifies a fresh pinned etcd majority and unchanged epoch
at these boundaries: preflight, before-transfer, after-transfer,
before-signed-restore and after-signed-restore. It verifies that the
checkpoint received via mTLS has exactly the SHA-256 digest bound into
the approved epoch and delegates the actual P-256 validation to .NET.
All external authority files must be disjoint from the inbox, restored
state and approved application executable tree. No successful return
is allowed if the epoch changed or lost majority even *after* the
offline restore command.

**Operation deadline:** the signed .NET restore subprocess is bounded
by the current live quorum verifier's EARLIEST accepted etcd lease
expiry, reserving at least five seconds for post-run verification. A
lease with under ten seconds of trusted remaining runway cannot start
the restore. The environment cannot override this deadline, and a
timeout is an incident, never successful fleet admission. The
`remaining_seconds()` value is cleared after any unsuccessful quorum
check; it cannot be reused from a previously healthy epoch. Unlike a
local offline test-only restore, cross-host recovery cannot take the
unbounded default 180-second subprocess allowance.

**Crash/expiry limit:** even when an after-restore check fails, a
ciphertext key ring might already have been installed in the
intentionally offline staging root. It is NOT a production gateway and
must remain quarantined for independently authorized reconciliation.
The currently bounded one-shot lease does not guarantee that a long
restore operation completes within TTL. The final software acceptance
must include renewable authority/transfer handoff or a strongly
bounded operation window, separately authenticated writer quiescence,
source+destination two-node role fencing, audited rotation/rollback
and a real operator-approved service promotion contract. The CI tests
here establish no automatic HA cutover and do not satisfy #36.
