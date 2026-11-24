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
  --restore-bundle-sha256 REPLACE_WITH_APPROVED_64_UPPER_HEX_BUNDLE
```

There is no headless live deployment action, implicit recovery retry or
fail-open fallback. The TLS server cert is checked against both the CA/SAN
and exact leaf pin; the received bounded ZIP is non-overwriting and private.
The verified bytes land under `/secure/dp-inbox/rev43`. Only then is the
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
