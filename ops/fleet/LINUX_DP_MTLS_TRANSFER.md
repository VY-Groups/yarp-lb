# Linux Data Protection encrypted snapshot delivery over mutual TLS (#48)

This standalone Python 3 standard-library transport provides **authenticated,
encrypted, bounded, read-only distribution** of a separately captured Linux
Data Protection ciphertext snapshot. It is disabled by default and never
runs inside the shipping gateway. Its serving process must be started
explicitly by an authorized operator with **independent TLS identities**.
It never transfers Data Protection RSA private wrapping keys, P-256 signing
keys, runtime cookies, session tokens, local DP state, or the recovery
authority trust public key.

## Establish independent identity and source custody

Use customer PKI to issue distinct **TLS server** and **TLS client**
certificates with appropriate SANs and EKUs. Record their SHA-256 DER **leaf**
fingerprints in an independently approved runbook. Supply separate customer
CA material and certificate/key files. TLS 1.2+ performs CA-chain and
hostname validation; a pinned leaf fingerprint is **also** required at
both peers. An untrusted CA-signed peer is rejected unless its exact leaf
hash is approved. Server private keys must be local, single-link owner-only
0600 files. Revocation/renewal and service account ACL checks are operational
gates; certificate fingerprint changes require independent authorization.

1. Fence and stop all source key-ring writers **using an independent
   distributed authority**. This transport does not provide an election,
   quorum or fencing service.
2. Use the already merged offline .NET
   \`control-center/tools/LinuxDpEncryptedSnapshot\` \`capture\` command to
   produce a quiesced owner-private ciphertext directory under a private
   **source root**. Independently issue a P-256 signed checkpoint over
   exactly those bytes and retain the trust public key outside the backup.
3. Verify that the checkpoint is immutable and backed by an approved
   independently protected external revision floor. The mTLS sender
   includes a bounded copy of the checkpoint, **not** the signer key.
4. Ensure the receiving archive root is an empty or existing **0700**
   directory owned by the dedicated receiving service account, and located
   outside all production or staged Data Protection state roots.

Example; replace all paths/identities/port with approved private material:

\`\`\`sh
python3 ops/fleet/linux_dp_mtls_transport.py serve \
  --source-root /secure/dp-snapshots \
  --label rev43 \
  --checkpoint /secure/recovery-checkpoints/rev43.json \
  --listen 10.0.0.11 --port 17443 --allow-nonloopback \
  --client-cert-sha256 <64-UPPERCASE-HEX-RECEIVER-LEAF> \
  --ca /secure/operator-pki/root.pem \
  --certificate /secure/operator-pki/sender.pem \
  --private-key /secure/operator-pki/sender.key
\`\`\`

The server serves exactly one read-only
\`GET /v1/linux-dp-snapshot/rev43\` resource. TLS requires an approved client
certificate and does **not** accept a caller-provided snapshot label, POST,
directory traversal, redirects, transfer encoding or unbounded payloads.
It has no logging of private paths or credentials. Deploy behind tightly
scoped network ACLs, never on the public gateway ingress. Remote listening
requires explicit \`--allow-nonloopback\`.

From a **different, separately authorized Linux receiver**, with its own
TLS certificate:

\`\`\`sh
python3 ops/fleet/linux_dp_mtls_transport.py receive \
  --server-url https://10.0.0.11:17443 \
  --server-cert-sha256 <64-UPPERCASE-HEX-SENDER-LEAF> \
  --destination-root /secure/dp-inbox \
  --label rev43 \
  --ca /secure/operator-pki/root.pem \
  --certificate /secure/operator-pki/receiver.pem \
  --private-key /secure/operator-pki/receiver.key
\`\`\`

A successful pinned transfer leaves only
\`/secure/dp-inbox/rev43/ring/*.xml\` and
\`/secure/dp-inbox/rev43/checkpoint.json\`. Both are in a non-overwriting,
fsynced, owner-private archive. A second transfer to the same revision
fails without modifying the existing bytes. The transfer is limited to
32 MiB total, at most 512 encrypted XML entries of 1 MiB each and a 16 KiB
checkpoint. Symlinks, hard-linked input files, ZIP path traversal, duplicate
entries, compressed/zip-bomb members, unapproved TLS peers, invalid private
key permissions and changing file identities are rejected.

## Signed restore remains a separate mandatory authority

The received archive is **not trusted because a TLS request succeeded**.
The sender certificate authenticates the transfer node, while the
independent P-256 checkpoint authenticates **the actual encrypted Data
Protection key-ring bytes and revision**. The recipient must independently
provision its separate P-256 trust public key, RSA wrapping certificate/key
with approved access, and the monotonic high-water floor before invoking
the merged fail-closed .NET restore CLI, **while all destination writers are
stopped and fenced**:

\`\`\`sh
dotnet run --project control-center/tools/LinuxDpEncryptedSnapshot/LinuxDpEncryptedSnapshot.csproj -- \
  restore \
  --archive /secure/dp-inbox/rev43/ring \
  --state-root /var/lib/gatewaycore-yarp/staged-recovery-control-plane \
  --checkpoint /secure/dp-inbox/rev43/checkpoint.json \
  --trusted-public-key /secure/recovery-authority/trusted-verifier.pem \
  --minimum-revision-file /secure/recovery-authority/min-revision.txt
\`\`\`

That CLI independently verifies P-256 signature and XML inventory before,
during and after new-only atomic key-ring installation, refuses plaintext
or tampered XML and refuses a stale external revision. Do **not** move the
restored directory into a live service or promote a node until separate
quorum fencing, wrapping-key custody, and staged rotation/HA gates have passed.
A received checkpoint is not its own root of trust, and this receiver
does not authorize the signing key or advance the external monotonic floor.

## Current test and acceptance limits

\`python3 -m unittest discover -s ops/fleet
-p test_linux_dp_mtls_transport.py -v\` exercises a genuine localhost
OpenSSL-generated CA, client/server certificate validation, exact bidirectional
leaf pins, wrong same-CA client rejection, wrong-server pin, read-only
resource isolation, owner-only source reads, bounded ZIP and durable new-only
recipient staging. No customer credentials or raw backup blobs are
uploaded as CI artifacts.

These are **disposable localhost software tests**, not an independently
authenticated production remote-host DR demonstration. The real operator
must still verify a separate-host mTLS network, PKI revocation, quorum/partition
fencing, actual service-identity ACLs, Windows DPAPI-to-fleet migration,
a timed multi-node rotation and RHEL 9 SELinux/systemd. These are additional
#48 acceptance gates and must not be silently reassigned to physical #36.
This transport never claims production GO or closes #48 alone.
