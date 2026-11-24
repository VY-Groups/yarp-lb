# Windows Data Protection DPAPI-to-certificate offline rewrap (#48)

This source-only .NET 10 utility is a **separate, deliberately offline**
migration path for an existing Windows Server key-ring encrypted under the
original machine's DPAPI identity. It preserves the existing Data Protection
key GUIDs, algorithms, activation/expiration metadata and revocation XML, but
re-encrypts the protected master-key XML with a specifically approved
`LocalMachine\\My` RSA 3072+ certificate. New keys and existing cookies remain
under the same configured application name and Data Protection purposes.

Unlike copying a DPAPI ring to a second host (which cannot work), the
resulting **certificate-wrapped encrypted** XML can be distributed only to
separately authorized service identities that independently possess the
approved certificate and equivalent application/purpose configuration.

## Non-negotiable software preconditions

- Run on **the original Windows machine** under the service/machine identity
  that can decrypt the legacy DPAPI-encrypted key XML. The migration utility
  does not accept or export the original DPAPI machine secret.
- Stop **every source key-ring writer**, independently fence the live source
  and recipients, and record authorized migration change/revision. The
  utility detects modifications during its bounded source snapshot, but it
  **cannot** guarantee a different service is quiesced or that new writes will
  never occur after inspection.
- Create a protected Windows state tree using
  `WindowsStateProtection.InitializeStateDirectory` with inherited ACLs
  disabled and only the current service identity, SYSTEM and Administrators
  authorized. Both the original key-ring and output parent must already
  have validated, protected ACLs. The utility refuses linked directories
  and a pre-existing output.
- Separately provision a valid RSA 3072+ **key encipherment** leaf with
  accessible private key in `LocalMachine\\My`, explicit X.509 trust,
  non-CA basic constraints, and more than one day left before expiry.
  Certificate material must never be embedded in the repository,
  installer or CI artifacts.
- Keep the original DPAPI ring and independently backed-up signing/encryption
  identities until a reviewed rollback/migration and all original-cookie
  acceptance steps pass. Never overwrite the source or a serving destination.

## Offline invocation

Publish from the approved source without customer secrets:

```powershell
dotnet publish control-center/tools/WindowsDpFleetMigration/WindowsDpFleetMigration.csproj -c Release -o C:\\Tools\\OfflineDpMigration
dotnet C:\\Tools\\OfflineDpMigration\\WindowsDpFleetMigration.dll migrate --approved-offline "C:\\ProgramData\\GatewayCoreYarp\\ControlPlane\\data-protection-keys" "C:\\ProgramData\\GatewayCoreYarp\\ControlPlane\\portable-fleet-ring" REPLACE_WITH_APPROVED_40_HEX_THUMBPRINT
```

Every path is absolute; the destination must **not** exist. The utility
validates the source private ACLs, rejects unknown/duplicate/linked XML,
refuses any plaintext or non-approved DPAPI decryptor, checks the
machine-store certificate and performs an actual legacy DPAPI decrypt
followed by X.509 rewrap in memory. It verifies that the new ciphertext
decrypts back to the exact original masterKey element before creating
the new protected output. It writes only encrypted XML into a new protected
staging directory, re-reads the complete original inventory, verifies
identical source ciphertext SHA-256, then atomically renames the new private
directory into place. It never deletes/replaces the source ring, logs
private key/cookie bytes, or auto-promotes an active gateway.

The Windows migration process holds short-lived **managed plaintext**
from the framework's DPAPI XML decryptor in memory; it never persists
plaintext and exits immediately after the bounded operation. Run the
utility only on an operator-controlled, isolated source host with
no crash-dump/private-process-memory collection of its secrets.

## Real .NET acceptance

`.github/workflows/windows-dpapi-fleet-migration.yml` publishes the actual
utility and runs a separate Windows Server 2022 .NET 10 process. The
acceptance creates a real DPAPI LocalMachine encrypted ring and authentic
cookie, installs a disposable LocalMachine RSA 3072+ certificate, migrates
the ring, verifies that original XML stays byte-identical, that the
target is certificate-wrapped instead of DPAPI/plaintext, then starts a
fresh fleet-certificate Data Protection provider to decrypt the **same**
original cookie. It rejects duplicate destination/replay, unapproved
operator invocation, unexpected decryptor class and missing certificate.
All synthetic materials remain on the disposable runner; this test
does not validate source host private-key ACL on a separate customer
machine or a production Active Directory account.

**Important remaining #48 software work:** independently enforced source
and destination writer quiescence/epoch handoff, zero-downtime phased
live cutover and rollback across two different *authorized* service
identities, protected cross-node signing/wrapping-key escrow, renewal
for long recovery operations, and complete Linux/Windows service identity
and operational lifecycle documentation. This utility is a genuine
offline migration component, **not** a production-safe online migration
or proof of complete fleet continuity. Physical site validation is #36,
but software correctness gaps remain in #48 until independently
implemented, CI-tested and reviewed.
