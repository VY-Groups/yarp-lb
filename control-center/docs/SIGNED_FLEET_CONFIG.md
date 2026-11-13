# Signed gateway configurations (development 0.1)

## Security
The gateway agent already requires a trusted mTLS client certificate. **Config prepare additionally requires a P-256 ECDSA signature** from a controller signing key pinned at each gateway; **v2** signature covers protocol version, signing key ID, strictly increasing sequence, unique transaction ID, expected config revision, canonical JSON digest, and a deadline no more than five minutes in the future. Older v1 signatures are never accepted by the gateway. The agent verifies before it creates a staged configuration. Replays are rejected while the transaction directory persists and revision checks prevent activation after drift.

## Key provisioning (not automatic)
From a trusted administration shell with .NET 10 installed:

```powershell
dotnet run --project control-center/tools/FleetKeyTool/FleetKeyTool.csproj -- "C:\ProgramData\SpeedSignYarp\ControlPlane\fleet-signing-private.pem" "C:\ProgramData\SpeedSignYarp\ControlPlane\fleet-signing-public.pem"
```

Never check in or email the private PEM. Restrict filesystem ACLs to the controller service identity and administrators; review backups and key rotation policy. Copy **only** the public PEM to `Agent:ControllerSigningPublicKeyPath` on each gateway. Agent config deployments remain disabled unless the absolute public key path is present. Separate agent server certificates and TLS client thumbprint trust are still required.

## Non-goals and caution
The signature does not by itself make a multi-node rollout atomic, provide HSM backing, automatic key rotation, or guarantee application health. The controller currently stages and activates nodes sequentially, with best-effort rollback. Fleet HA and formal immutable audit remain pending. Signing is deliberately fail-closed when keys are missing.

The key pair must be provisioned independently for each deployment. Never use demo keys in a production environment.

## Rollback/replay defense (signed protocol v2)
Each controller persists a monotonic sequence counter in `ControlPlane/fleet-sequence.txt`. Each agent independently persists the largest accepted sequence in `StageDirectory/last-accepted-sequence.txt`, even when the config reverts to an older revision. A signed prepare at or below this high-water mark is rejected. Older staged transactions cannot be activated or rolled back after a newer signed prepare is accepted. A legitimate rollback is handled by the current transaction; future rollbacks to prior known-good settings must be approved and re-signed with a NEW sequence.

Protect these monotonic files and backups from rollback or unauthorized deletion; restoring a stale snapshot of the agent filesystem can undermine replay resistance. Filesystem integrity/rollback protection (HSM/TPM, append-only quorum) is not included.

## Two-key overlap rotation
`Agent:TrustedSigningPublicKeyPaths` permits 1–3 explicit public PEM files. Deploy the new public key to agents *before* changing the controller private key, observe dual trust, then remove the old public key only after testing. No private key should ever be copied to an agent. Automated fleet key distribution, key revocation and HSM-backed signing are still pending. Updated agents reject legacy signed v1 messages.
