# Signed gateway configurations (development 0.1)

## Security
The gateway agent already requires a trusted mTLS client certificate. **Config prepare additionally requires a P-256 ECDSA signature** from a controller signing key pinned at each gateway; signature covers protocol version, unique transaction ID, expected config revision, a deterministic canonical JSON digest, and a deadline no more than five minutes into the future. The agent verifies before it creates a staged configuration. Replays are rejected while the transaction directory persists and revision checks prevent activation after drift.

## Key provisioning (not automatic)
From a trusted administration shell with .NET 10 installed:

```powershell
dotnet run --project control-center/tools/FleetKeyTool/FleetKeyTool.csproj -- "C:\ProgramData\SpeedSignYarp\ControlPlane\fleet-signing-private.pem" "C:\ProgramData\SpeedSignYarp\ControlPlane\fleet-signing-public.pem"
```

Never check in or email the private PEM. Restrict filesystem ACLs to the controller service identity and administrators; review backups and key rotation policy. Copy **only** the public PEM to `Agent:ControllerSigningPublicKeyPath` on each gateway. Agent config deployments remain disabled unless the absolute public key path is present. Separate agent server certificates and TLS client thumbprint trust are still required.

## Non-goals and caution
The signature does not by itself make a multi-node rollout atomic, provide HSM backing, automatic key rotation, or guarantee application health. The controller currently stages and activates nodes sequentially, with best-effort rollback. Fleet HA and formal immutable audit remain pending. Signing is deliberately fail-closed when keys are missing.

The key pair must be provisioned independently for each deployment. Never use demo keys in a production environment.
