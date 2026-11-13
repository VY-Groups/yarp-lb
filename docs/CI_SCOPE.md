# CI scope and follow-up work

This repository was initialized empty. The initial change proposes an isolated working L7 traffic laboratory and the custom YARP policies from the Control Center 0.1 engineering snapshot, rather than presenting an unreviewed ZIP as a production-ready platform.

A CI pass is **not** a full Control Center release pass.

## Included in this gate

- Compile two custom policies against YARP 2.3.0 on Windows Server 2022 and Ubuntu runner images.
- Start two real HTTP backends and a YARP gateway process.
- Verify weighted distribution, source affinity, rendezvous remapping, config reload, health checks, interruption behavior and recovery.
- Attach machine-readable evidence.

## Still required

- Import and build the full Control Center UI, API and agent projects.
- Reproducible package lockfile, dependency/security scans.
- Authentication, RBAC, approval, config and audit integration tests.
- mTLS, signed configs, HA fleet rollout, real ingress/VIP and isolated infrastructure E2E tests.
- Branch protection and required reviews before production changes.

No workflow targets real gateways or production endpoints.
