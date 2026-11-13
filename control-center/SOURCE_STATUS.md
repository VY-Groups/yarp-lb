# Source status (0.1 development)

This directory contains the **complete latest universal Control Center source package** available from the preceding development build, not historical intermediate versions. The CA/PKI sector is an optional profile.

## Verification boundaries

- The independent `tests/L7` GitHub Actions acceptance harness is already in the repository; it compiles an isolated YARP gateway and executes real HTTP traffic.
- The full `control-center/SpeedSignYarp.csproj` has not yet passed a GitHub CI build. The new `control-center-ci.yml` is intended to establish that gate.
- Operational LDAP/SMTP, fleet HA, L4, WAF, GSLB, and multi-tenancy remain unverified or unimplemented as stated in `docs/ACCEPTANCE_MATRIX.md`.
- The `GatewayAgent` folder is a separate project; app `tests/` are separate projects. They are excluded from SDK implicit Compile items in the main application project.
- The application retains legacy Windows project and state paths to support migration compatibility; they are not organization-specific runtime requirements for future deployments.
- Never use `appsettings.TEST.sample.json` as a production secrets file.
