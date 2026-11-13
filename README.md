# YARP Control Center 0.1 — development

This repository is a development workspace for a universal, YARP-based L7 load balancer and control center. **Not production-certified.**

## CI verification

The `ci/l7-acceptance` branch introduces a GitHub Actions pipeline that compiles the extracted weighted balancing policy code and sends real loopback HTTP traffic through a YARP gateway to two ASP.NET Core backends. This validates the L7 data-plane policies, **not** the full control-plane/admin portal.

## Scope & security

- YARP is the L7 HTTP(S) data plane. TCP/UDP, GSLB, WAF and Anycast are separate engines.
- Active–Active requires a health-aware ingress/VIP; two gateways alone are not an HA solution.
- CI mock backends bind only to loopback; no production certificates, credentials, or customer data are used.
- Never treat a CI pass as production CA/PKI change approval.

See `.github/workflows/` for automation and `tests/L7/` for the executable harness.
