# Offline installation verification checklist

- [ ] `PRECHECK.ps1` PASS (explicit localhost-only HTTP listener, SDK, stopped app)
- [ ] `INSTALL.ps1` PASS (no C# compilation errors)
- [ ] Configuration SHA-256 unchanged by installer
- [ ] `VERIFY-RUNNING.ps1` and `VERIFY-SETUP.ps1` PASS (200 gateway, 200 dashboard, CSP, protected API)
- [ ] Read-only `/admin/api/runtime/destinations` reports actual YARP health states after login; Unknown is not misreported as Healthy
- [ ] Routing freeze blocks local route changes with HTTP 423 and is auditable
- [ ] Browser console no JavaScript/CSP failures
- [ ] Fresh local administrator can sign in; 0.1 Setup Center renders with authenticated server-side evidence
- [ ] 6-step architecture onboarding renders from Setup Center
- [ ] Standalone, HA pair, fleet mode validation passes/fails appropriately
- [ ] Draft save survives refresh and stale revision rejects second save
- [ ] No service/firewall/pgpool/database modification during onboarding
- [ ] Source rollback tested on a separate lab copy; restore package includes old ProgramData backups
- [ ] CA change approval and site security review completed separately before production
