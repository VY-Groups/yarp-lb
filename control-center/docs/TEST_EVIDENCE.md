# 0.1 test evidence and limitations

Tests executed when the ZIP was assembled (Linux build environment, no .NET SDK available):

| Test | Status | Evidence/meaning |
| --- | --- | --- |
| `tsc -p wwwroot` | PASS | TypeScript compiles to browser-ready JavaScript |
| `node --check wwwroot/app.js` | PASS | JavaScript parses |
| `node tests/test_onboarding_ui.mjs` | PASS | All six topology steps render and mode transition validation works in deterministic VM |
| `node tests/test_setup_ui.mjs` | PASS | 0.1 Setup Center renders, escapes malicious server-supplied content, shows runtime state and includes CSRF token on freeze requests |
| `python tests/test_release_contracts.py` | PASS | Setup APIs and local freeze presence, implementation status, installer copies, source packaging and no inline styling |
| `python tests/validate_package.py` | PASS | Legacy approvals/CSP/inventory baseline checks |
| ZIP `testzip()` and manifest | PASS | Archive entries readable and checksums consistent |

**Not performed**: C# compilation (build host does not have the .NET SDK and no network access to install it); Windows LDAP and SMTP integration, signed/certificate enrollment, authentication penetration testing, API stress testing, real two-node HA failover, immutable external audit, or CA protocol qualification.

On the user's Windows Server run:

```powershell
.\PRECHECK.ps1
.\INSTALL.ps1
# After launching GatewayCoreYarp in a first terminal:
.\VERIFY-RUNNING.ps1
.\VERIFY-SETUP.ps1
```

Then verify each relevant workflow through the browser. Record actual errors, timestamps and resulting HTTP statuses. Do **not** label the release production approved based only on static checks.
