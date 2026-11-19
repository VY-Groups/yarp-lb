from pathlib import Path
import re, json
root=Path(__file__).resolve().parents[1]
program=(root/'Program.cs').read_text()
setup=(root/'SetupCenter.cs').read_text()
ts=(root/'wwwroot/app.ts').read_text()
html=(root/'wwwroot/index.html').read_text()
installer=(root/'INSTALL.ps1').read_text()
precheck=(root/'PRECHECK.ps1').read_text()
support_doc=(root/'docs/DATA_PROTECTION_PLATFORM_SUPPORT.md').read_text(encoding='utf-8')
linux_keys=(root/'LinuxKeyProtection.cs').read_text(encoding='utf-8')
support_project=(root/'GatewayCoreYarp.csproj').read_text(encoding='utf-8')
support_program=program
support_installer=installer
support_service=(root/'ops/systemd/gatewaycore-yarp.service').read_text(encoding='utf-8')
global_sdk=(root.parent/'global.json').read_text(encoding='utf-8')
assert 'app.MapSetupCenter(privateDir)' in program
assert 'SetupCenter.ReadFreeze(privateDir).Frozen' in program
for path in ['/admin/api/setup/version','/admin/api/setup/overview','/admin/api/setup/freeze','/admin/api/runtime/destinations']:
    assert path in setup
assert 'IProxyStateLookup' in setup and 'd.Health.Active' in setup and 'd.Health.Passive' in setup
assert 'RequireAuthorization(p => p.RequireRole("Administrator"))' in setup
assert 'http-loopback' in setup and 'verifiedForProduction = false' in setup
assert 'NotImplementedException' not in setup
assert 'Input.Password' not in setup
assert 'SetupCenter.cs' in installer and 'SetupCenter.cs' in precheck
assert 'C:\\YARP\\Backups' in installer
assert 'wwwroot\\app.js' in installer
assert 'appsettings.json' in installer and 'configHashBefore' in installer
assert 'before-0.1' in installer
assert 'Setup Center' in html and '0.1' in html and 'style="' not in html
assert "'setup','onboarding','users','mail','directory'" in ts
assert 'setup-add-application' in ts and 'setup-live-health' in ts
assert "HealthyAndUnknown" in ts
assert "if(b1===b2)throw Error" in ts
assert "edit();show('Application added to unsaved draft" in ts
assert 'MapPost("/admin/api/apply"' not in program
assert 'app.MapReverseProxy' in program
assert not re.search(r'\bstyle\s*=\s*["\']',ts)
assert '"version": "10.0.100"' in global_sdk
assert '<TargetFramework>net10.0</TargetFramework>' in support_project
assert 'ProtectKeysWithDpapi(protectToLocalMachine: true)' in support_program
assert 'LinuxKeyProtection.Configure(dataProtection, privateDir)' in support_program
assert 'ProtectKeysWithCertificate(current)' in linux_keys
assert 'UnprotectKeysWithAnyCertificate(current, previous)' in linux_keys
assert 'YARP_LINUX_DP_OLD_CERT_PFX_PATH' in support_doc
assert 'not automatically rewrapped' in support_doc
assert 'Key expiry alone is not sufficient' in support_doc
assert 'Windows Server 2022' in support_doc and 'Ubuntu 24.04' in support_doc
assert 'RHEL-family Linux' in support_doc and 'Not qualified for deployment' in support_doc
assert 'Windows Service hosting and installation are not implemented' in support_doc
assert 'No production GatewayCore container image' in support_doc
assert 'LocalMachine\\My' in support_doc
assert 'not a service installer' in support_doc
assert 'temporary service derived from the Linux unit template' in support_doc
assert 'not a production installation' in support_doc
assert 'not supported by this release' in support_doc
assert 'shipped unit template' in support_doc
assert 'User=gateway-gateway' in support_service and 'UMask=0077' in support_service
assert 'IMPORTANT: staging/local-only installation' in support_installer
assert all(policy in support_doc for policy in (
    '`RoundRobin`', '`PowerOfTwoChoices`', '`LeastRequests`', '`Random`',
    '`FirstAlphabetical`', '`WeightedRandom`', '`SourceIpHash`', '`PrimaryBackup`'
))
for feature in ('HTTP/1.1', 'HTTP/2', 'HTTP/3', 'HTTPS', 'L4 TCP/UDP', 'DNS/GSLB', 'WAF'):
    assert f'| {feature} |' in support_doc
assert 'Opt-in and Windows-CI-tested only' in support_doc
assert 'Ubuntu wire behavior is unqualified' in support_doc
assert 'not integrated into GatewayCore Control Center lifecycle' in support_doc
assert 'No built-in GatewayCore WAF' in support_doc
for evidence_path in (
    'tests/L7/Acceptance/Program.cs', '.github/workflows/l7-acceptance.yml',
    'control-center/tests/TlsInventoryTests/TrafficHttp3Acceptance.cs',
    '.github/workflows/control-center-ci.yml',
    'tests/L4Acceptance/Program.cs', '.github/workflows/l4-acceptance.yml',
    'tests/GslbAcceptance/Program.cs', '.github/workflows/gslb-acceptance.yml',
    'tests/WafCrs/verify.sh', '.github/workflows/waf-crs-acceptance.yml'
):
    assert evidence_path in support_doc
# Ensure major CI files are present.
for fn in ['README.md','SetupCenter.cs','Onboarding.cs','DirectoryAuth.cs','Program.cs','PRECHECK.ps1','INSTALL.ps1','VERIFY-SETUP.ps1','docs/API_CONTRACT.md','docs/RELEASE_GATES.md']:
    assert (root/fn).exists(),fn
print('PASS: 0.1 release/API/RBAC/freeze/onboarding/installer/platform support/static security contracts')
