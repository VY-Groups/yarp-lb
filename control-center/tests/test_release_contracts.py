from pathlib import Path
import re, json
root=Path(__file__).resolve().parents[1]
program=(root/'Program.cs').read_text()
setup=(root/'SetupCenter.cs').read_text()
ts=(root/'wwwroot/app.ts').read_text()
html=(root/'wwwroot/index.html').read_text()
installer=(root/'INSTALL.ps1').read_text()
precheck=(root/'PRECHECK.ps1').read_text()
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
# Ensure major CI files are present.
for fn in ['README.md','SetupCenter.cs','Onboarding.cs','DirectoryAuth.cs','Program.cs','PRECHECK.ps1','INSTALL.ps1','VERIFY-SETUP.ps1','docs/API_CONTRACT.md','docs/RELEASE_GATES.md']:
    assert (root/fn).exists(),fn
print('PASS: 0.1 release/API/RBAC/freeze/onboarding/installer/static security contracts')
