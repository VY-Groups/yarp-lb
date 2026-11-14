from pathlib import Path
p=Path(__file__).resolve().parents[1]
api=(p/'OrganizationProfile.cs').read_text()
app=(p/'Program.cs').read_text()
ui=(p/'wwwroot/app.ts').read_text()
html=(p/'wwwroot/index.html').read_text()
installer=(p/'INSTALL.ps1').read_text()
for value in ['/admin/api/organization','/admin/api/organization/sectors','MapOrganizationProfile', 'RequireRole("Administrator")','ExpectedRevision','Results.Conflict','File.Move(tmp, dest, true)']:
 assert value in (api+app), value
assert 'OrganizationProfile.cs' in installer
assert 'app.MapOrganizationProfile(privateDir)' in app
assert "IsLoopback(address)" in app and 'yarp_control_http_requests_total' in app
assert "'GatewayCore.ApplicationCategory'" not in ui
assert 'Set up your GatewayCore gateway' not in ui
assert '<strong>GatewayCore</strong>' not in html
assert 'data-organization-name' in html
assert 'Organization profile' in ui
assert "multiTenantIsolation = false" in api
assert (p/'tests/MockHttpBackend/Program.cs').is_file()
assert (p/'tests/L7Integration/VERIFY-HTTP-DISTRIBUTION.ps1').is_file()
print('PASS: universal product profile, authorization, installer, UI and metrics contracts')
