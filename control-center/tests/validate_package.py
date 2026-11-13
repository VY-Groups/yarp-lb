"""Static packaging assertions; does not substitute for dotnet build and runtime tests."""
from pathlib import Path
import re
root = Path(__file__).resolve().parents[1]
cs = (root/'Program.cs').read_text()
ts = (root/'wwwroot/app.ts').read_text()
html = (root/'wwwroot/index.html').read_text()
js = (root/'wwwroot/app.js').read_text()
installer = (root/'INSTALL.ps1').read_text()
assert 'MapPost("/admin/api/apply"' not in cs
assert '/admin/api/change-requests' in cs
assert 'different Administrator' in cs or 'requester cannot approve' in cs.lower()
assert '/admin/api/metrics' in cs
assert 'style="' not in html
assert not re.search(r'\bstyle\s*=\s*["\']', ts)
assert '/admin/api/change-requests' in js
assert 'C:\\YARP\\Backups' in installer
assert 'C:\\YARP\\SpeedSignYarp' in installer
print('PASS: static package assertions; C# runtime build not performed')
