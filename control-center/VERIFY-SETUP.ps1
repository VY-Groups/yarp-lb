# 0.1 read-only anonymous boundary/asset smoke tests. Open a SECOND PowerShell window while YARP runs.
[CmdletBinding()]
param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
$base = $BaseUrl.TrimEnd('/')
Write-Host 'GatewayCore YARP Control Center 0.1 — API and security smoke checks' -ForegroundColor Cyan
function Expect([string]$Path, [int]$Status) {
    $url = $base + $Path
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 8
        $got = [int]$r.StatusCode
    } catch [System.Net.WebException] {
        if ($null -eq $_.Exception.Response) { throw }
        $got = [int]$_.Exception.Response.StatusCode
    }
    if ($got -ne $Status) { throw "FAIL $Path expected HTTP $Status but received $got" }
    Write-Host "PASS $Path => HTTP $got" -ForegroundColor Green
}
Expect '/gateway/health' 200
Expect '/dashboard' 200
Expect '/dashboard/app.js' 200
Expect '/dashboard/style.css' 200
Expect '/admin/api/session' 200
Expect '/admin/api/setup/overview' 401
Expect '/admin/api/setup/version' 401
Expect '/admin/api/setup/freeze' 401
Expect '/admin/api/runtime/destinations' 401
Expect '/admin/api/onboarding' 401
Expect '/admin/api/state' 401
Expect '/admin/api/mail' 401
Expect '/admin/api/directory' 401
$dashboard = Invoke-WebRequest -UseBasicParsing -Uri ($base+'/dashboard') -TimeoutSec 8
if($dashboard.Content -notmatch '0.1') { throw 'Dashboard does not identify the 0.1 development release.' }
if($dashboard.Headers['Content-Security-Policy'] -notmatch "style-src 'self'") { throw 'Strict Content Security Policy missing.' }
Write-Host 'PASS: 0.1 dashboard, strict CSP and anonymous endpoint denial.' -ForegroundColor Green
Write-Host 'MANUAL: Sign in as Administrator, open Setup Center and validate each stage, change freeze and live runtime state.'
