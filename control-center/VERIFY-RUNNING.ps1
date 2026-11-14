# Read-only post-start smoke test; open a SECOND PowerShell window.
[CmdletBinding()]
param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function CheckPage([string]$path,[int]$expected,[string]$contentType) {
    $u = $BaseUrl.TrimEnd('/') + $path
    $response = Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 8
    if ([int]$response.StatusCode -ne $expected) { throw "Unexpected HTTP status for $u" }
    if ($contentType -and $response.Headers['Content-Type'] -notmatch [regex]::Escape($contentType)) { throw "Unexpected Content-Type for $u" }
    Write-Host "PASS: $path -> HTTP $expected" -ForegroundColor Green
    return $response
}
$h = CheckPage '/gateway/health' 200 'application/json'
$body = $h.Content | ConvertFrom-Json
if ($body.status -ne 'healthy') { throw 'Gateway health endpoint returned non-healthy status' }
$dashboard = CheckPage '/dashboard' 200 'text/html'
if ($dashboard.Content -notmatch 'GatewayCore') { throw 'Dashboard shell missing GatewayCore label' }
if ($dashboard.Headers['Content-Security-Policy'] -notmatch "style-src 'self'") { throw 'Expected strict CSP missing from dashboard' }
CheckPage '/dashboard/app.js' 200 'javascript' | Out-Null
CheckPage '/dashboard/style.css' 200 'text/css' | Out-Null
$methods = CheckPage '/admin/api/auth-methods' 200 'application/json'
$methodsJson = $methods.Content | ConvertFrom-Json
if ($null -eq $methodsJson.activeDirectory) { throw 'Missing AD login discovery state' }
$session = CheckPage '/admin/api/session' 200 'application/json'
$sessionInfo = $session.Content | ConvertFrom-Json
if ($sessionInfo.authenticated -eq $true) { Write-Warning 'Session is authenticated; expected anonymous in this clean smoke test.' }
# Anonymous onboarding read must be inaccessible. PowerShell 5.1 throws for non-2xx.
try {
    Invoke-WebRequest -UseBasicParsing -Uri ($BaseUrl.TrimEnd('/') + '/admin/api/onboarding') -TimeoutSec 8 | Out-Null
    throw 'SECURITY FAILURE: anonymous onboarding endpoint returned 2xx'
} catch [System.Net.WebException] {
    $status = [int]$_.Exception.Response.StatusCode
    if ($status -ne 401) { throw "Expected anonymous onboarding HTTP 401; received $status" }
    Write-Host 'PASS: anonymous onboarding endpoint requires login (401)' -ForegroundColor Green
}
foreach ($restricted in @('/admin/api/mail', '/admin/api/directory')) {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri ($BaseUrl.TrimEnd('/') + $restricted) -TimeoutSec 8 | Out-Null
        throw "SECURITY FAILURE: anonymous $restricted returned 2xx"
    } catch [System.Net.WebException] {
        $status = [int]$_.Exception.Response.StatusCode
        if ($status -ne 401) { throw "Expected anonymous $restricted HTTP 401; received $status" }
        Write-Host "PASS: anonymous $restricted forbidden (401)" -ForegroundColor Green
    }
}
Write-Host 'PASS: gateway, frontend, LDAPS/SMTP APIs protected, CSP and authentication boundary checks.'  -ForegroundColor Green
Write-Host 'NEXT: Sign in at /dashboard and manually test all onboarding modes against docs\ACCEPTANCE.md.'
