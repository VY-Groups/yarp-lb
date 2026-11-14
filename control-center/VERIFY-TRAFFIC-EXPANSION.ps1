# Read-only validation of the 0.1 traffic-engine expansion.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = 'C:\YARP\GatewayCoreYarp'
if (-not (Test-Path (Join-Path $project 'LoadBalancingExtensions.cs'))) { throw 'Traffic expansion not installed' }
Push-Location $project
try {
    & dotnet build --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Gateway compile failed' }
} finally { Pop-Location }
Push-Location (Join-Path $PSScriptRoot 'tests\LoadBalancingCoreTests')
try {
    & dotnet restore --ignore-failed-sources
    if ($LASTEXITCODE -ne 0) { throw 'Offline algorithm restore failed' }
    & dotnet run --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Algorithm tests failed' }
} finally { Pop-Location }
# API checks require a separately running gateway. Anonymous caller must not see the inventory.
$listener = Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue | Where-Object LocalAddress -eq '127.0.0.1'
if ($listener) {
    $status = 0
    try {
        $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/admin/api/capabilities' -UseBasicParsing -ErrorAction Stop
        $status = [int]$response.StatusCode
    } catch {
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        else { throw 'Cannot verify API authentication: ' + $_.Exception.Message }
    }
    if ($status -ne 401) { throw "FAIL: anonymous capability API response was HTTP $status, expected 401" }
    Write-Host 'PASS: capability API requires login (401)'
} else {
    Write-Host 'NOTE: gateway is stopped; check anonymous 401 after it starts.'
}
Write-Host 'VERIFY: run a two-backend weighted test after approved routing config; check source-IP handling through firewall SNAT.'
