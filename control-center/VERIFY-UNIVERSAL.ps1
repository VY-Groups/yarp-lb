# Read-only Windows Server 2022/.NET 10 validation. Run after INSTALL.ps1.
[CmdletBinding()]
param([string]$ProjectRoot='C:\YARP\SpeedSignYarp', [string]$GatewayUrl='http://127.0.0.1:8080')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!(Test-Path (Join-Path $ProjectRoot 'OrganizationProfile.cs'))) { throw 'OrganizationProfile.cs missing from installed source' }
Push-Location $ProjectRoot
try {
    & dotnet build --no-restore
    if($LASTEXITCODE -ne 0){ throw 'FAIL: gateway C# compilation' }
} finally { Pop-Location }
Write-Host 'PASS: gateway C# builds on this Windows Server' -ForegroundColor Green
Push-Location (Join-Path $PSScriptRoot 'tests\LoadBalancingCoreTests')
try {
    & dotnet restore --ignore-failed-sources
    if($LASTEXITCODE -ne 0){ throw 'FAIL: offline algorithm test restore' }
    & dotnet run --no-restore
    if($LASTEXITCODE -ne 0){ throw 'FAIL: offline algorithm tests' }
} finally { Pop-Location }
$listener = Get-NetTCPConnection -State Listen -LocalPort 8080 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '127.0.0.1' }
if(!$listener) { Write-Warning 'Gateway is not currently running on 127.0.0.1:8080. Start it and rerun for HTTP tests.'; return }
function GetStatus([string]$url) {
  try { $r=Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop; return [int]$r.StatusCode }
  catch { if($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } throw }
}
$health=GetStatus "$GatewayUrl/gateway/health"
if($health -ne 200){throw "FAIL: gateway health $health"}
foreach($endpoint in @('/admin/api/organization','/admin/api/organization/sectors')) {
    $code=GetStatus ("$GatewayUrl"+$endpoint)
    if($code -ne 401){throw "FAIL: anonymous $endpoint returned $code instead of 401"}
}
$r=Invoke-WebRequest -Uri "$GatewayUrl/gateway/metrics" -UseBasicParsing -TimeoutSec 8
if($r.StatusCode -ne 200 -or $r.Content -notmatch 'yarp_control_http_requests_total') {
  throw 'FAIL: Prometheus-format endpoint not available or invalid'
}
Write-Host 'PASS: gateway health 200; org API protected; local Prometheus exporter responds' -ForegroundColor Green
Write-Host 'NOTE: Actual HTTP distribution, RBAC/CSRF/SSO and external network tests remain separate acceptance gates.'
