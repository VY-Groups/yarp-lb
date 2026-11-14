# GatewayCore v0.1 Windows x64 TEST ONLY. No IIS configuration is altered.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$IisBackendUrl,
  [ValidateRange(1024,65535)][int]$Port=8080,
  [switch]$PrepareOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$app=Join-Path $root 'app'
$exe=Join-Path $app 'GatewayCoreYarp.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Missing GatewayCoreYarp.exe: extract the complete GitHub release ZIP first.' }
$uri=$null
if (-not [Uri]::TryCreate($IisBackendUrl,[UriKind]::Absolute,[ref]$uri)) { throw 'IisBackendUrl must be an absolute http(s) URL.' }
if ($uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) { throw 'IisBackendUrl must be http(s), without credentials, query or fragment.' }
if ($uri.AbsolutePath -ne '/') { throw 'Use an IIS site root URL ending in /; app-specific path routing is not enabled in this test package.' }
if ($Port -eq $uri.Port -and $uri.Host -in @('localhost','127.0.0.1','::1')) { throw 'Gateway and IIS cannot use the same local listening port.' }
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Use an elevated Windows PowerShell window for initial test setup and ProgramData permissions.' }
$state=Join-Path $env:ProgramData 'GatewayCoreYarp\ControlPlane'
$existingConfig=Join-Path $app 'appsettings.json'
# In-place upgrades or an existing control plane require explicit migration.
if (Test-Path -LiteralPath $state) {
  $entries=@(Get-ChildItem -LiteralPath $state -Force -ErrorAction Stop)
  if ($entries.Count -gt 0) {
    throw "Existing GatewayCore control-plane state found at $state. STOP: back up and use a disposable test machine; do not overwrite encrypted identities."
  }
}
if (Test-Path -LiteralPath $existingConfig) {
  throw "appsettings.json already exists at $existingConfig. Refusing to overwrite a previous installation."
}
$destination=$uri.AbsoluteUri
$config=[ordered]@{
  AllowedHosts='localhost;127.0.0.1'
  Logging=@{LogLevel=@{Default='Warning';'Microsoft.AspNetCore'='Warning'}}
  ReverseProxy=@{
    Routes=@{
      iis=[ordered]@{
        ClusterId='iis'
        Match=@{Path='/proxy/{**catch-all}'}
        Transforms=@(@{PathRemovePrefix='/proxy'})
      }
    }
    Clusters=@{
      iis=[ordered]@{
        LoadBalancingPolicy='RoundRobin'
        Destinations=@{iis01=@{Address=$destination}}
      }
    }
  }
}
$utf8=New-Object System.Text.UTF8Encoding($false)
$generated=$config | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($existingConfig,$generated,$utf8)
Write-Host "Test gateway configured: http://127.0.0.1:$Port/proxy/" -ForegroundColor Cyan
Write-Host "IIS upstream: $destination" -ForegroundColor Cyan
Write-Host "IIS sites, application pools, bindings and firewall are UNCHANGED."
Write-Host "APP STATE: $state (a new test identity store; never migrate by copying ciphertext)"
if ($PrepareOnly) { Write-Host 'PREPARE PASS'; exit 0 }
$env:ASPNETCORE_URLS="http://127.0.0.1:$Port"
$env:ASPNETCORE_ENVIRONMENT='Production'
$env:YARP_LISTENERS_CONFIG_FILE=''
$env:YARP_RUNTIME_CONFIG_PATH=''
$env:YARP_EC2_LAB_MODE=''
Set-Location $app
& $exe
if ($LASTEXITCODE -ne 0) { throw "GatewayCoreYarp exited $LASTEXITCODE" }
