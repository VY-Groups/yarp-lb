# Read-only prerequisites. No network, no downloads, no machine modifications.
[CmdletBinding()]
param([string]$ProjectRoot = 'C:\YARP\SpeedSignYarp')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source=$PSScriptRoot
Write-Host 'YARP Control Center 0.1 - offline preflight' -ForegroundColor Cyan
$failures = New-Object System.Collections.Generic.List[string]
$required = @('Program.cs','LoadBalancingCore.cs','LoadBalancingExtensions.cs','CapabilityRegistry.cs','OrganizationProfile.cs','Onboarding.cs','DirectoryAuth.cs','SetupCenter.cs','wwwroot\index.html','wwwroot\style.css','wwwroot\app.js','wwwroot\app.ts','wwwroot\tsconfig.json')
foreach($f in $required) { if (-not (Test-Path -LiteralPath (Join-Path $source $f) -PathType Leaf)) { $failures.Add("Missing package file $f") } }
if (-not (Test-Path -LiteralPath 'C:\YARP-Packages\System.DirectoryServices.Protocols.10.0.15.nupkg')) { $failures.Add('Offline LDAP package missing: C:\YARP-Packages\System.DirectoryServices.Protocols.10.0.15.nupkg. Download on laptop and transfer first.') }
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot 'SpeedSignYarp.csproj') -PathType Leaf)) { $failures.Add('Existing SpeedSignYarp project missing') }
if (-not (Test-Path -LiteralPath (Join-Path $ProjectRoot 'appsettings.json') -PathType Leaf)) { $failures.Add('Existing appsettings.json missing; installer never creates/overwrites it') }
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if ($null -eq $dotnet) { $failures.Add('dotnet SDK not found') }
else {
    $sdkList = @(& dotnet --list-sdks 2>$null)
    if (-not @($sdkList | Where-Object { $_ -match '^10\.' }).Count) { $failures.Add('No .NET 10 SDK installed') }
    Write-Host ('SDK: '+($sdkList -join '; '))
}
if (Test-Path -LiteralPath (Join-Path $ProjectRoot 'SpeedSignYarp.csproj')) {
    $project = Get-Content (Join-Path $ProjectRoot 'SpeedSignYarp.csproj') -Raw
    if ($project -notmatch '<TargetFramework>net10\.0</TargetFramework>') { $failures.Add('Project must target net10.0') }
    if ($project -notmatch 'Yarp.ReverseProxy') { $failures.Add('Project missing Yarp.ReverseProxy reference') }
}
# A past installer put Program.cs in nested project backups, which caused CS8802.
if (Test-Path -LiteralPath $ProjectRoot) {
    $nested = @(Get-ChildItem -LiteralPath $ProjectRoot -Filter 'Program.cs' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne (Join-Path $ProjectRoot 'Program.cs') -and $_.FullName -notmatch '\\(bin|obj)\\' })
    if($nested.Count -gt 0) { $failures.Add(('Duplicate Program.cs files inside project: ' + ($nested.FullName -join ', ') + '. Move backup folders outside the project.')) }
}
$gatewayProcess = @(Get-CimInstance Win32_Process -Filter "Name = 'SpeedSignYarp.exe' OR Name = 'dotnet.exe'" -ErrorAction SilentlyContinue | Where-Object {
    ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($ProjectRoot,[StringComparison]::OrdinalIgnoreCase)) -or
    ($_.CommandLine -and $_.CommandLine.IndexOf($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) -ge 0)
})
if ($gatewayProcess.Count -gt 0) { $failures.Add('A YARP process is still running from this project. Press Ctrl+C in its console first.') }
# This lab management console must stay on localhost. Preserve user config instead of changing it.
if (Test-Path -LiteralPath (Join-Path $ProjectRoot 'appsettings.json')) {
    try {
        $cfg = Get-Content (Join-Path $ProjectRoot 'appsettings.json') -Raw | ConvertFrom-Json
        $urls = @()
        if($cfg.Kestrel -and $cfg.Kestrel.Endpoints){foreach($ep in $cfg.Kestrel.Endpoints.PSObject.Properties){ $urls += [string]$ep.Value.Url }}
        if($urls.Count -eq 0){ $failures.Add('Kestrel.Endpoints absent; expected explicit local-only http://127.0.0.1:8080 listener') }
        foreach($url in $urls) { if ($url -notmatch '^http://(127\.0\.0\.1|localhost|\[::1\]):8080/?$') { $failures.Add("Unexpected Kestrel listener: $url. This LAB installation requires loopback-only 8080.") } }
    } catch { $failures.Add('appsettings.json invalid: '+$_.Exception.Message) }
}
if ($failures.Count) { foreach($e in $failures){Write-Host "FAIL: $e" -ForegroundColor Red}; throw "Preflight blocked: $($failures.Count) issue(s)." }
Write-Host 'PASS: project, SDK, package files, listener and stopped process checks.' -ForegroundColor Green
