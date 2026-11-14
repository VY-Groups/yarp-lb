# YARP Control Center 0.1 - transactional offline development installer.
# Requires: elevated Windows PowerShell 5.1, an EXISTING Windows Server 2022/.NET 10 gateway.
# Keeps live appsettings.json and ProgramData security state unchanged.
# IMPORTANT: staging/local-only installation, NOT a production go-live procedure.
[CmdletBinding()]
param(
    [string]$ProjectRoot = 'C:\YARP\GatewayCoreYarp',
    [string]$BackupRoot = 'C:\YARP\Backups',
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = $PSScriptRoot
$originals = @('Program.cs','LoadBalancingCore.cs','LoadBalancingExtensions.cs','CapabilityRegistry.cs','OrganizationProfile.cs','Onboarding.cs','DirectoryAuth.cs','SetupCenter.cs','GatewayCoreYarp.csproj','wwwroot\index.html','wwwroot\style.css','wwwroot\app.js','wwwroot\app.ts','wwwroot\tsconfig.json')

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator before running INSTALL.ps1.'
}
& (Join-Path $source 'PRECHECK.ps1') -ProjectRoot $ProjectRoot

# Private copies of application code; never create backup directories under ProjectRoot.
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
& icacls.exe $BackupRoot /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'BUILTIN\Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to secure backup directory.' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss-ffff'
$backup = Join-Path $BackupRoot ("before-0.1-$stamp")
New-Item -ItemType Directory -Path $backup -Force | Out-Null
$manifest = [ordered]@{ version = '0.1'; projectRoot = $ProjectRoot; createdUtc = (Get-Date).ToUniversalTime().ToString('o'); existing = @(); missing = @(); files = @() }
foreach ($relative in $originals) {
    $current = Join-Path $ProjectRoot $relative
    $copyTo = Join-Path $backup $relative
    $manifest.files += $relative
    if (Test-Path -LiteralPath $current -PathType Leaf) {
        $manifest.existing += $relative
        New-Item -ItemType Directory -Path (Split-Path $copyTo -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $current -Destination $copyTo -Force
    } else { $manifest.missing += $relative }
}
# Copy the existing JSON configuration for rollback/reference, but do not edit it.
$configFile = Join-Path $ProjectRoot 'appsettings.json'
Copy-Item -LiteralPath $configFile -Destination (Join-Path $backup 'appsettings.json') -Force
$manifest.configHashBefore = (Get-FileHash -Path $configFile -Algorithm SHA256).Hash
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $backup 'manifest.json') -Encoding UTF8
Write-Host "Saved restricted rollback backup at: $backup" -ForegroundColor Cyan

try {
    foreach ($relative in @($originals | Where-Object { $_ -ne 'GatewayCoreYarp.csproj' })) {
        $copyFrom = Join-Path $source $relative
        $copyTo = Join-Path $ProjectRoot $relative
        New-Item -ItemType Directory -Path (Split-Path $copyTo -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $copyFrom -Destination $copyTo -Force
    }
    # Preserve the original project references: add only the missing AD LDAP package.
    $projectFile = Join-Path $ProjectRoot 'GatewayCoreYarp.csproj'
    $projectText = Get-Content -LiteralPath $projectFile -Raw
    if ($projectText -notmatch 'System.DirectoryServices.Protocols') {
        if ($projectText -notmatch '</ItemGroup>') { throw 'Unable to locate project package references' }
        $projectText = $projectText.Replace('</ItemGroup>', '  <PackageReference Include="System.DirectoryServices.Protocols" Version="10.0.15" />' + [Environment]::NewLine + '  </ItemGroup>')
        Set-Content -Path $projectFile -Value $projectText -Encoding UTF8
    }
    # Align assembly/package metadata with the only public development version: 0.1.
    if ($projectText -match '<Version>[^<]*</Version>') {
        $projectText = [regex]::Replace($projectText, '<Version>[^<]*</Version>', '<Version>0.1</Version>')
    } else {
        $projectText = $projectText.Replace('</PropertyGroup>', '  <Version>0.1</Version>' + [Environment]::NewLine + '  </PropertyGroup>')
    }
    Set-Content -Path $projectFile -Value $projectText -Encoding UTF8
    if (-not $SkipBuild) {
        Push-Location $ProjectRoot
        try {
            $feed = 'C:\YARP-Packages'
            if (-not (Test-Path -LiteralPath $feed)) { throw "Offline NuGet source missing: $feed" }
            & dotnet restore --source $feed --ignore-failed-sources
            if ($LASTEXITCODE -ne 0) { throw "Offline restore failed. Put System.DirectoryServices.Protocols.10.0.15.nupkg in $feed" }
            & dotnet build --no-restore
            if ($LASTEXITCODE -ne 0) { throw "Compilation failed (exit $LASTEXITCODE)." }
        }
        finally { Pop-Location }
    }
    $configHashAfter = (Get-FileHash -Path $configFile -Algorithm SHA256).Hash
    if ($configHashAfter -ne $manifest.configHashBefore) { throw 'appsettings.json was unexpectedly modified; reverting.' }
    Write-Host 'PASS: 0.1 Setup Center, directory and mail installed; appsettings.json unchanged; build passed (unless -SkipBuild was requested).' -ForegroundColor Green
    Write-Host "ROLLBACK BACKUP: $backup"
    Write-Host 'NEXT: cd C:\YARP\GatewayCoreYarp'
    Write-Host '      dotnet run --no-build --no-launch-profile'
    Write-Host '      (In a SECOND PowerShell window) run VERIFY-RUNNING.ps1'
}
catch {
    $failure = $_.Exception.Message
    Write-Warning "Install failed: $failure"
    Write-Warning 'Restoring original application files; appsettings.json and ProgramData were not modified.'
    foreach ($relative in $originals) {
        $dest = Join-Path $ProjectRoot $relative
        $saved = Join-Path $backup $relative
        if ($relative -in $manifest.existing) {
            Copy-Item -LiteralPath $saved -Destination $dest -Force
        } elseif (Test-Path -LiteralPath $dest) {
            Remove-Item -LiteralPath $dest -Force
        }
    }
    throw "Upgrade rolled back after failure: $failure. Backup: $backup"
}
