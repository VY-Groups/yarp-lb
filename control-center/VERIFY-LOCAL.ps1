# 0.1 pre-start file/build verification ONLY. Do not build while YARP is running.
[CmdletBinding()]
param([string]$ProjectRoot = 'C:\YARP\SpeedSignYarp')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($f in @('Program.cs','Onboarding.cs','DirectoryAuth.cs','SetupCenter.cs','wwwroot\app.js','wwwroot\style.css','wwwroot\index.html','SpeedSignYarp.csproj')){
    if(-not (Test-Path -LiteralPath (Join-Path $ProjectRoot $f) -PathType Leaf)) {throw "Missing: $f"}
}
$running = @(Get-CimInstance Win32_Process -Filter "Name = 'SpeedSignYarp.exe' OR Name = 'dotnet.exe'" -ErrorAction SilentlyContinue | Where-Object {
  ($_.CommandLine -and $_.CommandLine.IndexOf($ProjectRoot,[StringComparison]::OrdinalIgnoreCase) -ge 0) -or
  ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($ProjectRoot,[StringComparison]::OrdinalIgnoreCase))
})
if($running.Count -gt 0){throw 'Stop YARP before compiling, or use VERIFY-RUNNING.ps1 while it runs.'}
Push-Location $ProjectRoot
try {& dotnet build --no-restore; if($LASTEXITCODE -ne 0){throw 'dotnet build returned an error'}}
finally{Pop-Location}
Write-Host 'PASS: source files and Windows .NET build verified. Start YARP, then run VERIFY-RUNNING.ps1 and VERIFY-SETUP.ps1.' -ForegroundColor Green
