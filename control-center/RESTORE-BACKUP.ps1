# Manual rollback (not automatic). Restores ONLY application source files, never ProgramData data.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][string]$BackupPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$manifestPath=Join-Path $BackupPath 'manifest.json'
if (-not (Test-Path $manifestPath)) {throw 'Backup manifest missing; refusing unverified rollback.'}
$m=Get-Content $manifestPath -Raw | ConvertFrom-Json
if ($m.version -ne '0.1') { throw 'Not a 0.1 installer backup.' }
$target=[string]$m.projectRoot
if ((@(Get-CimInstance Win32_Process -Filter "Name='SpeedSignYarp.exe' OR Name='dotnet.exe'" -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -and $_.CommandLine.IndexOf($target,[StringComparison]::OrdinalIgnoreCase) -ge 0})).Count) { throw 'Stop YARP process before rollback.' }
if ($PSCmdlet.ShouldProcess($target,'Restore application source files')) {
    foreach($rel in @($m.files)) {
        $dest=Join-Path $target $rel
        $orig=Join-Path $BackupPath $rel
        if ($rel -in @($m.existing)) { Copy-Item $orig $dest -Force }
        elseif (Test-Path $dest) { Remove-Item $dest -Force }
    }
    Write-Host 'Source files restored. You must now run dotnet build --no-restore and restart YARP.' -ForegroundColor Yellow
    Write-Host 'ProgramData user accounts/audit/design state and appsettings.json were NOT overwritten.'
}
