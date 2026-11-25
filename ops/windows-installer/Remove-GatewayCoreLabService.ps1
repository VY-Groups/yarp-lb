[CmdletBinding()]
param([Parameter(Mandatory)][string]$InstallRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
$serviceName = 'GatewayCoreYarp'
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
if ($null -eq $service) { exit 0 }
$match = [regex]::Match([string]$service.PathName, '"(?<exe>[^"]+\\GatewayCoreYarp\.exe)"|(?<exe>.+?\\GatewayCoreYarp\.exe)(?:\s|$)', 'IgnoreCase')
if (-not $match.Success) { throw 'Service executable path is not verifiable; refusing uninstall to avoid deleting an unrelated service.' }
$serviceRoot = [IO.Path]::GetFullPath((Split-Path -Parent (Split-Path -Parent $match.Groups['exe'].Value))).TrimEnd('\')
if (-not [string]::Equals($serviceRoot, $InstallRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Output 'A newer or different GatewayCore installation owns the service; leaving it unchanged.'
    exit 0
}
$running = Get-Service -Name $serviceName -ErrorAction Stop
if ($running.Status -ne 'Stopped') {
    Stop-Service -Name $serviceName
    $running.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(60))
}
& "$env:WINDIR\System32\sc.exe" delete $serviceName | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'SCM refused to remove the installed GatewayCore service.' }
for ($i=0; $i -lt 50 -and $null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 200 }
if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { throw 'GatewayCore service removal did not complete.' }
Write-Output 'GatewayCore service removed; protected ProgramData state retained.'
