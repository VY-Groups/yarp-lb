[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourceCommit,[Parameter(Mandatory)][string]$SetupPath,[Parameter(Mandatory)][string]$PayloadPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'Disposable hosted runner only' }
if ($SourceCommit -cnotmatch '^[0-9a-f]{40}$') { throw 'Invalid source commit' }
$target=Join-Path $env:ProgramFiles "GatewayCore\Lab\$SourceCommit"
$state=Join-Path $env:ProgramData 'GatewayCoreYarp'
if ((Test-Path -LiteralPath $target) -or (Test-Path -LiteralPath $state) -or (Get-Service GatewayCoreYarp -ErrorAction SilentlyContinue)) { throw 'Refusing existing installation/state/service' }
$argsForSetup=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-')
$p=Start-Process -FilePath $SetupPath -ArgumentList $argsForSetup -Wait -PassThru
if ($p.ExitCode -ne 0) { throw "Setup failed: $($p.ExitCode)" }
$uninstaller=Join-Path $target 'unins000.exe'
try {
  if ((Get-Content (Join-Path $target 'SOURCE_COMMIT.txt') -Raw).Trim() -cne $SourceCommit) { throw 'Installed source mismatch' }
  foreach ($file in Get-ChildItem -LiteralPath $PayloadPath -File -Recurse -Force) {
    $relative=$file.FullName.Substring($PayloadPath.Length+1)
    $installed=Join-Path $target $relative
    if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or (Get-FileHash -LiteralPath $installed).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash) { throw "Installed payload mismatch: $relative" }
  }
  $actual=@(Get-ChildItem -LiteralPath (Join-Path $target 'app') -File -Recurse -Force)
  $expected=@(Get-ChildItem -LiteralPath (Join-Path $PayloadPath 'app') -File -Recurse -Force)
  if ($actual.Count -ne $expected.Count) { throw 'Unexpected installed app files' }
  if (Get-Service GatewayCoreYarp -ErrorAction SilentlyContinue) { throw 'Setup unexpectedly registered a service' }
  foreach ($dir in @($state,(Join-Path $state 'ControlPlane'),(Join-Path $state 'ControlPlane\data-protection-keys'))) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container) -or -not (Get-Acl -LiteralPath $dir).AreAccessRulesProtected) { throw "Setup did not provision protected state: $dir" }
  }
  $again=Start-Process -FilePath $SetupPath -ArgumentList $argsForSetup -Wait -PassThru
  if ($again.ExitCode -eq 0) { throw 'Setup permitted an existing version overwrite' }
  # Only this disposable runner's newly provisioned empty state is removed.
  if (@(Get-ChildItem -LiteralPath $state -Recurse -File -Force).Count -ne 0) { throw 'Unexpected files in fresh state' }
  $scm=Join-Path $PSScriptRoot '..\..\control-center\tests\WindowsServiceAcceptance\VERIFY-WINDOWS-SCM.ps1'
  & $scm -CandidateAppDirectory (Join-Path $target 'app') -InstallerProvisionedState
  & $scm -Identity LocalService -CandidateAppDirectory (Join-Path $target 'app')
  if (Test-Path -LiteralPath $state) { throw 'SCM smoke did not clean its disposable state' }
  New-Item -ItemType Directory -Path $state | Out-Null
  Set-Content (Join-Path $state 'installer-state-sentinel.txt') 'must survive uninstall'
  $u=Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
  if ($u.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $target 'app\GatewayCoreYarp.exe'))) { throw 'Uninstall failed' }
  if ((Get-Content (Join-Path $state 'installer-state-sentinel.txt') -Raw).Trim() -ne 'must survive uninstall') { throw 'Uninstall removed protected state' }
  $beforeAcl=(Get-Acl -LiteralPath $state).Sddl
  $blocked=Start-Process -FilePath $SetupPath -ArgumentList $argsForSetup -Wait -PassThru
  if ($blocked.ExitCode -eq 0 -or (Get-Acl -LiteralPath $state).Sddl -ne $beforeAcl -or (Get-Content (Join-Path $state 'installer-state-sentinel.txt') -Raw).Trim() -ne 'must survive uninstall') { throw 'Existing state refusal failed' }
  Write-Host 'PASS: actual setup, exact payload, overwrite refusal, SCM acceptance, uninstall and state preservation'
} finally {
  $sentinel=Join-Path $state 'installer-state-sentinel.txt'
  if (Test-Path -LiteralPath $sentinel) { Remove-Item -LiteralPath $sentinel; Remove-Item -LiteralPath $state }
}
