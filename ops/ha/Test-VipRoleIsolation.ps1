# CI-only: run a separate probe in the exact existing SCM service registration.
# Never opens or impersonates another process's token; no privilege escalation.
param([Parameter(Mandatory)][string]$ProviderDirectory,[Parameter(Mandatory)][string]$ControllerDirectory,
 [Parameter(Mandatory)][string]$ProviderKey,[Parameter(Mandatory)][string]$ControllerKey,
 [Parameter(Mandatory)][string]$ProbeExe)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $IsWindows){throw 'Hosted CI only'}
function FixtureRoot([string]$Directory){
 $root=Get-Item -LiteralPath $Directory
 if(-not $root.PSIsContainer -or $root.Name -notlike 'gc-vip-ci-*' -or $root.Parent.FullName -ne $env:ProgramData -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected fixture root'}
 return $root
}
$null=FixtureRoot $ProviderDirectory
$null=FixtureRoot $ControllerDirectory
$probe=Get-Item -LiteralPath $ProbeExe
$binRoot=FixtureRoot $probe.Directory.Parent.FullName
if($binRoot.Name -notlike 'gc-vip-ci-bin-*' -or $probe.Name -ne 'VipRoleProbe.exe' -or ($probe.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected probe binary'}
function Quote([string]$Value){
 if($Value -match '["\r\n]'){throw 'Unsafe fixture argument'}
 return '"'+$Value+'"'
}
function Change-Command($Name,$Command){
 $service=Get-CimInstance Win32_Service -Filter "Name='$Name'"
 $changed=Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$Command}
 if($changed.ReturnValue -ne 0){throw "SCM path change failed: $($changed.ReturnValue)"}
}
function Wait-State($Name,$State){
 (Get-Service -Name $Name).WaitForStatus([ServiceProcess.ServiceControllerStatus]$State,[TimeSpan]::FromSeconds(30))
}
function Check-Role($Name,$Directory,$Own,$Other){
 $root=FixtureRoot $Directory
 if((Split-Path -Parent $Own) -ne $root.FullName -or -not(Test-Path -LiteralPath $Other -PathType Leaf) -or -not(Test-Path -LiteralPath $Own -PathType Leaf)){throw 'Expected fixture credential files'}
 $service=Get-CimInstance Win32_Service -Filter "Name='$Name'"
 if($service.State -ne 'Running' -or $service.ProcessId -lt 1 -or $service.StartName -ne "NT SERVICE\$Name"){throw 'Exact live virtual service identity required'}
 $original=$service.PathName
 if(-not $original.StartsWith('"'+$binRoot.FullName+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Expected original fixture shipping executable'}
 $sid=[Security.Principal.NTAccount]::new("NT SERVICE\$Name").Translate([Security.Principal.SecurityIdentifier]).Value
 $allowed=@('S-1-5-18','S-1-5-32-544',$sid)
 foreach($item in @($root)+@(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse)){
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked fixture refused'}
  $acl=Get-Acl -LiteralPath $item.FullName
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $allowed}){throw 'Unexpected cross-role allow ACE'}
  if(-not($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $sid})){throw 'Own service ACE missing'}
 }
 $result=Join-Path $root.FullName ('role-probe-'+[Guid]::NewGuid().ToString('N')+'.txt')
 $command=(@($probe.FullName,$Name,$sid,$Own,$Other,$result)|ForEach-Object {Quote $_}) -join ' '
 Stop-Service -Name $Name;Wait-State $Name 'Stopped'
 try{
  Change-Command $Name $command
  Start-Service -Name $Name;Wait-State $Name 'Running'
  if(-not(Test-Path -LiteralPath $result -PathType Leaf)){throw 'Probe produced no evidence'}
  $actual=Get-Content -LiteralPath $result -Raw
  if($actual -cne "PASS $Name $sid"){throw "Actual service identity probe failed: $actual"}
  Write-Output "PASS: $Name same SCM registration, exact identity, own read allowed and peer read denied"
 }finally{
  try{
   if((Get-Service -Name $Name).Status -ne 'Stopped'){Stop-Service -Name $Name;Wait-State $Name 'Stopped'}
  }finally{
   Change-Command $Name $original
   if(Test-Path -LiteralPath $result){Remove-Item -LiteralPath $result -Force}
   Start-Service -Name $Name;Wait-State $Name 'Running'
  }
 }
}
Check-Role 'GatewayCoreVipFenceProvider' $ProviderDirectory $ProviderKey $ControllerKey
Check-Role 'GatewayCoreVipController' $ControllerDirectory $ControllerKey $ProviderKey
Write-Output 'PASS: both restored shipping service registrations'
