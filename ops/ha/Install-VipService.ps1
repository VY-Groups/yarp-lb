[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('agent','provider','controller')][string]$Role,
 [Parameter(Mandatory)][string]$Executable,
 [Parameter(Mandatory)][string]$Config,
 [string]$Scope,[string]$Policy,[string]$Provider,[string]$Journal,
 [switch]$Apply
)
$ErrorActionPreference='Stop'
function LocalPath([string]$Path,[bool]$MustExist=$true){
 if($Path -notmatch '^[A-Za-z]:\\[^"\r\n]+$' -or $Path -match '[%&|<>\x00-\x1F]' -or $Path -match '(^|\\)\.\.?($|\\)'){throw 'Absolute simple local path required'}
 if($MustExist){
  $item=Get-Item -LiteralPath $Path
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Expected existing ordinary file'}
 }
 return '"' + $Path + '"'
}
$binary=LocalPath $Executable
$configArg=LocalPath $Config
switch($Role){
 'agent' {$name='GatewayCoreVipNodeAgent';$identity='LocalSystem';$startup='Automatic';$command="$binary --vip-node-agent $configArg"}
 'provider' {$name='GatewayCoreVipFenceProvider';$identity="NT SERVICE\$name";$startup='Manual';$command="$binary --vip-redfish-provider $configArg"}
 'controller' {
  if($Scope -cnotmatch '^[A-F0-9]{64}$'){throw 'Exact uppercase scope required'}
  $p=LocalPath $Policy;$f=LocalPath $Provider;$j=LocalPath $Journal $false
  if(-not(Test-Path -LiteralPath (Split-Path -Parent $Journal) -PathType Container)){throw 'Existing protected journal directory required'}
  $name='GatewayCoreVipController';$identity="NT SERVICE\$name";$startup='Manual'
  $command="$binary --vip-owner $configArg $Scope automatic-policy $p $f $j"
 }
}
if(-not $Apply){
 [pscustomobject]@{Name=$name;Identity=$identity;Startup=$startup;Command=$command;Applied=$false}
 return
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated local installation required'}
if(Get-Service -Name $name -ErrorAction SilentlyContinue){throw 'Existing service; refuse overwrite'}
if($Role -eq 'agent'){
 $gateway=Get-Service -Name GatewayCoreYarp
 if($gateway.Status -ne 'Stopped' -or $gateway.StartType -ne 'Manual'){throw 'Dedicated gateway must be stopped and Manual'}
}
# CIM avoids shell quoting/reparsing of the registered executable path.
$created=Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
 Name=$name;DisplayName=$name;PathName=$command;ServiceType=[uint32]16;ErrorControl=[uint32]1;
 StartMode=$startup;DesktopInteract=$false;StartName=$identity
}
if($created.ReturnValue -ne 0){throw "SCM service creation failed: $($created.ReturnValue)"}
Write-Verbose 'Installed; not started. Provision service-identity ACLs and validate topology before starting.'
[pscustomobject]@{Name=$name;Identity=$identity;Startup=$startup;Command=$command;Applied=$true}
