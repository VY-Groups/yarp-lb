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
# Fixed Windows security event source; services only write events.
if(-not [Diagnostics.EventLog]::SourceExists('GatewayCoreVipSecurity')){
 [Diagnostics.EventLog]::CreateEventSource('GatewayCoreVipSecurity','Application')
}
if([Diagnostics.EventLog]::LogNameFromSourceName('GatewayCoreVipSecurity','.') -ne 'Application'){throw 'Unexpected VIP security event log source'}
# CIM avoids shell quoting/reparsing of the registered executable path.
$created=Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
 Name=$name;DisplayName=$name;PathName=$command;ServiceType=[byte]16;ErrorControl=[byte]1;
 StartMode=$startup;DesktopInteract=$false;StartName=$identity
}
if($created.ReturnValue -ne 0){throw "SCM service creation failed: $($created.ReturnValue)"}
# Only a successful Create grants permission to undo this registration.
# Verify the actual SCM record, not just the provider return code.
$filter="Name='"+$name+"'"
$expectedStart=if($Role -eq 'agent'){'Auto'}else{'Manual'}
function ReadRegistration {
 Get-CimInstance -ClassName Win32_Service -Filter $filter
}
function MatchesRegistration($Service){
 return ($null -ne $Service -and $Service.Name -eq $name -and
  $Service.PathName -ceq $command -and $Service.StartName -eq $identity)
}
try{
 $registered=ReadRegistration
 if(-not (MatchesRegistration $registered) -or $registered.State -ne 'Stopped' -or
    $registered.StartMode -ne $expectedStart){throw 'Installed SCM state not confirmed'}
}
catch{
 # Do not delete an unexpected or active service, even during rollback.
 try{
  $registered=ReadRegistration
  if($null -ne $registered){
   if(-not (MatchesRegistration $registered) -or $registered.State -ne 'Stopped'){
    throw 'Unexpected service identity, command or runtime state'
   }
   $removed=Invoke-CimMethod -InputObject $registered -MethodName Delete
   if($removed.ReturnValue -ne 0){throw 'SCM rollback deletion failed'}
   $deadline=[DateTime]::UtcNow.AddSeconds(10)
   do{
    $remaining=ReadRegistration
    if($null -eq $remaining){break}
    Start-Sleep -Milliseconds 200
   }while([DateTime]::UtcNow -lt $deadline)
   if($null -ne $remaining){throw 'SCM rollback removal not confirmed'}
  }
 }
 catch{throw 'SCM registration rollback unconfirmed; inspect the exact service before retrying'}
 throw 'SCM registration verification failed; newly created service rolled back'
}
Write-Verbose 'Installed; not started. Provision service-identity ACLs and validate topology before starting.'
[pscustomobject]@{Name=$name;Identity=$identity;Startup=$startup;Command=$command;Applied=$true}
