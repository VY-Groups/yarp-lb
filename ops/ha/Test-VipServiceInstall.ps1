# Disposable hosted-runner acceptance: register the shipping service roles, never start them.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $IsWindows){throw 'Hosted Windows CI only'}
$names=@('GatewayCoreYarp','GatewayCoreVipNodeAgent','GatewayCoreVipFenceProvider','GatewayCoreVipController')
foreach($name in $names){if(Get-Service -Name $name -ErrorAction SilentlyContinue){throw "Pre-existing service: $name"}}
$root=Join-Path $env:RUNNER_TEMP ('gc-vip-install-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$created=[System.Collections.Generic.List[string]]::new()
try{
 $binary=Join-Path $env:SystemRoot 'System32\whoami.exe'
 $config=Join-Path $root 'config.json'
 $policy=Join-Path $root 'policy.json'
 $provider=Join-Path $root 'provider.json'
 $journal=Join-Path $root 'journal.json'
 foreach($file in @($config,$policy,$provider)){Set-Content -LiteralPath $file -Value '{}'}
 # A stopped, manual fixture is required by the shipping agent installer.
 New-Service -Name GatewayCoreYarp -BinaryPathName ('"'+$binary+'"') -StartupType Manual | Out-Null
 $created.Add('GatewayCoreYarp')
 foreach($role in @('agent','provider','controller')){
  $params=@{Role=$role;Executable=$binary;Config=$config}
  if($role -eq 'controller'){$params.Scope='A'*64;$params.Policy=$policy;$params.Provider=$provider;$params.Journal=$journal}
  $plan=& "$PSScriptRoot/Install-VipService.ps1" @params
  if($plan.Applied -or (Get-Service -Name $plan.Name -ErrorAction SilentlyContinue)){throw 'Plan unexpectedly mutated SCM'}
  # Record the exact absent service before invoking the installer so cleanup
  # also handles a successful creation followed by a failed assertion.
  $created.Add($plan.Name)
  # Fail only the first verification read after actual SCM creation.
  # Rollback still uses the real SCM record and actual Delete method.
  # A mutable captured object is shared across the caller and child
  # script scopes; $script: variables resolve to different script scopes.
  $injection=@{Name=$plan.Name;Reads=0;Triggered=$false}
  $hook={
   param([Parameter(Position=0)][string]$ClassName,[string]$Filter)
   $record=CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $Filter
   if($null -ne $record -and $record.Name -eq $injection.Name){
    $injection.Reads++
    if(-not $injection.Triggered){
     $injection.Triggered=$true
     throw 'Injected post-create verification read failure'
    }
   }
   return $record
  }.GetNewClosure()
  Set-Item -Path Function:\Get-CimInstance -Value $hook
  $rolledBack=$false
  try{
   try{& "$PSScriptRoot/Install-VipService.ps1" @params -Apply | Out-Null}
   catch{
    if($_.Exception.Message -notmatch 'newly created service rolled back'){throw}
    $rolledBack=$true
   }
   if(-not $injection.Triggered -or $injection.Reads -lt 2 -or -not $rolledBack){throw 'Failure injection did not exercise real verification and rollback reads'}
  }
  finally{
   Remove-Item Function:\Get-CimInstance
   Remove-Variable injection,hook
  }
  if(Get-Service -Name $plan.Name -ErrorAction SilentlyContinue){throw 'Failed registration left an SCM service'}
  $gateway=Get-Service -Name GatewayCoreYarp
  if($gateway.Status -ne 'Stopped' -or $gateway.StartType -ne 'Manual'){throw 'Rollback changed dedicated gateway'}
  Write-Output "PASS: SCM $role post-create verification failure rolled back without changing gateway"
  $installed=& "$PSScriptRoot/Install-VipService.ps1" @params -Apply
  if(-not $installed.Applied){throw 'Installer did not report completion'}
  $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$plan.Name+"'")
  $expectedStart=if($role -eq 'agent'){'Auto'}else{'Manual'}
  $expectedIdentity=if($role -eq 'agent'){'LocalSystem'}else{$plan.Identity}
  if($svc.State -ne 'Stopped' -or $svc.StartMode -ne $expectedStart -or
     $svc.StartName -ne $expectedIdentity -or $svc.PathName -cne $plan.Command){throw "Unexpected installed role: $role"}
  $refused=$false
  try{& "$PSScriptRoot/Install-VipService.ps1" @params -Apply | Out-Null}
  catch{if($_.Exception.Message -notmatch 'Existing service'){throw};$refused=$true}
  if(-not $refused){throw 'Existing service overwrite was not refused'}
  Write-Output "PASS: SCM $role registration, exact identity/command/start mode, stopped state and overwrite refusal"
 }
}
finally{
 foreach($name in $created.ToArray()){
  $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
  if($null -ne $svc){
   if($svc.State -ne 'Stopped'){throw "Unexpected running fixture: $name"}
   $result=Invoke-CimMethod -InputObject $svc -MethodName Delete
   if($result.ReturnValue -ne 0){throw "Fixture cleanup failed: $name"}
  }
 }
 Remove-Item -LiteralPath $root -Recurse -Force
}
