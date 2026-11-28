# Disposable fixture ACL provisioning: replace, never merge, the DACL.
param([Parameter(Mandatory)][string]$Directory,[Parameter(Mandatory)][string]$Identity)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $IsWindows){throw 'Hosted CI only'}
$root=Get-Item -LiteralPath $Directory
if(-not $root.PSIsContainer -or $root.Name -notlike 'gc-vip-*' -or $root.Parent.FullName -ne $env:ProgramData){throw 'Expected exact disposable fixture directory'}
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$sid=[Security.Principal.NTAccount]::new($Identity).Translate([Security.Principal.SecurityIdentifier])
$principals=@($system,$admins,$sid) | Select-Object -Unique
function Protect([System.IO.FileSystemInfo]$item){
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked fixture refused'}
 if($item.PSIsContainer){
  $acl=[Security.AccessControl.DirectorySecurity]::new()
  $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
 }else{
  $acl=[Security.AccessControl.FileSecurity]::new()
  $inherit=[Security.AccessControl.InheritanceFlags]::None
 }
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner($admins)
 foreach($p in $principals){
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($p,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
 }
 Set-Acl -LiteralPath $item.FullName -AclObject $acl
}
Protect $root
foreach($item in Get-ChildItem -LiteralPath $root.FullName -Force -Recurse){Protect $item}
