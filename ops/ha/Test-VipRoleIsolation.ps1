# Hosted-only acceptance against the live SCM service tokens; never reads secret contents.
param([Parameter(Mandatory)][string]$ProviderDirectory,[Parameter(Mandatory)][string]$ControllerDirectory,
 [Parameter(Mandatory)][string]$ProviderKey,[Parameter(Mandatory)][string]$ControllerKey)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $IsWindows){throw 'Hosted CI only'}
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class VipRoleReadProbe {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeAccessTokenHandle token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing,uint access,IntPtr attributes,int level,int type,out SafeAccessTokenHandle token);
 public static void Check(int pid,string expectedSid,string own,string other) {
  IntPtr process=OpenProcess(0x1000,false,pid);
  if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
  try {
   SafeAccessTokenHandle original;
   if(!OpenProcessToken(process,0x000A,out original)) throw new Win32Exception(Marshal.GetLastWin32Error());
   using(original) {
    SafeAccessTokenHandle impersonation;
    if(!DuplicateTokenEx(original,0x000C,IntPtr.Zero,2,2,out impersonation)) throw new Win32Exception(Marshal.GetLastWin32Error());
    using(impersonation) WindowsIdentity.RunImpersonated(impersonation,()=>{
     using(var identity=WindowsIdentity.GetCurrent()) {
      if(identity.User==null || identity.User.Value!=expectedSid) throw new InvalidOperationException("Unexpected SCM service token");
     }
     using(var stream=File.Open(own,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)) { if(stream.Length<1) throw new InvalidOperationException("Own credential missing"); }
     try { using(var denied=File.Open(other,FileMode.Open,FileAccess.Read,FileShare.ReadWrite)) {} }
     catch(UnauthorizedAccessException) { return; }
     throw new InvalidOperationException("Cross-role credential unexpectedly accessible");
    });
   }
  } finally { CloseHandle(process); }
 }
}
'@
function Check-Role($Name,$Directory,$Own,$Other){
 $root=Get-Item -LiteralPath $Directory
 if(-not $root.PSIsContainer -or $root.Name -notlike 'gc-vip-ci-*' -or $root.Parent.FullName -ne $env:ProgramData){throw 'Unexpected fixture path'}
 if((Split-Path -Parent $Own) -ne $root.FullName -or -not(Test-Path -LiteralPath $Other -PathType Leaf)){throw 'Expected fixture credential files'}
 $service=Get-CimInstance Win32_Service -Filter "Name='$Name'"
 if($service.State -ne 'Running' -or $service.ProcessId -lt 1 -or $service.StartName -ne "NT SERVICE\$Name"){throw 'Exact live virtual service identity required'}
 $sid=[Security.Principal.NTAccount]::new("NT SERVICE\$Name").Translate([Security.Principal.SecurityIdentifier]).Value
 $allowed=@('S-1-5-18','S-1-5-32-544',$sid)
 foreach($item in @($root)+@(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse)){
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked fixture refused'}
  $acl=Get-Acl -LiteralPath $item.FullName
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $allowed}){throw 'Unexpected cross-role allow ACE'}
  if(-not($rules | Where-Object {$_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $sid})){throw 'Own service ACE missing'}
 }
 [VipRoleReadProbe]::Check([int]$service.ProcessId,$sid,$Own,$Other)
}
Check-Role 'GatewayCoreVipFenceProvider' $ProviderDirectory $ProviderKey $ControllerKey
Check-Role 'GatewayCoreVipController' $ControllerDirectory $ControllerKey $ProviderKey
Write-Output 'PASS: real Windows SCM role tokens can open own credential and cannot open peer credential'
