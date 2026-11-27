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
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
 [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Luid; public uint Attributes; }
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token,bool disable,ref Privileges value,int length,out Privileges previous,out int returned);
 static Win32Exception Error(string stage) {
  int code=Marshal.GetLastWin32Error();
  return new Win32Exception(code,stage+" failed with Windows error "+code);
 }
 // Enable only the existing admin debug privilege to obtain a token from
 // the two exact disposable SCM processes, then restore before impersonating.
 static SafeAccessTokenHandle GetServiceToken(int pid) {
  SafeAccessTokenHandle current;
  if(!OpenProcessToken(GetCurrentProcess(),0x0028,out current)) throw Error("Open fixture administrator token");
  using(current) {
   Luid luid;
   if(!LookupPrivilegeValue(null,"SeDebugPrivilege",out luid)) throw Error("Lookup fixture debug privilege");
   var enable=new Privileges {Count=1,Luid=luid,Attributes=2};
   Privileges previous; int returned;
   if(!AdjustTokenPrivileges(current,false,ref enable,Marshal.SizeOf<Privileges>(),out previous,out returned) || Marshal.GetLastWin32Error()!=0)
    throw Error("Enable fixture debug privilege");
   SafeAccessTokenHandle result=null;
   try {
    IntPtr process=OpenProcess(0x1000,false,pid);
    if(process==IntPtr.Zero) throw Error("Open exact SCM process");
    try {
     if(!OpenProcessToken(process,0x000A,out result)) throw Error("Open exact SCM token");
    } finally {CloseHandle(process);}
   } finally {
    Privileges ignored; int unused;
    if(!AdjustTokenPrivileges(current,false,ref previous,Marshal.SizeOf<Privileges>(),out ignored,out unused) || Marshal.GetLastWin32Error()!=0) {
     if(result!=null)result.Dispose();
     throw Error("Restore fixture debug privilege");
    }
   }
   return result;
  }
 }
 public static void Check(int pid,string expectedSid,string own,string other) {
  using(var original=GetServiceToken(pid)) {
    SafeAccessTokenHandle impersonation;
    if(!DuplicateTokenEx(original,0x000C,IntPtr.Zero,2,2,out impersonation)) throw Error("Duplicate exact SCM token");
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
 Write-Output "PASS: $Name exact protected ACL allowlist"
 [VipRoleReadProbe]::Check([int]$service.ProcessId,$sid,$Own,$Other)
 Write-Output "PASS: $Name exact service token own/peer file access"
}
Check-Role 'GatewayCoreVipFenceProvider' $ProviderDirectory $ProviderKey $ControllerKey
Check-Role 'GatewayCoreVipController' $ControllerDirectory $ControllerKey $ProviderKey
Write-Output 'PASS: real Windows SCM role tokens can open own credential and cannot open peer credential'
