# Real address acceptance on a dedicated in-box test adapter, never an existing NIC.
param([Parameter(Mandatory)][string]$Dll)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or -not $IsWindows){throw 'Hosted Windows CI only'}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated disposable runner required'}
$inf=Join-Path $env:SystemRoot 'INF\netloop.inf'
if(-not(Test-Path -LiteralPath $inf -PathType Leaf)){throw 'In-box Microsoft test adapter INF unavailable'}
foreach($device in Get-PnpDevice -Class Net){
 $ids=Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue
 if($ids.Data -contains '*MSLOOP'){throw 'Existing Microsoft test adapter; refuse mutation'}
}
if(@(Get-NetAdapter -IncludeHidden | Where-Object {$_.ComponentID -eq '*msloop'}).Count){throw 'Existing Microsoft test adapter; refuse mutation'}
# Register a fresh root-enumerated device using Windows SetupAPI. The driver
# itself is the Microsoft-signed in-box driver; no external downloads.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
public static class GatewayCoreCiTestAdapter {
 [StructLayout(LayoutKind.Sequential)] struct DevInfo {
  public int cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved;
 }
 [DllImport("setupapi.dll", SetLastError=true)] static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid g,IntPtr hwnd);
 [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool SetupDiCreateDeviceInfo(IntPtr set,string name,ref Guid g,string description,IntPtr hwnd,uint flags,ref DevInfo data);
 [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool SetupDiSetDeviceRegistryProperty(IntPtr set,ref DevInfo data,uint property,byte[] buffer,uint size);
 [DllImport("setupapi.dll", SetLastError=true)] static extern bool SetupDiCallClassInstaller(uint fn,IntPtr set,ref DevInfo data);
 [DllImport("setupapi.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool SetupDiGetDeviceInstanceId(IntPtr set,ref DevInfo data,StringBuilder id,int size,out int required);
 [DllImport("setupapi.dll", SetLastError=true)] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool UpdateDriverForPlugAndPlayDevices(IntPtr hwnd,string hwid,string inf,uint flags,out bool reboot);
 static void Check(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
 public static string Create(){
  Guid g=new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
  IntPtr set=SetupDiCreateDeviceInfoList(ref g,IntPtr.Zero);
  if(set==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error());
  var data=new DevInfo{cbSize=Marshal.SizeOf(typeof(DevInfo))};
  bool registered=false;
  try {
   Check(SetupDiCreateDeviceInfo(set,"Net",ref g,"GatewayCore disposable CI test adapter",IntPtr.Zero,1,ref data));
   byte[] hw=Encoding.Unicode.GetBytes("*MSLOOP\0\0");
   Check(SetupDiSetDeviceRegistryProperty(set,ref data,1,hw,(uint)hw.Length));
   Check(SetupDiCallClassInstaller(0x19,set,ref data)); registered=true;
   var id=new StringBuilder(1024);int required;
   Check(SetupDiGetDeviceInstanceId(set,ref data,id,id.Capacity,out required));
   return id.ToString();
  } catch {if(registered)SetupDiCallClassInstaller(5,set,ref data);throw;}
  finally {SetupDiDestroyDeviceInfoList(set);}
 }
 public static void Install(string inf){
  bool reboot;
  Check(UpdateDriverForPlugAndPlayDevices(IntPtr.Zero,"*MSLOOP",inf,4,out reboot));
  if(reboot)throw new InvalidOperationException("Test adapter requires reboot; refusing");
 }
}
'@
$id=$null
try{
 $id=[GatewayCoreCiTestAdapter]::Create()
 if($id -notmatch '^ROOT\\[^\\]+\\[0-9A-F]+$'){throw 'Unexpected generated device identity'}
 [GatewayCoreCiTestAdapter]::Install($inf)
 $adapter=$null
 for($i=0;$i -lt 40;$i++){
  $matches=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.PnPDeviceID -eq $id})
  if($matches.Count -eq 1 -and $matches[0].Status -eq 'Up'){$adapter=$matches[0];break}
  if($matches.Count -gt 1){throw 'Ambiguous adapter identity'}
  Start-Sleep -Milliseconds 500
 }
 if($null -eq $adapter -or $adapter.ComponentID -ne '*msloop'){throw 'Dedicated adapter not ready'}
 # Mutate only the newly created device's interface. No default route or
 # gateway is configured, and neither family uses DHCP.
 foreach($family in @('IPv4')){
  Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily $family -Dhcp Disabled -ErrorAction Stop
 }
 if(@(Get-NetRoute -InterfaceIndex $adapter.ifIndex | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count){throw 'Fixture unexpectedly has a default route'}
 $guid=([guid]$adapter.InterfaceGuid).ToString('D')
 & dotnet $Dll --isolated-windows-adapter $guid
 if($LASTEXITCODE -ne 0){throw 'Production address lifecycle test failed'}
 foreach($address in @('192.0.2.10')){
  if(@(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -ErrorAction Stop | Where-Object {$_.IPAddress -eq $address}).Count){throw 'Fixture address not withdrawn'}
 }
}
finally{
 if($id){
  & "$env:SystemRoot\System32\pnputil.exe" /remove-device $id
  if($LASTEXITCODE -ne 0){throw 'Failed to remove exact disposable test adapter'}
  if(@(Get-PnpDevice -PresentOnly -Class Net | Where-Object {$_.InstanceId -eq $id}).Count){throw 'Disposable adapter remains present'}
 }
}
