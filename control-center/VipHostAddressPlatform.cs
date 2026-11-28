using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using GatewayCore.Gslb.Contracts;

internal static class VipHostAddressPlatform
{
    internal static IPAddress Parse(string text)
    {
        if(!IPAddress.TryParse(text,out var ip)||ip.ToString()!=text)
            throw new InvalidDataException("Canonical IP VIP required.");
        var bytes=ip.GetAddressBytes();
        if(ip.AddressFamily==AddressFamily.InterNetworkV6)
        {
            // Global unicast and unique-local only; no scoped, mapped, multicast,
            // link-local, loopback, unspecified or IPv4-compatible addresses.
            if(ip.ScopeId!=0||((bytes[0]&0xe0)!=0x20&&(bytes[0]&0xfe)!=0xfc))
                throw new InvalidDataException("Special-purpose IPv6 address refused.");
        }
        else if(ip.AddressFamily!=AddressFamily.InterNetwork||
            bytes[0] is 0 or 127 or >=224 || (bytes[0]==169&&bytes[1]==254))
            throw new InvalidDataException("Special-purpose IPv4 address refused.");
        return ip;
    }
    internal sealed record Observation(string InterfaceId,string Name,int Index,bool Present,bool Ready,IPAddress? ManagementAddress=null);
    internal static Observation Inspect(string interfaceId,IPAddress address,IPAddress? management=null)
    {
        var snapshot=NetworkInterface.GetAllNetworkInterfaces();
        if(snapshot.Length>256)throw new InvalidDataException("Incomplete interface inventory.");
        var target=snapshot.SingleOrDefault(n=>n.Id==interfaceId)
            ??throw new InvalidDataException("Exact local interface identity required.");
        if(target.OperationalStatus!=OperationalStatus.Up || target.NetworkInterfaceType is
            NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
            throw new InvalidDataException("Dedicated up interface required.");
        var properties=target.GetIPProperties();
        if(properties.GatewayAddresses.Count!=0 ||
            (management is not null && properties.UnicastAddresses.Any(x=>x.Address.Equals(management))))
            throw new InvalidDataException("Management or default gateway interface refused.");
        bool v6=address.AddressFamily==AddressFamily.InterNetworkV6;
        int index=v6?(properties.GetIPv6Properties()?.Index??throw new InvalidDataException("IPv6 interface required.")):
            (properties.GetIPv4Properties()?.Index??throw new InvalidDataException("IPv4 interface required."));
        int prefix=v6?128:32;
        var matches=new List<(string Id,int Prefix,bool Ready)>();
        foreach(var n in snapshot)
        {
            var entries=n.GetIPProperties().UnicastAddresses;
            if(entries.Count>128)throw new InvalidDataException("Incomplete address inventory.");
            foreach(var entry in entries)
                if(entry.Address.Equals(address))
                    matches.Add((n.Id,entry.PrefixLength,OperatingSystem.IsWindows()
                        ? entry.DuplicateAddressDetectionState==DuplicateAddressDetectionState.Preferred
                        : !v6||VipIpv6Readiness.IsReady(entry,index,n.Name,VipIpv6Readiness.ReadLinux())));
        }
        if(matches.Count>1 || (matches.Count==1&&(matches[0].Id!=target.Id||matches[0].Prefix!=prefix)))
            throw new InvalidDataException("VIP is already assigned elsewhere or with a different prefix.");
        return new(target.Id,target.Name,index,matches.Count==1,matches.Count==1&&matches[0].Ready,management);
    }
    internal static async Task Change(Observation observation,IPAddress address,bool add,CancellationToken token)
    {
        var current=Inspect(observation.InterfaceId,address,observation.ManagementAddress);
        if(current.Index!=observation.Index || current.Name!=observation.Name || current.Present==add)
            throw new InvalidDataException("Interface or address changed before mutation.");
        bool v6=address.AddressFamily==AddressFamily.InterNetworkV6;
        ProcessStartInfo start;
        if(OperatingSystem.IsLinux())
        {
            if(!Regex.IsMatch(current.Name,@"\A[A-Za-z0-9_.-]{1,15}\z") || current.Name.StartsWith('-'))
                throw new InvalidDataException("Unsupported Linux interface name.");
            // Ubuntu's iproute2 can expose /usr/sbin/ip -> /bin/ip with /bin
            // itself a merged-usr link. Choose the actual installed regular
            // executable in an allowlisted canonical directory, never a PATH
            // lookup or an arbitrary symlink target.
            var resolved=new[]{"/usr/bin/ip","/usr/sbin/ip"}
                .FirstOrDefault(candidate=>File.Exists(candidate) &&
                    (File.GetAttributes(candidate)&FileAttributes.ReparsePoint)==0)
                ??throw new InvalidDataException("Canonical iproute2 executable unavailable.");
            PrivateKeyFileSecurity.ValidateLinuxTrustedExecutableDirectory(Path.GetDirectoryName(resolved)!,"VIP address tool");
            if((File.GetUnixFileMode(resolved)&(UnixFileMode.GroupWrite|UnixFileMode.OtherWrite))!=0)
                throw new InvalidDataException("Untrusted IP executable.");
            start=new ProcessStartInfo(resolved);
            foreach(string arg in new[]{v6?"-6":"-4","address",add?"add":"del",address+(v6?"/128":"/32"),"dev",current.Name})
                start.ArgumentList.Add(arg);
            if(add)start.ArgumentList.Add("noprefixroute");
        }
        else if(OperatingSystem.IsWindows())
        {
            // No user-supplied PowerShell source or shell interpolation.
            const string script="""
            $ErrorActionPreference='Stop'
            $ProgressPreference='SilentlyContinue'
            $i=[int]$env:GC_VIP_INTERFACE_INDEX
            $a=[string]$env:GC_VIP_ADDRESS
            $family=[string]$env:GC_VIP_FAMILY
            $prefix=[int]$env:GC_VIP_PREFIX
            $m=[string]$env:GC_VIP_MANAGEMENT_ADDRESS
            if(@(Get-NetRoute -InterfaceIndex $i -PolicyStore ActiveStore | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}).Count){throw 'Default-route interface refused'}
            if($m -and @(Get-NetIPAddress -InterfaceIndex $i -PolicyStore ActiveStore | Where-Object {$_.IPAddress -eq $m}).Count){throw 'Management interface refused'}
            $iface=Get-NetIPInterface -InterfaceIndex $i -AddressFamily $family -PolicyStore ActiveStore
            if($iface.Dhcp -ne 'Disabled'){throw 'Dedicated static interface required'}
            $existing=@(Get-NetIPAddress -AddressFamily $family -PolicyStore ActiveStore | Where-Object {$_.IPAddress -eq $a})
            if($env:GC_VIP_ADD -eq '1'){
              if($existing.Count -ne 0){throw 'Address already exists'}
              New-NetIPAddress -InterfaceIndex $i -IPAddress $a -PrefixLength $prefix -SkipAsSource $true -PolicyStore ActiveStore | Out-Null
            } else {
              if($existing.Count -ne 1 -or $existing[0].InterfaceIndex -ne $i -or $existing[0].PrefixLength -ne $prefix){throw 'Exact address required'}
              Remove-NetIPAddress -InputObject $existing[0] -Confirm:$false
            }
            """;
            start=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"));
            foreach(var arg in new[]{"-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(script))})
                start.ArgumentList.Add(arg);
            start.Environment["GC_VIP_INTERFACE_INDEX"]=current.Index.ToString(CultureInfo.InvariantCulture);
            start.Environment["GC_VIP_ADDRESS"]=address.ToString();
            start.Environment["GC_VIP_MANAGEMENT_ADDRESS"]=current.ManagementAddress?.ToString()??"";
            start.Environment["GC_VIP_ADD"]=add?"1":"0";
            start.Environment["GC_VIP_FAMILY"]=v6?"IPv6":"IPv4";
            start.Environment["GC_VIP_PREFIX"]=v6?"128":"32";
        }
        else throw new PlatformNotSupportedException("VIP address mutation supports Linux and Windows.");
        start.UseShellExecute=false;
        start.RedirectStandardOutput=true;start.RedirectStandardError=true;start.CreateNoWindow=true;
        // Revalidate after preparing the command and before starting the privileged process.
        var boundary=Inspect(current.InterfaceId,address,current.ManagementAddress);
        if(boundary!=current)throw new InvalidDataException("Interface or address changed before mutation.");
        token.ThrowIfCancellationRequested();
        using var process=Process.Start(start)??throw new InvalidOperationException("Address command did not start.");
        var output=process.StandardOutput.ReadToEndAsync();
        var error=process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync(token); }
        catch(OperationCanceledException)
        {
            try {process.Kill(entireProcessTree:true);}catch(InvalidOperationException){}
            await process.WaitForExitAsync();
            throw;
        }
        await Task.WhenAll(output,error);
        if(process.ExitCode!=0)throw new InvalidOperationException("Operating system address operation failed.");
        for(int attempt=0;attempt<20;attempt++)
        {
            token.ThrowIfCancellationRequested();
            var observed=Inspect(current.InterfaceId,address,current.ManagementAddress);
            if(add?observed.Ready:!observed.Present)return;
            await Task.Delay(250,token);
        }
        throw new InvalidOperationException("Operating system address state not confirmed.");
    }
}
