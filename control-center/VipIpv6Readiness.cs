using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

internal static class VipIpv6Readiness
{
    // Linux exposes address flags through the kernel, not the Windows-only
    // DuplicateAddressDetectionState API. Missing or oversized data denies IPv6.
    internal static string? ReadLinux()
    {
        if(!OperatingSystem.IsLinux())return null;
        try
        {
            using var reader=new StreamReader("/proc/net/if_inet6");
            var buffer=new char[65537];
            int count=reader.ReadBlock(buffer,0,buffer.Length);
            return count==buffer.Length?null:new string(buffer,0,count);
        }
        catch(IOException){return null;}
        catch(UnauthorizedAccessException){return null;}
    }
    internal static bool LinuxReady(string? snapshot,IPAddress address,int index,string name)
    {
        if(snapshot is null||snapshot.Length>65536||index<=0)return false;
        string expected=Convert.ToHexString(address.GetAddressBytes());
        int matches=0;
        bool ready=false;
        foreach(var line in snapshot.Split('\n',StringSplitOptions.RemoveEmptyEntries))
        {
            var fields=line.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            if(fields.Length!=6)return false;
            if(!fields[0].Equals(expected,StringComparison.OrdinalIgnoreCase)||fields[5]!=name)continue;
            if(!int.TryParse(fields[1],NumberStyles.HexNumber,CultureInfo.InvariantCulture,out int actualIndex)||actualIndex!=index||
                !int.TryParse(fields[4],NumberStyles.HexNumber,CultureInfo.InvariantCulture,out int flags))return false;
            matches++;
            // OPTIMISTIC, DADFAILED, DEPRECATED, TENTATIVE.
            ready=(flags&0x6c)==0;
        }
        return matches==1&&ready;
    }
    internal static bool IsReady(UnicastIPAddressInformation entry,int index,string name,string? linux)
    {
        if(entry.Address.AddressFamily!=AddressFamily.InterNetworkV6)return true;
        if(OperatingSystem.IsLinux())return LinuxReady(linux,entry.Address,index,name);
        if(OperatingSystem.IsWindows())return entry.DuplicateAddressDetectionState==DuplicateAddressDetectionState.Preferred;
        return false;
    }
}
