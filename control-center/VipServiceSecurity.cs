using System.Text.Json;
using GatewayCore.Gslb.Contracts;

// Hosted VIP roles have an independently provisioned private directory per
// identity. Never repair permissions silently or share an authority key.
internal static class VipServiceSecurity
{
    // Emit a fixed event only for an exact file allow-ACE refusal.
    // Never include paths, secret content, or exception text.
    internal static void ReportWindowsFileAclRefusal(Exception error,int eventId)
    {
        if(!OperatingSystem.IsWindows()||error is not WindowsPrivateFileAclException)return;
        try
        {
            System.Diagnostics.EventLog.WriteEntry("GatewayCoreVipSecurity",
                "VIP service startup refused: unapproved private-file allow ACE.",
                System.Diagnostics.EventLogEntryType.Error,eventId);
        }
        catch(Exception e) when(e is InvalidOperationException or System.ComponentModel.Win32Exception or
            UnauthorizedAccessException or System.Security.SecurityException or ArgumentException)
        {Console.Error.WriteLine("VIP Windows refusal event unavailable: "+e.GetType().Name);}
    }
    internal static void Directory(string path)
    {
        if(!Path.IsPathFullyQualified(path))throw new InvalidDataException("Absolute private VIP state directory required.");
        if(OperatingSystem.IsWindows())WindowsStateProtection.ValidateOfflineKeyRingDirectory(path,true);
        else if(OperatingSystem.IsLinux())PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(path,"VIP service");
        else throw new PlatformNotSupportedException("Unsupported VIP service platform.");
    }
    internal static string RequireFile(string path,int max=65536)
    {
        if(string.IsNullOrWhiteSpace(path)||!Path.IsPathFullyQualified(path))
            throw new InvalidDataException("Absolute private VIP credential path required.");
        Directory(Path.GetDirectoryName(path)!);
        return FleetQuorum.FilePath(path,max,true);
    }
    internal static void Journal(string path)
    {
        if(!Path.IsPathFullyQualified(path))throw new InvalidDataException("Absolute private journal path required.");
        Directory(Path.GetDirectoryName(path)!);
        // An idle journal is legitimately empty; credentials never are.
        if(File.Exists(path))_ = FleetQuorum.FilePath(path,1024*1024,true,allowEmpty:true);
        else if(new FileInfo(path).LinkTarget is not null || System.IO.Directory.Exists(path))
            throw new InvalidDataException("Invalid journal path.");
    }
    internal static void Quorum(string path,bool writer=false)
    {
        var s=JsonSerializer.Deserialize<FleetQuorum.Settings>(File.ReadAllBytes(RequireFile(path,16384)),VipMachineTransport.Json)
            ??throw new InvalidDataException("Missing quorum configuration.");
        RequireFile(s.CaFile);RequireFile(s.CertFile);RequireFile(s.KeyFile);
        if(writer)RequireFile(s.VipFencePublicKeyFile!,16384);
    }
    internal static void Client(VipMachineTransport.ClientSettings s)
    {RequireFile(s.CaFile);RequireFile(s.CertFile);RequireFile(s.KeyFile);}
    internal static void Controller(string[] args)
    {
        if(args.Length!=7||args[3] is not ("automatic-policy" or "recover-policy"))throw new InvalidDataException("Hosted policy command required.");
        Quorum(args[1],true);RequireFile(args[4],8192);
        var p=JsonSerializer.Deserialize<VipFenceProvider.Settings>(File.ReadAllBytes(RequireFile(args[5],16384)),VipMachineTransport.Json)
            ??throw new InvalidDataException("Missing fencing provider settings.");
        RequireFile(p.CaFile);RequireFile(p.CertFile);RequireFile(p.KeyFile);
        Journal(args[6]);
    }
}
