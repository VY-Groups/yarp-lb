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
    // Local, offline and nonmutating. Run as the intended independent
    // controller identity with the service stopped. Never claim network readiness.
    internal static int InspectController(string[] args)
    {
        try
        {
            Controller(args);
            var policy=VipPolicyDocument.Load(args[4],args[2],out var digest,args.Length==8?args[7]:null);
            using var authority=FleetQuorum.OpenVipWriter(args[1],args[2]);
            if(authority.VipReaderPin==policy.PreferredPin||authority.VipReaderPin==policy.OtherPin)
                throw new InvalidDataException("Writer must be independent from gateway identities.");
            using var provider=VipFenceProvider.Open(args[5],args[2],policy.PreferredPin,policy.OtherPin);
            bool exists=File.Exists(args[6]);
            using var journal=exists?new VipAutomaticJournal(args[6],args[2],policy.PreferredPin,policy.OtherPin,readOnly:true):null;
            Console.WriteLine(JsonSerializer.Serialize(new{
                validated=true,networkVerified=false,mutated=false,scope=policy.Scope,
                policySha256=digest,digestVerified=args.Length==8,
                journalExists=exists,recoveryRequired=journal?.Pending is not null,
                lastCompletedEpoch=journal?.LastCompletedEpoch??0,
                lastRearmAttemptEpoch=journal?.LastRearmAttemptEpoch??0,
                pending=journal?.Pending is { } intent?new {intent.OldEpoch,intent.Kind}:null
            }));
            return 0;
        }
        catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException or ArgumentException or JsonException or System.Security.Cryptography.CryptographicException or
            FormatException or OverflowException or PlatformNotSupportedException)
        {Console.Error.WriteLine("VIP offline controller validation refused: "+e.GetType().Name);return 78;}
    }
    internal static void Controller(string[] args)
    {
        if(args.Length is not (7 or 8)||args[3] is not ("automatic-policy" or "recover-policy" or "inspect-policy"))throw new InvalidDataException("Hosted policy command required.");
        Quorum(args[1],true);RequireFile(args[4],8192);
        var p=JsonSerializer.Deserialize<VipFenceProvider.Settings>(File.ReadAllBytes(RequireFile(args[5],16384)),VipMachineTransport.Json)
            ??throw new InvalidDataException("Missing fencing provider settings.");
        RequireFile(p.CaFile);RequireFile(p.CertFile);RequireFile(p.KeyFile);
        Journal(args[6]);
    }
}
