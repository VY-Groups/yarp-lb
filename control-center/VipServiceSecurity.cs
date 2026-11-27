using System.Text.Json;
using GatewayCore.Gslb.Contracts;

// Hosted VIP roles have an independently provisioned private directory per
// identity. Never repair permissions silently or share an authority key.
internal static class VipServiceSecurity
{
    internal static void Directory(string path)
    {
        if(!Path.IsPathFullyQualified(path))throw new InvalidDataException("Absolute private VIP state directory required.");
        if(OperatingSystem.IsWindows())WindowsStateProtection.ValidateOfflineKeyRingDirectory(path);
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
        if(args.Length!=7||args[3]!="automatic-policy")throw new InvalidDataException("Hosted policy command required.");
        Quorum(args[1],true);RequireFile(args[4],8192);
        var p=JsonSerializer.Deserialize<VipFenceProvider.Settings>(File.ReadAllBytes(RequireFile(args[5],16384)),VipMachineTransport.Json)
            ??throw new InvalidDataException("Missing fencing provider settings.");
        RequireFile(p.CaFile);RequireFile(p.CertFile);RequireFile(p.KeyFile);
        if(!Path.IsPathFullyQualified(args[6]))throw new InvalidDataException("Absolute journal path required.");
        Directory(Path.GetDirectoryName(args[6])!);
        if(File.Exists(args[6]))RequireFile(args[6],1024*1024);
    }
}
