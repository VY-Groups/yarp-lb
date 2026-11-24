#if GATEWAYCORE_COMMERCIAL
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using GatewayCore.Licensing;

// No network or per-request disk I/O. An engine must never retain a feature
// after signed expiry; unreadable state and stalled refresh fail closed.
internal sealed class EngineLicenseGate : IDisposable
{
    private sealed record Snapshot(VerifiedLicense License,long ExpiryTick,long RefreshTick);
    private readonly OfflineLicenseStore store;
    private readonly object sync=new();
    private readonly Timer timer;
    private Snapshot? snapshot;
    private string? lastPayload;
    private long lastExpiryTick;
    private EngineLicenseGate(OfflineLicenseStore store)
    {
        this.store=store;
        Refresh();
        timer=new Timer(_=>Refresh(),null,TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(1));
    }
    private static OfflineLicenseStore Open()
    {
        var directory=Environment.GetEnvironmentVariable("GATEWAYCORE_ENGINE_LICENSE_DIR");
        if(string.IsNullOrWhiteSpace(directory)||!Path.IsPathFullyQualified(directory))
            throw new InvalidOperationException("Absolute local engine license directory required.");
        using var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("GatewayCore.CommercialTrust")
            ?? throw new InvalidDataException("Missing engine public trust.");
        if(stream.Length is < 1 or > 16384)throw new InvalidDataException("Invalid engine public trust.");
        var keys=JsonSerializer.Deserialize<Dictionary<string,byte[]>>(stream)
            ?? throw new InvalidDataException("Missing engine trust.");
        return new OfflineLicenseStore(directory,new OfflineLicenseVerifier(keys));
    }
    public static bool Command(string[] args,out int code)
    {
        code=0;
        if(args.Length==0||!args[0].StartsWith("--license-",StringComparison.Ordinal))return false;
        try
        {
            var store=Open();
            if(args is ["--license-init"])store.Initialize();
            else if(args is ["--license-request",var output])
            {
                using var file=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None);
                file.Write(store.ExportActivationRequest());file.Flush(true);
            }
            else if(args.Length==2 && args[0] is "--license-import" or "--license-revoke")
            {
                using var file=new FileStream(args[1],FileMode.Open,FileAccess.Read,FileShare.Read);
                if(file.Length is < 1 or > OfflineLicenseVerifier.MaxLicenseBytes)throw new InvalidDataException("Invalid license size.");
                var bytes=new byte[(int)file.Length];file.ReadExactly(bytes);
                if(file.ReadByte()!=-1)throw new InvalidDataException("License changed.");
                var result=args[0]=="--license-import"?store.Import(bytes,DateTimeOffset.UtcNow):
                    store.ImportRevocation(bytes,DateTimeOffset.UtcNow);
                Console.WriteLine(result.Validity.ToString());
            }
            else throw new ArgumentException("Use --license-init, --license-request FILE, --license-import FILE or --license-revoke FILE.");
        }
        catch(Exception e){Console.Error.WriteLine("Engine licensing rejected: "+e.GetType().Name);code=78;}
        return true;
    }
    public static EngineLicenseGate Start(params string[] required)
    {
        var gate=new EngineLicenseGate(Open());
        if(required.All(gate.Allows))return gate;
        gate.Dispose();
        throw new InvalidOperationException("Active engine feature entitlement required.");
    }
    private void Refresh()
    {
        lock(sync)
        {
            try
            {
                var now=DateTimeOffset.UtcNow;
                var license=store.Inspect(now);
                if(license is not {Validity:LicenseValidity.Active})
                {Volatile.Write(ref snapshot,null);return;}
                var tick=Environment.TickCount64;
                var expiry=tick+Math.Max(0L,(long)(license.ExpiresAt-now).TotalMilliseconds);
                if(lastPayload==license.PayloadSha256)expiry=Math.Min(lastExpiryTick,expiry);
                lastPayload=license.PayloadSha256;lastExpiryTick=expiry;
                Volatile.Write(ref snapshot,new Snapshot(license,expiry,tick+3000));
            }
            catch(Exception e) when(e is IOException or CryptographicException or InvalidDataException or
                FormatException or JsonException or UnauthorizedAccessException or ArgumentException or InvalidOperationException)
            {Volatile.Write(ref snapshot,null);}
        }
    }
    public bool Allows(string feature)
    {
        var value=Volatile.Read(ref snapshot);
        var tick=Environment.TickCount64;
        return value is not null && tick<value.ExpiryTick && tick<value.RefreshTick &&
            DateTimeOffset.UtcNow<value.License.ExpiresAt && value.License.Allows(feature);
    }
    public void Dispose()=>timer.Dispose();
}
#endif
