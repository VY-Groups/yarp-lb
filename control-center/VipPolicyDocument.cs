using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

// Nonsecret, exact-scope policy interchange. Gateway UI may prepare this
// document; only the independent writer loads it from a protected local file.
internal sealed record VipPolicyDocument(int Version,string Scope,string PreferredPin,string OtherPin,
    [property:JsonRequired] bool FailbackEnabled,int PollSeconds,int FailureSamples,int FailureSeconds,
    int FailbackEligibleSeconds,int MinimumOwnerSeconds,bool RearmEnabled=false)
{
    internal static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web)
        {UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,WriteIndented=true};
    internal static VipPolicyDocument Default(string scope,string preferred,string other,bool failback)=>
        new(1,scope,preferred,other,failback,5,3,10,120,300);
    internal void Validate(string scope)
    {
        VipFenceProvider.ValidatePair(Scope,PreferredPin,OtherPin);
        if(Version!=1||Scope!=scope||PollSeconds is <5 or >60||FailureSamples is <3 or >20||
            FailureSeconds is <10 or >600||FailureSeconds<(FailureSamples-1)*PollSeconds||
            FailbackEligibleSeconds is <120 or >3600||MinimumOwnerSeconds is <300 or >86400||
            MinimumOwnerSeconds<FailbackEligibleSeconds)
            throw new InvalidDataException("HA policy exceeds supported safety bounds or scope.");
    }
    internal static VipPolicyDocument Load(string path,string scope,string? expectedSha256=null)=>
        Load(path,scope,out _,expectedSha256);

    // Hash the exact bytes that are parsed, not a separate file read. The
    // independently approved digest is an integrity binding, not a signature.
    internal static VipPolicyDocument Load(string path,string scope,out string digest,string? expectedSha256=null)
    {
        var bytes=File.ReadAllBytes(FleetQuorum.FilePath(path,8192,true));
        if(bytes.Length is <1 or >8192)throw new InvalidDataException("HA policy size refused.");
        digest=Convert.ToHexString(SHA256.HashData(bytes));
        if(expectedSha256 is not null &&
            (expectedSha256.Length!=64 || expectedSha256.Any(c=>!Uri.IsHexDigit(c)) ||
             !string.Equals(digest,expectedSha256,StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("HA policy does not match the independently approved SHA-256.");
        var policy=JsonSerializer.Deserialize<VipPolicyDocument>(bytes,Json)
            ??throw new InvalidDataException("Missing HA policy.");
        policy.Validate(scope);return policy;
    }
}
