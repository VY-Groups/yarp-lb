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
    internal static VipPolicyDocument Load(string path,string scope)
    {
        var policy=JsonSerializer.Deserialize<VipPolicyDocument>(File.ReadAllBytes(FleetQuorum.FilePath(path,8192,true)),Json)
            ??throw new InvalidDataException("Missing HA policy.");
        policy.Validate(scope);return policy;
    }
}
