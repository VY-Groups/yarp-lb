using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

// The independent provider MUST durably isolate the predecessor before signing.
// TLS identity is separate from permit-signing trust. No provider key resides
// on the gateway or writer, and no shell/target/URL is supplied in the request.
internal sealed class VipFenceProvider : IDisposable
{
    internal sealed record Settings(string Origin,string LeafSha256,string CaFile,string CertFile,string KeyFile,
        string Scope,string[] OwnerPins);
    internal sealed record Request(string Scope,string OldPin,long RevokedEpoch,string NewPin);
    internal sealed record Permit(string Scope,string OldPin,long RevokedEpoch,string NewPin,long Expires,string Signature);
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web)
        {UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    private readonly HttpClient client;
    private readonly X509Certificate2 ca,credential;
    private readonly Uri endpoint;
    private VipFenceProvider(HttpClient client,X509Certificate2 ca,X509Certificate2 credential,Uri endpoint)
    {this.client=client;this.ca=ca;this.credential=credential;this.endpoint=endpoint;}
    internal static bool Pin(string? value)=>value is {Length:64}&&value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    internal static void ValidatePair(string scope,string oldPin,string newPin)
    {
        if(!Pin(scope)||!Pin(oldPin)||!Pin(newPin)||oldPin==newPin)
            throw new InvalidDataException("Exact distinct VIP predecessor and successor required.");
    }
    internal static VipFenceProvider Open(string path,string scope,string oldPin,string newPin)
    {
        ValidatePair(scope,oldPin,newPin);
        var s=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FleetQuorum.FilePath(path,16384,true)),Json)
            ??throw new InvalidDataException("Missing external fence provider settings.");
        if(s.Scope!=scope||s.OwnerPins is not {Length:2}||!s.OwnerPins.Contains(oldPin,StringComparer.Ordinal)||
            !s.OwnerPins.Contains(newPin,StringComparer.Ordinal)||!Pin(s.LeafSha256)||
            !Uri.TryCreate(s.Origin,UriKind.Absolute,out var origin)||origin.Scheme!="https"||
            origin.AbsolutePath!="/"||origin.Query!=""||origin.Fragment!=""||origin.UserInfo!="")
            throw new InvalidDataException("Exact independent HTTPS provider scope, pair and pin required.");
        var ca=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(s.CaFile,65536));
        X509Certificate2? credential=null;
        HttpClientHandler? handler=null;
        try
        {
            using var pem=X509Certificate2.CreateFromPemFile(FleetQuorum.FilePath(s.CertFile,65536),FleetQuorum.FilePath(s.KeyFile,65536,true));
            credential=X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12),null,
                OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
            if(s.OwnerPins.Contains(Convert.ToHexString(SHA256.HashData(credential.RawData)),StringComparer.Ordinal))
                throw new InvalidDataException("Provider client credential must be independent from gateway identities.");
            handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false,UseCookies=false};
            handler.ClientCertificates.Add(credential);
            var pin=Convert.FromHexString(s.LeafSha256);
            handler.ServerCertificateCustomValidationCallback=(_,leaf,_,errors)=>
            {
                if(leaf is null||(errors&(SslPolicyErrors.RemoteCertificateNameMismatch|SslPolicyErrors.RemoteCertificateNotAvailable))!=0||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.RawData),pin))return false;
                using var chain=new X509Chain();
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads=true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(leaf);
            };
            return new(new HttpClient(handler){Timeout=TimeSpan.FromSeconds(125),MaxResponseContentBufferSize=4096},
                ca,credential,new Uri(origin,"/v1/vip/hard-fence"));
        }
        catch{handler?.Dispose();credential?.Dispose();ca.Dispose();throw;}
    }
    internal static (long Expires,byte[] Signature) Validate(Request request,Permit permit,long now)
    {
        if(permit.Scope!=request.Scope||permit.OldPin!=request.OldPin||permit.NewPin!=request.NewPin||
            permit.RevokedEpoch!=request.RevokedEpoch||permit.Expires<=now||permit.Expires>now+300||
            permit.Signature is not {Length:>=84 and <=108})
            throw new InvalidDataException("Provider response does not match the exact bounded fencing transition.");
        byte[] signature=Convert.FromBase64String(permit.Signature);
        if(signature.Length is <64 or >80||Convert.ToBase64String(signature)!=permit.Signature)
            throw new InvalidDataException("Invalid canonical provider permit.");
        // FleetQuorum verifies the independent ECDSA signature again before CAS.
        return (permit.Expires,signature);
    }
    internal async Task<(long Expires,byte[] Signature)> Fence(Request request,CancellationToken token)
    {
        using var response=await client.PostAsJsonAsync(endpoint,request,Json,token);
        if(response.StatusCode!=System.Net.HttpStatusCode.OK)
            throw new InvalidDataException("Independent hard fencing not confirmed.");
        var body=await response.Content.ReadAsByteArrayAsync(token);
        if(body.Length>4096)throw new InvalidDataException("Oversized external fencing response.");
        var permit=JsonSerializer.Deserialize<Permit>(body,Json)??throw new InvalidDataException("Missing fence permit.");
        return Validate(request,permit,DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }
    internal sealed record NodeRequest(string Scope,string OwnerPin,long Epoch,string OtherPin,string Nonce);
    internal sealed record NodeEvidence(string Scope,string OwnerPin,long Epoch,string OtherPin,string Nonce,
        [property:JsonRequired] bool OwnerServing,[property:JsonRequired] bool OtherEligible,
        [property:JsonRequired] bool OwnerDrained,[property:JsonRequired] bool Quiescent);
    internal async Task<NodeEvidence> NodeAction(string action,string scope,string owner,long epoch,string other,CancellationToken token)
    {
        ValidatePair(scope,owner,other);
        if(epoch<1||action is not ("node-status" or "drain-node" or "activate-node" or "rearm-node"))
            throw new InvalidDataException("Invalid bounded provider action.");
        var request=new NodeRequest(scope,owner,epoch,other,Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        using var response=await client.PostAsJsonAsync(new Uri(endpoint,"/v1/vip/"+action),request,Json,token);
        if(response.StatusCode!=System.Net.HttpStatusCode.OK)
            throw new InvalidDataException("Independent node action unconfirmed.");
        var body=await response.Content.ReadAsByteArrayAsync(token);
        if(body.Length>4096)throw new InvalidDataException("Oversized node evidence.");
        var evidence=JsonSerializer.Deserialize<NodeEvidence>(body,Json)??throw new InvalidDataException("Missing node evidence.");
        return ValidateNode(request,evidence);
    }
    internal static NodeEvidence ValidateNode(NodeRequest request,NodeEvidence evidence)
    {
        if(evidence.Scope!=request.Scope||evidence.OwnerPin!=request.OwnerPin||evidence.Epoch!=request.Epoch||
            evidence.OtherPin!=request.OtherPin||evidence.Nonce!=request.Nonce)
            throw new InvalidDataException("Stale or unrelated independent node evidence.");
        return evidence;
    }
    public void Dispose(){client.Dispose();credential.Dispose();ca.Dispose();}
}

internal static class VipFencedTransfer
{
    internal static async Task<FleetQuorum.Fence> Run(string scope,string oldPin,long epoch,string newPin,bool resume,
        Func<CancellationToken,Task<FleetQuorum.Fence?>> observe,
        Func<string,long,CancellationToken,Task<FleetQuorum.Fence>> revoke,
        Func<VipFenceProvider.Request,CancellationToken,Task<(long Expires,byte[] Signature)>> fence,
        Func<string,long,string,long,byte[],CancellationToken,Task<FleetQuorum.Fence>> activate,
        CancellationToken token)
    {
        VipFenceProvider.ValidatePair(scope,oldPin,newPin);
        if(epoch<1)throw new InvalidDataException("Exact positive ownership revision required.");
        var before=await observe(token);
        var expected=new FleetQuorum.Fence((resume?"vip_revoked_":"vip_")+oldPin,epoch);
        if(before!=expected)throw new FleetQuorumContentionException();
        var revoked=resume?expected:await revoke(oldPin,epoch,token);
        if(revoked.Transaction!="vip_revoked_"+oldPin||revoked.Epoch<1||(!resume&&revoked.Epoch<=epoch)||
            await observe(token)!=revoked)throw new InvalidDataException("Revocation not confirmed by majority.");
        var permit=await fence(new(scope,oldPin,revoked.Epoch,newPin),token);
        if(await observe(token)!=revoked)throw new FleetQuorumContentionException();
        return await activate(oldPin,revoked.Epoch,newPin,permit.Expires,permit.Signature,token);
        // Never auto-unrevoke or retry a failed provider/activation. Explicit
        // resume uses the exact observed revoked revision after reconciliation.
    }
}
