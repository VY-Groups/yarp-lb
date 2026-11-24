using System.Globalization;
using System.Net.Security;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

// Persistent Raft lock, deliberately NOT an expiring lease. A crash or partition
// cannot grant another controller ownership while a mutation may be in flight.
// No automatic force-unlock. Recovery uses the original transaction/epoch.
internal sealed class FleetQuorumContentionException : InvalidOperationException
{
    internal FleetQuorumContentionException():base("Another fleet transaction owns or completed the quorum fence."){}
}
internal sealed class FleetQuorum : IDisposable
{
    internal sealed record Endpoint(string Url,string LeafSha256,string MemberId);
    internal sealed record Settings(string Scope,string ClusterId,string CaFile,string CertFile,string KeyFile,Endpoint[] Endpoints);
    internal sealed record Fence(string Transaction,long Epoch);
    private sealed record Peer(Uri Origin,ulong Id,HttpClient Client);
    private readonly Peer[] peers;
    private readonly ulong cluster;
    private readonly X509Certificate2 ca,credential;
    private readonly string key,namespaceKey;
    private readonly bool writable;
    internal string Scope { get; }
    internal static string DeploymentScope(string license,string customer,string deployment)=>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(license+"\n"+customer+"\n"+deployment)));
    private static bool Hex(string? value)=>value is {Length:64} && value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool Tx(string? value)=>value is not null && Regex.IsMatch(value,@"\Arollout_[A-F0-9]{24}\z",RegexOptions.CultureInvariant);
    private static string Base64(string text)=>Convert.ToBase64String(Encoding.ASCII.GetBytes(text));
    private static string FilePath(string path,int max,bool secret=false)
    {
        if(!Path.IsPathFullyQualified(path))throw new InvalidDataException("Absolute quorum credential/config path required.");
        var info=new FileInfo(path);
        if(!info.Exists || info.Length is <1 || info.Length>max || (info.Attributes&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Invalid quorum credential/config file.");
        if(secret && !OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|
                UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)
            throw new InvalidDataException("Quorum credential/config file must be owner-private.");
        return path;
    }
    private static ulong Number(string? value)
    {
        if(!ulong.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var n) || n==0 ||
            n.ToString(CultureInfo.InvariantCulture)!=value)throw new InvalidDataException("Invalid etcd identity.");
        return n;
    }
    private static ulong Number(JsonElement value)=>Number(value.ValueKind==JsonValueKind.String?value.GetString():value.GetRawText());
    internal static FleetQuorum? Open(string? path,bool writable)
    {
        if(string.IsNullOrWhiteSpace(path))return null;
        var opts=new JsonSerializerOptions(JsonSerializerDefaults.Web){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
        var settings=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FilePath(path,16384,true)),opts)
            ??throw new InvalidDataException("Missing quorum settings.");
        return new FleetQuorum(settings,writable);
    }
    private FleetQuorum(Settings settings,bool writable)
    {
        if(!Hex(settings.Scope) || settings.Endpoints is not {Length:3})
            throw new InvalidDataException("Require one deployment scope and exactly three pinned members.");
        Scope=settings.Scope;this.writable=writable;cluster=Number(settings.ClusterId);
        namespaceKey="/gatewaycore/commercial-fleet/v1/"+Scope;
        key=Base64(namespaceKey);
        var endpoints=settings.Endpoints.Select(e=>
        {
            if(!Uri.TryCreate(e.Url,UriKind.Absolute,out var uri) || uri.Scheme!="https" ||
                uri.AbsolutePath!="/" || uri.UserInfo!="" || uri.Query!="" || uri.Fragment!="" || !Hex(e.LeafSha256))
                throw new InvalidDataException("Invalid quorum HTTPS member or pin.");
            return (Origin:uri,Id:Number(e.MemberId),Pin:e.LeafSha256);
        }).ToArray();
        if(endpoints.Select(x=>x.Origin.Authority).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=3 ||
           endpoints.Select(x=>x.Id).Distinct().Count()!=3 || endpoints.Select(x=>x.Pin).Distinct(StringComparer.Ordinal).Count()!=3)
            throw new InvalidDataException("Duplicate quorum endpoint, identity or TLS leaf.");
        ca=X509CertificateLoader.LoadCertificateFromFile(FilePath(settings.CaFile,65536));
        using var pem=X509Certificate2.CreateFromPemFile(FilePath(settings.CertFile,65536),FilePath(settings.KeyFile,65536,true));
        credential=X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12),null,X509KeyStorageFlags.EphemeralKeySet);
        peers=endpoints.Select(e=>
        {
            var handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false};
            handler.ClientCertificates.Add(credential);
            handler.ServerCertificateCustomValidationCallback=(_,leaf,_,errors)=>
            {
                if(leaf is null || (errors&(SslPolicyErrors.RemoteCertificateNameMismatch|SslPolicyErrors.RemoteCertificateNotAvailable))!=0 ||
                    !CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.RawData),Convert.FromHexString(e.Pin)))return false;
                using var chain=new X509Chain();
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(ca);
                // Exact leaf pin plus independently provisioned CA and hostname.
                // Pin/CA rotation and revocation are external operational controls.
                chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads=true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                return chain.Build(leaf);
            };
            return new Peer(e.Origin,e.Id,new HttpClient(handler){Timeout=TimeSpan.FromSeconds(4),MaxResponseContentBufferSize=16384});
        }).ToArray();
    }
    private async Task<JsonElement> Post(Peer peer,string route,object body,CancellationToken token)
    {
        using var reply=await peer.Client.PostAsJsonAsync(new Uri(peer.Origin,route),body,token);
        if((int)reply.StatusCode>=500)throw new HttpRequestException("Etcd member unavailable.");
        if(!reply.IsSuccessStatusCode)throw new InvalidDataException("Etcd request refused.");
        using var doc=JsonDocument.Parse(await reply.Content.ReadAsByteArrayAsync(token));
        var root=doc.RootElement;
        var header=root.GetProperty("header");
        if(Number(header.GetProperty("cluster_id"))!=cluster || Number(header.GetProperty("member_id"))!=peer.Id)
            throw new InvalidDataException("Pinned Raft identity mismatch.");
        return root.Clone();
    }
    private string ReceiptKey(string tx)=>Base64(namespaceKey+"/completed/"+tx);
    private async Task<(Peer Peer,Fence? State)?> ReadOne(Peer peer,string readKey,CancellationToken token)
    {
        try
        {
            var root=await Post(peer,"/v3/kv/range",new {key=readKey,serializable=false},token);
            if(!root.TryGetProperty("kvs",out var rows) || rows.GetArrayLength()==0)return (peer,null);
            if(rows.GetArrayLength()!=1)throw new InvalidDataException("Unexpected quorum key count.");
            var row=rows[0];
            if(row.GetProperty("key").GetString()!=readKey ||
                (row.TryGetProperty("lease",out var lease) && lease.ToString()!="0"))
                throw new InvalidDataException("Unexpected key or expiring lease; persistent fencing required.");
            var tx=Encoding.ASCII.GetString(Convert.FromBase64String(row.GetProperty("value").GetString()!));
            var epoch=checked((long)Number(row.GetProperty("mod_revision")));
            if(tx.Length is <1 or >120 || tx.Any(c=>c is < (char)33 or > (char)126) ||
                Number(root.GetProperty("header").GetProperty("revision"))<(ulong)epoch ||
                Number(row.GetProperty("version"))!=1)
                throw new InvalidDataException("Invalid or overwritten transaction fence.");
            return (peer,new Fence(tx,epoch));
        }
        catch(HttpRequestException){return null;}
        catch(OperationCanceledException) when(!token.IsCancellationRequested){return null;}
    }
    private async Task<(Peer Peer,Fence? State)> Read(CancellationToken token,string? readKey=null)
    {
        var answers=(await Task.WhenAll(peers.Select(p=>ReadOne(p,readKey??key,token)))).Where(x=>x.HasValue).Select(x=>x!.Value).ToArray();
        if(answers.Length<2 || answers.Any(x=>x.State!=answers[0].State))
            throw new InvalidOperationException("No consistent authenticated Raft majority.");
        return answers[0];
    }
    internal async Task<Fence> Acquire(string transaction,long minimumEpoch,CancellationToken token=default)
    {
        if(!writable || !Tx(transaction) || minimumEpoch<0)throw new InvalidOperationException("Unauthorized quorum acquisition.");
        var before=await Read(token);
        if(before.State is not null)throw new FleetQuorumContentionException();
        var result=await Post(before.Peer,"/v3/kv/txn",new {
            compare=new[]{new {key,result="EQUAL",target="CREATE",createRevision="0"},
                new {key=ReceiptKey(transaction),result="EQUAL",target="CREATE",createRevision="0"}},
            success=new[]{new {requestPut=new {key,value=Base64(transaction)}}},failure=Array.Empty<object>()},token);
        if(!result.TryGetProperty("succeeded",out var ok)||ok.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new InvalidDataException("Unconfirmed quorum acquisition response.");
        if(!ok.GetBoolean())throw new FleetQuorumContentionException();
        var after=await Read(token);
        if(after.State is not { } owned || owned.Transaction!=transaction || owned.Epoch<=minimumEpoch)
            throw new InvalidOperationException("Quorum epoch not above durable node high-water; preserve fence for reconciliation.");
        return owned;
    }
    internal async Task<long> RecoverOwnEpoch(string transaction,CancellationToken token=default)
    {
        if(!writable||!Tx(transaction))throw new InvalidOperationException("Invalid acquisition recovery.");
        var observed=await Read(token);
        if(observed.State is not { } owned||owned.Transaction!=transaction)
            throw new InvalidOperationException("Original acquisition ownership cannot be confirmed.");
        return owned.Epoch;
    }
    internal async Task Assert(string transaction,long epoch,CancellationToken token=default)
    {
        if(!Tx(transaction)||epoch<1)throw new InvalidDataException("Invalid transaction fence.");
        var observed=await Read(token);
        if(observed.State!=new Fence(transaction,epoch))
            throw new InvalidOperationException("Transaction no longer owns the authenticated quorum fence.");
    }
    internal async Task Release(string transaction,long epoch,string outcome,CancellationToken token=default)
    {
        if(!writable || !Tx(transaction)||epoch<1 || outcome is not ("activated" or "rolled-back"))
            throw new InvalidOperationException("Unauthorized quorum completion.");
        var receiptKey=ReceiptKey(transaction);
        var receipt=transaction+":"+epoch.ToString(CultureInfo.InvariantCulture)+":"+outcome;
        async Task<bool> Completed()
        {
            var observed=await Read(token,receiptKey);
            if(observed.State is null)return false;
            if(observed.State.Transaction!=receipt)
                throw new InvalidOperationException("Completion receipt differs from durable intent.");
            return true;
        }
        // An atomic prior completion is idempotent after a lost response or
        // process crash. Never touch a successor's active lock.
        if(await Completed())return;
        var before=await Read(token);
        if(before.State!=new Fence(transaction,epoch))
        {
            if(await Completed())return;
            throw new InvalidOperationException("Exact transaction ownership required for release.");
        }
        _=await Post(before.Peer,"/v3/kv/txn",new {
            compare=new object[]{new {key,result="EQUAL",target="MOD",modRevision=epoch.ToString(CultureInfo.InvariantCulture)},
                new {key,result="EQUAL",target="VALUE",value=Base64(transaction)},
                new {key=receiptKey,result="EQUAL",target="CREATE",createRevision="0"}},
            success=new object[]{new {requestPut=new {key=receiptKey,value=Base64(receipt)}},
                new {requestDeleteRange=new {key}}},failure=Array.Empty<object>()},token);
        // Even if another process won the exact same completion CAS, accept
        // only the immutable same-epoch, same-outcome receipt.
        if(!await Completed())throw new InvalidOperationException("Quorum completion not confirmed; preserve journal.");
    }
    public void Dispose()
    {foreach(var peer in peers)peer.Client.Dispose();credential.Dispose();ca.Dispose();}
}
