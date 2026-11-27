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
    internal sealed record Settings(string Scope,string ClusterId,string CaFile,string CertFile,string KeyFile,Endpoint[] Endpoints,string? VipFencePublicKeyFile=null,string? VipFencePublicKeySha256=null);
    internal sealed record Fence(string Transaction,long Epoch);
    private sealed record Peer(Uri Origin,ulong Id,HttpClient Client);
    private readonly Peer[] peers;
    private readonly ulong cluster;
    private readonly X509Certificate2 ca,credential;
    private readonly string key,namespaceKey;
    private readonly bool writable;
    private ECDsa? vipFenceVerifier;
    internal string Scope { get; }
    internal static string DeploymentScope(string license,string customer,string deployment)=>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(license+"\n"+customer+"\n"+deployment)));
    private static bool Hex(string? value)=>value is {Length:64} && value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool Tx(string? value)=>value is not null && Regex.IsMatch(value,@"\Arollout_[A-F0-9]{24}\z",RegexOptions.CultureInvariant);
    private static string Base64(string text)=>Convert.ToBase64String(Encoding.ASCII.GetBytes(text));
    internal static string FilePath(string path,int max,bool secret=false)
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
        if(settings.VipFencePublicKeyFile is not null || settings.VipFencePublicKeySha256 is not null)
            throw new InvalidDataException("VIP writer trust is not a commercial fleet setting.");
        return new FleetQuorum(settings,writable,"/gatewaycore/commercial-fleet/v1/");
    }
    private FleetQuorum(Settings settings,bool writable,string keyPrefix)
    {
        if(!Hex(settings.Scope) || settings.Endpoints is not {Length:3})
            throw new InvalidDataException("Require one deployment scope and exactly three pinned members.");
        Scope=settings.Scope;this.writable=writable;cluster=Number(settings.ClusterId);
        namespaceKey=keyPrefix+Scope;
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
    // Separate, read-only namespace for a persistent VIP owner. The owner value
    // is bound to this node's independently provisioned TLS client certificate.
    internal static string VipScope(string fleet,string ip)
    {
        if (fleet is null || !Regex.IsMatch(fleet,@"\A[a-zA-Z0-9_-]{1,64}\z",RegexOptions.CultureInvariant) ||
            !System.Net.IPAddress.TryParse(ip,out var address))
            throw new InvalidDataException("Invalid VIP fleet or address.");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("gatewaycore-adc-vip-v1\n"+fleet+"\n"+address)));
    }
    internal static FleetQuorum OpenVip(string path,string scope)
    {
        var opts=new JsonSerializerOptions(JsonSerializerDefaults.Web){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
        var settings=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FilePath(path,16384,true)),opts)
            ??throw new InvalidDataException("Missing VIP quorum settings.");
        if(settings.Scope!=scope)throw new InvalidDataException("VIP quorum scope must match fleet and canonical address.");
        if(settings.VipFencePublicKeyFile is not null || settings.VipFencePublicKeySha256 is not null)
            throw new InvalidDataException("VIP gateway reader cannot load writer trust.");
        return new FleetQuorum(settings,false,"/gatewaycore/adc-vip/v1/");
    }
    internal static FleetQuorum OpenVipWriter(string path,string scope)
    {
        var opts=new JsonSerializerOptions(JsonSerializerDefaults.Web){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
        var settings=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FilePath(path,16384,true)),opts)
            ??throw new InvalidDataException("Missing VIP writer settings.");
        if(settings.Scope!=scope || !Hex(settings.VipFencePublicKeySha256) ||
            string.IsNullOrWhiteSpace(settings.VipFencePublicKeyFile))
            throw new InvalidDataException("Require exact VIP scope and pinned independent fencing public key.");
        var verifier=ECDsa.Create();
        FleetQuorum? quorum=null;
        try
        {
            verifier.ImportFromPem(File.ReadAllText(FilePath(settings.VipFencePublicKeyFile,16384)));
            var publicKey=verifier.ExportSubjectPublicKeyInfo();
            if(verifier.KeySize!=256 || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(publicKey),Convert.FromHexString(settings.VipFencePublicKeySha256!)))
                throw new InvalidDataException("Independent fencing trust mismatch.");
            // Reject private key material in the public trust file.
            try { _=verifier.ExportParameters(true); throw new InvalidDataException("Public key only required."); }
            catch(CryptographicException) { }
            quorum=new FleetQuorum(settings,true,"/gatewaycore/adc-vip/v1/");
            quorum.vipFenceVerifier=verifier;
            return quorum;
        }
        catch { quorum?.Dispose();verifier.Dispose();throw; }
    }
    private void RequireVipWriter()
    {
        if(!writable || vipFenceVerifier is null || !namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal))
            throw new InvalidOperationException("Independent VIP writer credentials required.");
    }
    internal async Task<Fence?> ObserveVip(CancellationToken token)
    {
        RequireVipWriter();
        var state=(await Read(token)).State;
        var initialized=(await Read(token,VipInitializationKey)).State;
        if((state is null)!=(initialized is null) ||
            (initialized is not null && initialized.Transaction!="vip_initialized"))
            throw new InvalidDataException("VIP initialization and owner records disagree; independent recovery required.");
        return state;
    }
    private string VipInitializationKey=>Base64(namespaceKey+"/initialized");
    internal async Task<Fence> RevokeVip(string ownerPin,long epoch,CancellationToken token)
    {
        RequireVipWriter();
        if(!Hex(ownerPin)||epoch<1)throw new InvalidDataException("Exact prior owner and epoch required.");
        return await ChangeVip(new Fence("vip_"+ownerPin,epoch),"vip_revoked_"+ownerPin,null,token);
    }
    internal async Task<Fence> ActivateVip(string oldPin,long revokedEpoch,string newPin,long expires,byte[] signature,CancellationToken token)
    {
        RequireVipWriter();
        if(!Hex(newPin) || (oldPin=="-" ? revokedEpoch!=0 : !Hex(oldPin)||revokedEpoch<1) ||
            newPin==Convert.ToHexString(SHA256.HashData(credential.RawData)))
            throw new InvalidDataException("Invalid successor, predecessor or epoch; writer cannot be the owner.");
        var previous=oldPin=="-" ? null : new Fence("vip_revoked_"+oldPin,revokedEpoch);
        void Verify()
        {
            long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if(expires<=now || expires>now+300 || signature.Length is <64 or >80)
                throw new InvalidDataException("Expired or unbounded external fencing permit.");
            var message=Encoding.UTF8.GetBytes(string.Join("\n","GatewayCore.VIP.HardFence.v1",Scope,oldPin,
                revokedEpoch.ToString(CultureInfo.InvariantCulture),newPin,expires.ToString(CultureInfo.InvariantCulture)));
            if(!vipFenceVerifier!.VerifyData(message,signature,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence))
                throw new InvalidDataException("Independent fencing permit signature rejected.");
        }
        Verify();
        return await ChangeVip(previous,"vip_"+newPin,Verify,token);
    }
    private async Task<Fence> ChangeVip(Fence? expected,string next,Action? verify,CancellationToken token)
    {
        var before=await Read(token);
        if(before.State!=expected)throw new FleetQuorumContentionException();
        var initialized=(await Read(token,VipInitializationKey)).State;
        if(expected is null ? initialized is not null : initialized?.Transaction!="vip_initialized")
            throw new InvalidDataException("Missing or previously initialized VIP owner record; refuse bootstrap or transfer.");
        var marker=VipInitializationKey;
        object[] compare=expected is null
            ? [new {key,result="EQUAL",target="CREATE",createRevision="0"},
               new {key=marker,result="EQUAL",target="CREATE",createRevision="0"}]
            : [new {key,result="EQUAL",target="MOD",modRevision=expected.Epoch.ToString(CultureInfo.InvariantCulture)},
               new {key,result="EQUAL",target="VALUE",value=Base64(expected.Transaction)},
               new {key=marker,result="EQUAL",target="MOD",modRevision=initialized!.Epoch.ToString(CultureInfo.InvariantCulture)},
               new {key=marker,result="EQUAL",target="VALUE",value=Base64("vip_initialized")}];
        object[] writes=expected is null
            ? [new {requestPut=new {key,value=Base64(next)}},
               new {requestPut=new {key=marker,value=Base64("vip_initialized")}}]
            : [new {requestPut=new {key,value=Base64(next)}}];
        verify?.Invoke();
        token.ThrowIfCancellationRequested();
        var result=await Post(before.Peer,"/v3/kv/txn",new {
            compare,success=writes,failure=Array.Empty<object>()},token);
        if(!result.TryGetProperty("succeeded",out var success)||success.ValueKind!=JsonValueKind.True)
            throw new FleetQuorumContentionException();
        var revision=checked((long)Number(result.GetProperty("header").GetProperty("revision")));
        var state=(await Read(token)).State;
        if(revision<=(expected?.Epoch??0)||state!=new Fence(next,revision))
            throw new InvalidOperationException("VIP transition not confirmed; inspect persistent state before any recovery.");
        return state!;
    }
    internal string VipReaderPin=>Convert.ToHexString(SHA256.HashData(credential.RawData));
    internal async Task<Fence> ReadVipState(CancellationToken token)
    {
        if(writable||!namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal))
            throw new InvalidOperationException("Read-only VIP identity required.");
        return (await Read(token)).State??throw new InvalidDataException("VIP owner record missing.");
    }
    internal async Task<(long Epoch,bool Own)> ObserveVipReader(CancellationToken token)
    {
        if(writable||!namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal))
            throw new InvalidOperationException("Read-only VIP identity required.");
        var state=(await Read(token)).State??throw new InvalidDataException("VIP owner record missing.");
        return (state.Epoch,state.Transaction=="vip_"+Convert.ToHexString(SHA256.HashData(credential.RawData)));
    }
    internal async Task<bool> IsVipOwner(long expectedEpoch,CancellationToken token)
    {
        if(expectedEpoch<1 || writable || !namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal))
            return false;
        var owner="vip_"+Convert.ToHexString(SHA256.HashData(credential.RawData));
        var read=await Read(token);
        return read.State==new Fence(owner,expectedEpoch);
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
                ((!namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal) || readKey!=key) && Number(row.GetProperty("version"))!=1))
                throw new InvalidDataException("Invalid or overwritten transaction fence.");
            if(namespaceKey.StartsWith("/gatewaycore/adc-vip/v1/",StringComparison.Ordinal) && readKey==key)
            {
                _=Number(row.GetProperty("version"));
                if(!(tx.StartsWith("vip_",StringComparison.Ordinal) && Hex(tx[4..])) &&
                   !(tx.StartsWith("vip_revoked_",StringComparison.Ordinal) && Hex(tx[12..])))
                    throw new InvalidDataException("Invalid VIP ownership record.");
            }
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
    {foreach(var peer in peers)peer.Client.Dispose();credential.Dispose();ca.Dispose();vipFenceVerifier?.Dispose();}
}
