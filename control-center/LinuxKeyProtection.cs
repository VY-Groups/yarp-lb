using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using System.Text;
using System.Text.Json;
using System.Net.Security;
using System.Text.RegularExpressions;
using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;
using GatewayCore.Gslb.Contracts;

/// <summary>
/// Linux/on-premise ASP.NET Data Protection key-ring envelope encryption.
/// No plaintext key-ring fallback outside disposable CI EC2 lab mode.
/// No secrets are accepted as process arguments or embedded in appsettings.
/// </summary>
public static class LinuxKeyProtection
{
    public const string FleetReplicaSetting = "YARP_LINUX_DP_FLEET_REPLICA";
    public const string DistributedRingSetting = "YARP_LINUX_DP_DISTRIBUTED_RING_CONFIG";

    // Separate opt-in backend. An independent operator provisions the exact
    // Raft writer epoch and narrow mTLS credentials. No local file repository
    // is used for distributed reads or writes, even on transport failures.
    internal sealed class DistributedRingRepository : IXmlRepository, IDisposable
    {
        internal sealed record Member(string Url, string LeafSha256, string MemberId);
        internal sealed record Settings(string Fleet, string NodeId, string ClusterId,
            long MinimumRaftRevision, Member[] Members, string Mode,
            string? WriterNode, long? LeaseId, long? WriterModRevision,
            string CaPath, string ClientPfxPath, string ClientPasswordPath);
        private const int MaxXml = 8192;
        private const int MaxKeys = 512;
        private const int MaxReply = 6 * 1024 * 1024;
        private readonly Settings config;
        private readonly byte[] active, previous;
        private readonly Func<Member,string,object,JsonDocument> rpc;
        private readonly List<IDisposable> resources = new();
        private readonly object sync = new();
        private readonly string prefix, writerKey;
        private long floor;

        internal DistributedRingRepository(Settings settings, X509Certificate2 current,
            X509Certificate2? historic, Func<Member,string,object,JsonDocument>? testRpc = null)
        {
            config=settings;
            static bool Id(string? x) => x is not null &&
                Regex.IsMatch(x, @"\A[a-z0-9][a-z0-9_-]{1,47}\z",
                    RegexOptions.CultureInvariant);
            static bool UInt(string? x) => x is not null &&
                ulong.TryParse(x,NumberStyles.None,CultureInfo.InvariantCulture,out var n) &&
                n>0 && n.ToString(CultureInfo.InvariantCulture)==x;
            if (!Id(config.Fleet) || config.Fleet.Length<3 || !Id(config.NodeId) ||
                !UInt(config.ClusterId) || config.MinimumRaftRevision<1 ||
                config.Members is null || config.Members.Length!=3 ||
                config.Mode is not ("reader" or "writer") ||
                config.Members.Any(m => m is null || !UInt(m.MemberId) ||
                    m.LeafSha256 is null || !Regex.IsMatch(m.LeafSha256,@"\A[A-F0-9]{64}\z") ||
                    !Uri.TryCreate(m.Url,UriKind.Absolute,out var uri) ||
                    uri.Scheme!="https" || uri.AbsolutePath!="/" ||
                    uri.UserInfo.Length!=0 || uri.Query.Length!=0 || uri.Fragment.Length!=0) ||
                config.Members.Select(m=>new Uri(m.Url).GetLeftPart(UriPartial.Authority))
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count()!=3 ||
                config.Members.Select(m=>m.MemberId).Distinct().Count()!=3 ||
                config.Members.Select(m=>m.LeafSha256).Distinct().Count()!=3 ||
                (config.Mode=="writer" && (config.WriterNode!=config.NodeId ||
                    config.LeaseId is null or <=0 || config.WriterModRevision is null or <=0)) ||
                (config.Mode=="reader" && (config.LeaseId is not null ||
                    config.WriterModRevision is not null || config.WriterNode is not null)))
                throw new InvalidOperationException("Invalid independent distributed key-ring inventory");
            prefix="/gatewaycore/linux-dp/runtime-ring/"+config.Fleet+"/";
            writerKey=B64("/gatewaycore/linux-dp/runtime-writer/"+config.Fleet);
            active=current.RawData;
            previous=historic?.RawData ?? Array.Empty<byte>();
            floor=config.MinimumRaftRevision;
            rpc=testRpc ?? BuildTransport();
        }

        private static string B64(string value)=>Convert.ToBase64String(Encoding.ASCII.GetBytes(value));
        private static string Text(JsonElement value)=>value.ValueKind==JsonValueKind.String
            ? value.GetString()! : value.GetRawText();
        private static long Positive(JsonElement value)
        {
            if (!long.TryParse(Text(value),NumberStyles.None,CultureInfo.InvariantCulture,out var n) || n<=0)
                throw new InvalidOperationException("Invalid distributed Raft revision");
            return n;
        }
        private static byte[] PrivateRead(string path,string label,int max)
        {
            try { return PrivateKeyFileSecurity.ReadPrivateFileBytes(path,label,max,requireSingleLink:true); }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { throw new InvalidOperationException("Unsafe distributed key-ring credential",ex); }
        }
        internal static Settings ReadSettings(string path,string state)
        {
            if (!Path.IsPathFullyQualified(path))
                throw new InvalidOperationException("Distributed ring config must be an independent absolute path");
            var raw=PrivateRead(path,"Distributed ring configuration",16384);
            try
            {
                using var doc=JsonDocument.Parse(raw,new JsonDocumentOptions {MaxDepth=5});
                EnsureUnique(doc.RootElement);
                var value=JsonSerializer.Deserialize<Settings>(raw,new JsonSerializerOptions {
                    UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
                }) ?? throw new InvalidOperationException("Missing distributed key-ring config");
                foreach(var item in new[]{path,value.CaPath,value.ClientPfxPath,value.ClientPasswordPath})
                {
                    if(string.IsNullOrEmpty(item)||!Path.IsPathFullyQualified(item) ||
                        Path.GetFullPath(item)!=item)
                        throw new InvalidOperationException("Independent distributed credential path required");
                    var relative=Path.GetRelativePath(state,item);
                    if(relative=="." || (!Path.IsPathRooted(relative)&&relative!=".."&&
                        !relative.StartsWith("../",StringComparison.Ordinal)))
                        throw new InvalidOperationException("Distributed credentials must be outside state root");
                }
                return value;
            }
            finally {CryptographicOperations.ZeroMemory(raw);}
        }

        private static void EnsureUnique(JsonElement element)
        {
            if(element.ValueKind==JsonValueKind.Object)
            {
                var seen=new HashSet<string>(StringComparer.Ordinal);
                foreach(var property in element.EnumerateObject())
                {
                    if(!seen.Add(property.Name)) throw new InvalidOperationException("Duplicate JSON member");
                    EnsureUnique(property.Value);
                }
            }
            else if(element.ValueKind==JsonValueKind.Array)
                foreach(var child in element.EnumerateArray()) EnsureUnique(child);
        }
        private Func<Member,string,object,JsonDocument> BuildTransport()
        {
            var caBytes=PrivateRead(config.CaPath,"Distributed CA",65536);
            var ca=X509Certificate2.CreateFromPem(new UTF8Encoding(false,true).GetString(caBytes));
            resources.Add(ca);
            var secret=PrivateRead(config.ClientPasswordPath,"Distributed client password",4096);
            var pfx=PrivateRead(config.ClientPfxPath,"Distributed client PFX",1024*1024);
            X509Certificate2 client;
            try
            {
                var password=new UTF8Encoding(false,true).GetString(secret).TrimEnd('\r','\n');
                if(password.Length==0||password.Any(char.IsControl))
                    throw new InvalidOperationException("Invalid distributed TLS password");
                client=X509CertificateLoader.LoadPkcs12(pfx,password,X509KeyStorageFlags.EphemeralKeySet);
            }
            finally {CryptographicOperations.ZeroMemory(secret);CryptographicOperations.ZeroMemory(pfx);}
            resources.Add(client);
            if(!client.HasPrivateKey || client.RawData.AsSpan().SequenceEqual(active) ||
                client.RawData.AsSpan().SequenceEqual(previous))
                throw new InvalidOperationException("Independent distributed TLS client identity required");
            var clients=new Dictionary<string,HttpClient>(StringComparer.Ordinal);
            foreach(var member in config.Members)
            {
                var handler=new HttpClientHandler {AllowAutoRedirect=false,UseProxy=false,
                    ClientCertificateOptions=ClientCertificateOption.Manual};
                handler.ClientCertificates.Add(client);
                handler.ServerCertificateCustomValidationCallback=(_,certificate,_,errors)=>
                {
                    if(certificate is null ||
                        (errors & (SslPolicyErrors.RemoteCertificateNameMismatch |
                            SslPolicyErrors.RemoteCertificateNotAvailable))!=0 ||
                        Convert.ToHexString(SHA256.HashData(certificate.RawData))!=member.LeafSha256)
                        return false;
                    using var chain=new X509Chain();
                    chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(ca);
                    chain.ChainPolicy.DisableCertificateDownloads=true;
                    chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                    chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                    return chain.Build(certificate);
                };
                var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(5)};
                clients.Add(member.MemberId,http);resources.Add(http);
            }
            return (member,resource,body)=>
            {
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var request=new HttpRequestMessage(HttpMethod.Post,
                    new Uri(new Uri(member.Url),resource));
                request.Content=new StringContent(JsonSerializer.Serialize(body),Encoding.UTF8,"application/json");
                using var response=clients[member.MemberId].Send(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
                if(!response.IsSuccessStatusCode||response.Content.Headers.ContentType?.MediaType!="application/json")
                    throw new InvalidOperationException("Distributed ring RPC refused");
                if(response.Content.Headers.ContentLength>MaxReply)
                    throw new InvalidOperationException("Distributed ring response exceeds bound");
                using var stream=response.Content.ReadAsStream(timeout.Token);
                using var bytes=new MemoryStream();
                var buffer=new byte[16384];
                while(true)
                {
                    var n=stream.ReadAsync(buffer.AsMemory(),timeout.Token).AsTask().GetAwaiter().GetResult();
                    if(n==0)break;
                    if(bytes.Length+n>MaxReply)throw new InvalidOperationException("Distributed response exceeds bound");
                    bytes.Write(buffer,0,n);
                }
                return JsonDocument.Parse(bytes.ToArray(),new JsonDocumentOptions{MaxDepth=16});
            };
        }

        private long Header(JsonElement root,Member member)
        {
            EnsureUnique(root);
            var h=root.GetProperty("header");
            if(Text(h.GetProperty("cluster_id"))!=config.ClusterId ||
                Text(h.GetProperty("member_id"))!=member.MemberId)
                throw new InvalidOperationException("Distributed ring member identity mismatch");
            var revision=Positive(h.GetProperty("revision"));
            if(revision<floor)throw new InvalidOperationException("Distributed key-ring revision rolled back");
            return revision;
        }

        private XElement CheckXml(string name,byte[] raw,bool writing)
        {
            if(raw.Length is <1 or >MaxXml ||
                !Regex.IsMatch(name,@"\Akey-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.xml\z"))
                throw new InvalidOperationException("Invalid bounded distributed XML name or size");
            using var stream=new MemoryStream(raw,false);
            using var reader=XmlReader.Create(stream,new XmlReaderSettings{
                DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=MaxXml});
            var root=XElement.Load(reader);
            XNamespace dp="http://schemas.asp.net/2015/03/dataProtection";
            XNamespace ds="http://www.w3.org/2000/09/xmldsig#";
            XNamespace enc="http://www.w3.org/2001/04/xmlenc#";
            if(root.Name!="key" || (string?)root.Attribute("id")!=name[4..^4] ||
                root.DescendantsAndSelf().Any(e=>e.Name.LocalName=="masterKey"))
                throw new InvalidOperationException("Invalid distributed key XML identity or plaintext");
            var wrapped=root.Descendants().Where(e=>e.Name.LocalName=="encryptedSecret").ToArray();
            if(wrapped.Length!=1 || wrapped[0].Name!=dp+"encryptedSecret" ||
                !((string?)wrapped[0].Attribute("decryptorType")??"").Split(',',
                    StringSplitOptions.TrimEntries).Take(2).SequenceEqual(new[]{
                    "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor",
                    "Microsoft.AspNetCore.DataProtection"}) ||
                wrapped[0].Descendants(enc+"EncryptedData").Count()!=1)
                throw new InvalidOperationException("Unapproved distributed encrypted envelope");
            var recipients=wrapped[0].Descendants(ds+"X509Certificate").ToArray();
            if(recipients.Length is <1 or >4)
                throw new InvalidOperationException("Missing distributed wrapping recipient");
            foreach(var recipient in recipients)
            {
                var der=Convert.FromBase64String(recipient.Value);
                if(!CryptographicOperations.FixedTimeEquals(der,active) &&
                    (writing || !CryptographicOperations.FixedTimeEquals(der,previous)))
                    throw new InvalidOperationException("Unapproved distributed wrapping recipient");
            }
            return root;
        }

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            lock(sync)
            {
                Dictionary<string,byte[]>? agreed=null;
                var votes=0;
                long highest=floor;
                foreach(var member in config.Members)
                {
                    try
                    {
                        // ASCII prefix ends with '/', so prefix+'0' is its
                        // exclusive range upper bound. Do not allow pagination.
                        using var doc=rpc(member,"/v3/kv/range",new {
                            key=B64(prefix),range_end=B64(prefix[..^1]+"0"),
                            serializable=false,limit=(MaxKeys+1).ToString(CultureInfo.InvariantCulture)});
                        var root=doc.RootElement;
                        var revision=Header(root,member);
                        if(root.TryGetProperty("more",out var more)&&more.ValueKind!=JsonValueKind.False)
                            throw new InvalidOperationException("Distributed ring is unbounded");
                        var found=new Dictionary<string,byte[]>(StringComparer.Ordinal);
                        if(root.TryGetProperty("kvs",out var items))
                            foreach(var item in items.EnumerateArray())
                            {
                                var key=Encoding.ASCII.GetString(Convert.FromBase64String(item.GetProperty("key").GetString()!));
                                if(!key.StartsWith(prefix,StringComparison.Ordinal) ||
                                    (item.TryGetProperty("lease",out var attached)&&Text(attached)!="0") ||
                                    Positive(item.GetProperty("mod_revision"))>revision ||
                                    Positive(item.GetProperty("version"))!=1 ||
                                    found.Count>=MaxKeys)
                                    throw new InvalidOperationException("Untrusted distributed key record");
                                var name=key[prefix.Length..];
                                var raw=Convert.FromBase64String(item.GetProperty("value").GetString()!);
                                _=CheckXml(name,raw,false);
                                if(!found.TryAdd(name,raw))throw new InvalidOperationException("Duplicate key record");
                            }
                        var count=root.TryGetProperty("count",out var total)?Text(total):"0";
                        if(count!=found.Count.ToString(CultureInfo.InvariantCulture))
                            throw new InvalidOperationException("Incomplete distributed ring");
                        if(agreed is not null && (agreed.Count!=found.Count ||
                            agreed.Any(x=>!found.TryGetValue(x.Key,out var value)||
                                !x.Value.AsSpan().SequenceEqual(value))))
                            throw new InvalidOperationException("Distributed ring quorum disagrees");
                        agreed=found;votes++;highest=Math.Max(highest,revision);
                    }
                    catch(Exception ex) when(ex is HttpRequestException or IOException or OperationCanceledException)
                    { /* transport loss is not a vote */ }
                }
                if(votes<2||agreed is null)throw new InvalidOperationException("Distributed ring quorum unavailable");
                floor=highest;
                return agreed.Select(x=>CheckXml(x.Key,x.Value,false)).ToArray();
            }
        }

        public void StoreElement(XElement element,string friendlyName)
        {
            lock(sync)
            {
                if(config.Mode!="writer")throw new InvalidOperationException("Distributed replica cannot write keys");
                var name=friendlyName+".xml";
                var raw=Encoding.UTF8.GetBytes(element.ToString(SaveOptions.DisableFormatting));
                _=CheckXml(name,raw,true);
                // An actual new ciphertext write is conditional on the exact
                // independently provisioned lease and mod revision in one Raft txn.
                // Revocation/epoch replacement makes the compare fail.
                var item=B64(prefix+name);
                var body=new {
                    compare=new object[] {
                        new {result="EQUAL",target="MOD",key=writerKey,
                            modRevision=config.WriterModRevision!.Value.ToString(CultureInfo.InvariantCulture)},
                        new {result="EQUAL",target="LEASE",key=writerKey,
                            lease=config.LeaseId!.Value.ToString(CultureInfo.InvariantCulture)},
                        new {result="EQUAL",target="CREATE",key=item,createRevision="0"}},
                    success=new[]{new {requestPut=new {key=item,value=Convert.ToBase64String(raw)}}},
                    failure=Array.Empty<object>()};
                // Never retry ambiguous mutations. The transaction itself
                // is linearizable and cannot succeed in a minority.
                using var doc=rpc(config.Members[0],"/v3/kv/txn",body);
                var revision=Header(doc.RootElement,config.Members[0]);
                if(!doc.RootElement.TryGetProperty("succeeded",out var succeeded)||
                    succeeded.ValueKind!=JsonValueKind.True)
                    throw new InvalidOperationException("Distributed writer epoch or key creation refused");
                floor=revision;
            }
        }
        public void Dispose()
        {
            foreach(var resource in resources.AsEnumerable().Reverse())resource.Dispose();
        }
    }


    // Prevent explicit IKeyManager creation and revocation writes as well
    // as automatic generation. This is an in-process replica boundary,
    // not an OS ACL or a distributed writer-promotion protocol.
    private sealed class ReadOnlyRingRepository(IXmlRepository inner) : IXmlRepository
    {
        public IReadOnlyCollection<XElement> GetAllElements() => inner.GetAllElements();

        public void StoreElement(XElement element, string friendlyName) =>
            throw new InvalidOperationException(
                "Fleet replica cannot persist Data Protection keys or revocations");
    }

    private static bool IsFleetReplica()
    {
        var value = Environment.GetEnvironmentVariable(FleetReplicaSetting);
        return value switch
        {
            null or "false" => false,
            "true" => true,
            _ => throw new InvalidOperationException(
                FleetReplicaSetting + " must be exactly true or false")
        };
    }

    private static void ConfigureReplica(IDataProtectionBuilder builder, string keyDirectory)
    {
        if (!Directory.EnumerateFiles(keyDirectory, "key-*.xml").Any())
            throw new InvalidOperationException(
                "Fleet replica requires an existing encrypted Data Protection ring");

        builder.DisableAutomaticKeyGeneration();
        // PostConfigure runs after PersistKeysToFileSystem and all ordinary
        // options setup. Refuse any implicit fallback repository.
        builder.Services.PostConfigure<KeyManagementOptions>(options =>
        {
            options.AutoGenerateKeys = false;
            options.XmlRepository = new ReadOnlyRingRepository(
                options.XmlRepository ?? throw new InvalidOperationException(
                    "Fleet replica requires an explicit key repository"));
        });
    }

    private const UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode SecretFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PublicPermissions =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    public static string InitializeStateDirectory()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Linux key protector is Linux-only");
        var root = Environment.GetEnvironmentVariable("YARP_CONTROL_PLANE_DIR");
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
            throw new InvalidOperationException(
                "Set YARP_CONTROL_PLANE_DIR to an absolute private Linux directory");
        root = Path.GetFullPath(root);
        if (root == "/" || root == "/tmp" || root == "/var" || root == "/var/lib")
            throw new InvalidOperationException("Refusing unsafe Linux data-protection state root");
        // Path-based CreateDirectory can traverse a parent symlink before
        // CheckPrivateDirectory ever runs. Create/inspect each component
        // relative to already-opened no-follow Linux directory handles.
        // Reject a linked (including dangling-linked) ancestor *before*
        // creating anything beneath its target.
        var keyDir = Path.Combine(root, "data-protection-keys");
        try
        {
            PrivateKeyFileSecurity.EnsureLinuxPrivateStateDirectory(
                root, "Linux Data Protection state");
            PrivateKeyFileSecurity.EnsureLinuxPrivateStateDirectory(
                keyDir, "Linux Data Protection key ring");
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidOperationException(
                "Unsafe Linux Data Protection directory bootstrap", ex);
        }
        CheckPrivateDirectory(root);
        CheckPrivateDirectory(keyDir);
        return root;
    }

    private static void CheckPrivateDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Key directory must not be a symlink");
        try { PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(path, "Linux Data Protection state"); }
        catch (InvalidDataException ex) { throw new InvalidOperationException("Unsafe Linux Data Protection directory ancestry", ex); }
        var mode = File.GetUnixFileMode(path);
        if ((mode & PublicPermissions) != 0 || (mode & PrivateDirectoryMode) != PrivateDirectoryMode)
            throw new InvalidOperationException("State/key directory requires owner-only 0700 permissions");
    }

    private static string SecretPath(string environmentName)
    {
        var path = Environment.GetEnvironmentVariable(environmentName);
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("Missing absolute secret file path: " + environmentName);
        path = Path.GetFullPath(path);
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Missing or symlinked secret: " + environmentName);
        var mode = File.GetUnixFileMode(path);
        if ((mode & PublicPermissions) != 0 || (mode & SecretFileMode) != SecretFileMode)
            throw new InvalidOperationException("Secret requires mode 0600 (no group/other access): " + environmentName);
        return path;
    }

    private static X509Certificate2 LoadRsaProtector(
        string pfxEnv, string passwordFileEnv, bool decryptionOnlyPrevious = false)
    {
        var path = SecretPath(pfxEnv);
        var passwordPath = SecretPath(passwordFileEnv);
        byte[] ReadSecret(string file, string purpose, int limit)
        {
            // Wrapper PFX and its separate password must each be independently
            // provisioned private files. A second hardlink can alias the
            // same secret inode outside the protected provisioning path;
            // validate the opened handle's link count before reading bytes.
            try { return PrivateKeyFileSecurity.ReadPrivateFileBytes(
                file, purpose, limit, requireSingleLink: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { throw new InvalidOperationException("Unsafe or unavailable Linux Data Protection secret", ex); }
        }
        var passwordBytes = ReadSecret(passwordPath, "Linux PFX password", 4096);
        X509Certificate2 cert;
        try
        {
            var password = new System.Text.UTF8Encoding(false, true).GetString(passwordBytes).TrimEnd('\r', '\n');
            if (password.Length == 0 || password.Any(char.IsControl))
                throw new InvalidOperationException("Invalid Linux PFX password");
            var pfx = ReadSecret(path, "Linux wrapping PFX", 1024 * 1024);
            try { cert = X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.EphemeralKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
        try
        {
            using var privateKey = cert.GetRSAPrivateKey();
            // Do not use a CA signing key or signing-only TLS identity as
            // an ASP.NET Data Protection XML envelope key. The dedicated
            // RSA leaf must explicitly authorize key encipherment.
            var usage = cert.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            var constraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
            if (privateKey is null || privateKey.KeySize < 2048 ||
                usage.Length != 1 ||
                (usage[0].KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0 ||
                constraints.Length != 1 || constraints[0].CertificateAuthority ||
                cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
                (!decryptionOnlyPrevious &&
                 cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(1)))
                throw new InvalidOperationException(
                    "Linux Data Protection requires a valid RSA >=2048 leaf wrapping certificate with explicit keyEncipherment usage and a private key");
            return cert;
        }
        catch
        {
            cert.Dispose();
            throw;
        }
    }

    // ProtectKeysWithCertificate only wraps newly persisted keys. It does
    // not reject a legacy plaintext ring imported from an earlier lab.
    // Inspect existing XML without modifying it or deserializing key types.
    private static void ValidateExistingKeyRing(string directory)
    {
        const string protectionNamespace = "http://schemas.asp.net/2015/03/dataProtection";
        // Bound and validate the full restore inventory before framework import.
        const int MaximumKeyRingXmlFiles = 512;
        var inventory = Directory.EnumerateFiles(directory, "*.xml")
            .Take(MaximumKeyRingXmlFiles + 1).ToArray();
        if (inventory.Length > MaximumKeyRingXmlFiles)
            throw new InvalidOperationException(
                "Linux Data Protection key-ring XML inventory exceeds 512 entries");
        var seenKeys = new HashSet<Guid>();
        foreach (var path in inventory)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML must not be a symlink");
            if ((File.GetUnixFileMode(path) & PublicPermissions) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML requires owner-only permissions");
            byte[] bytes;
            try { bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(path, "Linux key-ring XML", 1024 * 1024,
                requireSingleLink: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { throw new InvalidOperationException("Unsafe existing Linux key-ring XML", ex); }
            try
            {
                using var stream = new MemoryStream(bytes, writable: false);
                using var reader = XmlReader.Create(stream, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = 1024 * 1024
                });
                if (reader.MoveToContent() != XmlNodeType.Element)
                    throw new InvalidOperationException("Existing Linux key-ring XML has no root element");
                var rootName = reader.LocalName;
                var rootNamespace = reader.NamespaceURI;
                var isRevocation = rootName == "revocation" && rootNamespace.Length == 0;
                var isKey = rootName == "key" && rootNamespace.Length == 0;
                if (!isRevocation && !isKey)
                    throw new InvalidOperationException(
                        "Existing Linux key ring is not certificate-wrapped; isolate and recover an approved protected backup");

                if (isKey)
                {
                    // Data Protection identifies keys by GUID, so the file name
                    // and embedded id must describe the same unique key.
                    var id = reader.GetAttribute("id");
                    if (!Guid.TryParseExact(id, "D", out var keyId) ||
                        !string.Equals(Path.GetFileName(path),
                            "key-" + keyId.ToString("D") + ".xml",
                            StringComparison.OrdinalIgnoreCase) ||
                        !seenKeys.Add(keyId))
                        throw new InvalidOperationException(
                            "Linux Data Protection key-ring XML identity mismatch or duplicate");
                }

                // Walk element names only. Do not materialize the document's
                // text into an XDocument, where a legacy plaintext master key
                // would become a long-lived managed string.
                var encryptedSecretCount = 0;
                while (reader.Read())
                {
                    if (reader.NodeType != XmlNodeType.Element) continue;
                    if (reader.LocalName == "masterKey" ||
                        (isRevocation && reader.LocalName == "encryptedSecret"))
                        throw new InvalidOperationException(
                            "Existing Linux key-ring XML contains unexpected key material");
                    if (isKey && reader.LocalName == "encryptedSecret")
                    {
                        // A foreign namespace may hide extra secret material
                        // alongside the approved certificate-wrapped element.
                        if (reader.NamespaceURI != protectionNamespace)
                            throw new InvalidOperationException(
                                "Linux key-ring XML contains a foreign encryptedSecret element");
                        var decryptor = reader.GetAttribute("decryptorType");
                        var assemblyQualified = decryptor?.Split(
                            ',', StringSplitOptions.TrimEntries);
                        if (assemblyQualified is null || assemblyQualified.Length < 2 ||
                            assemblyQualified[0] !=
                                "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor" ||
                            assemblyQualified[1] != "Microsoft.AspNetCore.DataProtection")
                            throw new InvalidOperationException(
                                "Linux key-ring XML is not from the approved certificate decryptor");
                        encryptedSecretCount++;
                    }
                }
                if (isKey && encryptedSecretCount != 1)
                    throw new InvalidOperationException(
                        "Existing Linux key ring is not certificate-wrapped; isolate and recover an approved protected backup");
            }
            finally
            {
                // Clear the bounded source buffer even if XML parsing or a
                // plaintext-key rejection fails.
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    // Refuse silent retirement of a historic wrapping identity. ASP.NET Core
    // can otherwise start with a valid new certificate while old persisted
    // keys remain encrypted under a now-missing previous private key; old
    // authentication cookies fail later, after traffic has been admitted.
    // Inspection is read-only and never exports/decrypts a master key.
    private static void RequireHistoricWrappingCertificates(
        string keyDirectory, X509Certificate2 current, X509Certificate2? previous)
    {
        const string protectedNs = "http://schemas.asp.net/2015/03/dataProtection";
        const string xmldsigNs = "http://www.w3.org/2000/09/xmldsig#";
        const int maximumKeyFiles = 512;
        // The ASP.NET Core FileSystemXmlRepository imports every top-level
        // *.xml file, not only files beginning with "key-". The custody
        // inventory must inspect that SAME complete set before startup.
        var keys = Directory.EnumerateFiles(keyDirectory, "*.xml")
            .Take(maximumKeyFiles + 1).ToArray();
        if (keys.Length > maximumKeyFiles)
            throw new InvalidOperationException("Historic encrypted key-ring inventory is unbounded");
        var activeRecipient = current.RawData;
        var historicRecipient = previous?.RawData;
        try
        {
            foreach (var path in keys)
            {
                var bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                    path, "Historic Data Protection encrypted XML", 1024 * 1024,
                    requireSingleLink: true);
                try
                {
                    using var stream = new MemoryStream(bytes, writable: false);
                    using var reader = XmlReader.Create(stream, new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = 1024 * 1024
                    });
                    // Revocation XML has no encrypted key recipient;
                    // key XML MUST carry one or more approved recipients.
                    if (reader.MoveToContent() != XmlNodeType.Element ||
                        reader.NamespaceURI.Length != 0 ||
                        (reader.LocalName != "key" &&
                         reader.LocalName != "revocation"))
                        throw new InvalidOperationException(
                            "Unexpected XML in Data Protection key repository");
                    if (reader.LocalName == "revocation")
                        continue;
                    var envelopeDepth = -1;
                    var recipientCount = 0;
                    while (reader.Read())
                    {
                        if (reader.NodeType == XmlNodeType.Element &&
                            reader.LocalName == "encryptedSecret" &&
                            reader.NamespaceURI == protectedNs)
                        {
                            if (envelopeDepth != -1)
                                throw new InvalidOperationException(
                                    "Ambiguous Data Protection certificate envelope");
                            envelopeDepth = reader.Depth;
                        }
                        else if (reader.NodeType == XmlNodeType.EndElement &&
                                 reader.LocalName == "encryptedSecret" &&
                                 reader.NamespaceURI == protectedNs &&
                                 reader.Depth == envelopeDepth)
                        {
                            envelopeDepth = -1;
                        }
                        else if (reader.NodeType == XmlNodeType.Element &&
                                 reader.LocalName == "X509Certificate" &&
                                 reader.NamespaceURI == xmldsigNs &&
                                 envelopeDepth >= 0 &&
                                 reader.Depth > envelopeDepth)
                        {
                            // This is the PUBLIC embedded recipient cert, not
                            // the encrypted DP key or private wrapping PFX.
                            var encoded = reader.ReadElementContentAsString();
                            if (encoded.Length is < 1 or > 16384)
                                throw new InvalidOperationException(
                                    "Invalid bounded encrypted-key recipient");
                            byte[] recipient;
                            try { recipient = Convert.FromBase64String(encoded); }
                            catch (FormatException)
                            {
                                throw new InvalidOperationException(
                                    "Malformed encrypted-key recipient certificate");
                            }
                            try
                            {
                                if (!CryptographicOperations.FixedTimeEquals(
                                        recipient, activeRecipient) &&
                                    (historicRecipient is null ||
                                     !CryptographicOperations.FixedTimeEquals(
                                         recipient, historicRecipient)))
                                    throw new InvalidOperationException(
                                        "Historic Data Protection certificate cannot be retired while its keys remain");
                                recipientCount++;
                            }
                            finally { CryptographicOperations.ZeroMemory(recipient); }
                        }
                    }
                    if (recipientCount == 0 || recipientCount > 4)
                        throw new InvalidOperationException(
                            "Encrypted Data Protection key lacks approved public wrapping recipient");
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(activeRecipient);
            if (historicRecipient is not null)
                CryptographicOperations.ZeroMemory(historicRecipient);
        }
    }

    public static void Configure(IDataProtectionBuilder dataProtection, string rootDirectory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Linux key protector is Linux-only");
        CheckPrivateDirectory(rootDirectory);
        var keyDirectory = Path.Combine(rootDirectory, "data-protection-keys");
        CheckPrivateDirectory(keyDirectory);
        var replica = IsFleetReplica();
        var distributed = Environment.GetEnvironmentVariable(DistributedRingSetting);
        if(distributed is not null && (replica ||
            Directory.EnumerateFileSystemEntries(keyDirectory).Any() ||
            new[]{LinuxDpRecoveryEvidence.ManifestEnv,LinuxDpRecoveryEvidence.PublicKeyEnv,
                LinuxDpRecoveryEvidence.MinimumRevisionEnv,LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,
                LinuxDpRecoveryEvidence.RequireEvidenceEnv}.Any(x=>Environment.GetEnvironmentVariable(x) is not null)))
            throw new InvalidOperationException("Distributed ring cannot mix with local key state, replica mode or offline recovery settings");
        ValidateExistingKeyRing(keyDirectory);
        // During a deliberately staged fleet restore, the independently held
        // signed checkpoint and minimum revision must match before key import.
        LinuxDpRecoveryEvidence.VerifyConfigured(keyDirectory);
        var current = LoadRsaProtector("YARP_LINUX_DP_CERT_PFX_PATH",
            "YARP_LINUX_DP_CERT_PASSWORD_FILE");
        // Optional overlap only during planned protection certificate rotation.
        // Previously persisted XML keys still require the old private key.
        var old = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PFX_PATH");
        var oldPassword = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE");
        if (string.IsNullOrEmpty(old) != string.IsNullOrEmpty(oldPassword))
            throw new InvalidOperationException("Old PFX and its password file must be specified together");
        // Expired historic RSA recipients remain decrypt-only; a new
        // certificate must always be currently valid for new-key encryption.
        X509Certificate2? previous = null;
        if (!string.IsNullOrEmpty(old))
            previous = LoadRsaProtector("YARP_LINUX_DP_OLD_CERT_PFX_PATH",
                "YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",
                decryptionOnlyPrevious: true);

        // Require the configured identities to cover ALL persisted recipient
        // certificates BEFORE admitting any service traffic. A new active
        // identity alone must not silently break previous auth sessions.
        RequireHistoricWrappingCertificates(keyDirectory, current, previous);
        dataProtection.ProtectKeysWithCertificate(current);
        if (previous is not null)
            dataProtection.UnprotectKeysWithAnyCertificate(current, previous);
        if(distributed is not null)
        {
            var settings=DistributedRingRepository.ReadSettings(distributed,rootDirectory);
            var repository=new DistributedRingRepository(settings,current,previous);
            try
            {
                var keys=repository.GetAllElements();
                if(settings.Mode=="reader"&&keys.Count==0)
                    throw new InvalidOperationException("Distributed reader requires existing encrypted keys");
                // Disable implicit generation on all fleet nodes. Rotation
                // is explicitly issued by the separately authorized writer.
                dataProtection.DisableAutomaticKeyGeneration();
                dataProtection.Services.AddSingleton<IXmlRepository>(_=>repository);
                dataProtection.Services.PostConfigure<KeyManagementOptions>(options=>
                {
                    options.AutoGenerateKeys=false;
                    options.XmlRepository=repository;
                });
            }
            catch {repository.Dispose();throw;}
        }
        else if (replica)
            ConfigureReplica(dataProtection, keyDirectory);
    }
}
