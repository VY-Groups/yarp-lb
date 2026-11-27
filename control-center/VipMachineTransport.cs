using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed class VipMachineTransport:IDisposable
{
    internal sealed record ClientSettings(string Origin,string LeafSha256,string CaFile,string CertFile,string KeyFile);
    internal sealed record ServerSettings(string ListenIp,int Port,string Pfx,string PasswordFile,string ClientCaFile,string ClientPin);
    internal static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web)
        {UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    private readonly HttpClient client;
    private readonly X509Certificate2 ca,credential;
    private readonly Uri origin;
    private VipMachineTransport(HttpClient client,X509Certificate2 ca,X509Certificate2 credential,Uri origin)
    {this.client=client;this.ca=ca;this.credential=credential;this.origin=origin;}
    internal static bool Pinned(X509Certificate2? leaf,X509Certificate2 ca,string pin,string eku)
    {
        if(leaf is null||!VipFenceProvider.Pin(pin)||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(leaf.RawData),Convert.FromHexString(pin)))return false;
        using var chain=new X509Chain();
        chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads=true;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(eku));
        return chain.Build(leaf);
    }
    internal static VipMachineTransport Open(ClientSettings s)
    {
        if(!Uri.TryCreate(s.Origin,UriKind.Absolute,out var uri)||uri.Scheme!="https"||
            uri.AbsolutePath!="/"||uri.Query!=""||uri.Fragment!=""||uri.UserInfo!=""||
            !VipFenceProvider.Pin(s.LeafSha256))throw new InvalidDataException("Exact private HTTPS origin required.");
        var ca=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(s.CaFile,65536));
        X509Certificate2? cert=null;HttpClientHandler? handler=null;
        try
        {
            using var pem=X509Certificate2.CreateFromPemFile(FleetQuorum.FilePath(s.CertFile,65536),FleetQuorum.FilePath(s.KeyFile,65536,true));
            cert=X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12),null,X509KeyStorageFlags.EphemeralKeySet);
            handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false,UseCookies=false};
            handler.ClientCertificates.Add(cert);
            handler.ServerCertificateCustomValidationCallback=(_,leaf,_,errors)=>
                (errors&(SslPolicyErrors.RemoteCertificateNameMismatch|SslPolicyErrors.RemoteCertificateNotAvailable))==0&&
                Pinned(leaf,ca,s.LeafSha256,"1.3.6.1.5.5.7.3.1");
            return new(new HttpClient(handler){Timeout=TimeSpan.FromSeconds(120),MaxResponseContentBufferSize=4096},ca,cert,uri);
        }
        catch{handler?.Dispose();cert?.Dispose();ca.Dispose();throw;}
    }
    internal async Task<T> Post<T>(string path,object request,CancellationToken token)
    {
        if(path is not ("/v1/vip-node/status" or "/v1/vip-node/activate" or "/admin/vip-machine/drain"))
            throw new InvalidDataException("Unknown machine operation.");
        using var response=await client.PostAsJsonAsync(new Uri(origin,path),request,Json,token);
        if(response.StatusCode!=HttpStatusCode.OK)throw new InvalidDataException("Machine operation unconfirmed.");
        var bytes=await response.Content.ReadAsByteArrayAsync(token);
        if(bytes.Length>4096)throw new InvalidDataException("Oversized machine response.");
        return JsonSerializer.Deserialize<T>(bytes,Json)??throw new InvalidDataException("Missing machine response.");
    }
    public void Dispose(){client.Dispose();credential.Dispose();ca.Dispose();}
}
