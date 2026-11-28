using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

// Independent BMC power fencing. Only preconfigured systems that guarantee
// AlwaysOff after AC restoration are supported; never alter the BMC policy.
internal sealed class VipRedfishFence : IDisposable
{
    internal sealed record Settings(string Origin,string LeafSha256,string CaFile,string SystemPath,
        string SystemUuid,string CredentialFile);
    internal sealed record Credentials(string Username,string Password);
    private readonly HttpClient client;
    private readonly X509Certificate2? ca;
    private readonly Uri system;
    private readonly Guid uuid;
    private readonly string action;
    internal VipRedfishFence(HttpClient client,Uri system,Guid uuid,X509Certificate2? ca=null)
    {
        this.client=client;this.system=system;this.uuid=uuid;this.ca=ca;
        action=system.AbsolutePath+"/Actions/ComputerSystem.Reset";
    }
    internal static VipRedfishFence Open(Settings s)
    {
        if(!Uri.TryCreate(s.Origin,UriKind.Absolute,out var origin)||origin.Scheme!="https"||
            origin.AbsolutePath!="/"||origin.UserInfo!=""||origin.Query!=""||origin.Fragment!=""||
            !VipFenceProvider.Pin(s.LeafSha256)||
            !Regex.IsMatch(s.SystemPath??"",@"\A/redfish/v1/Systems/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}\z")||
            !Guid.TryParseExact(s.SystemUuid,"D",out var uuid)||uuid==Guid.Empty)
            throw new InvalidDataException("Invalid exact Redfish BMC system identity.");
        var credentials=JsonSerializer.Deserialize<Credentials>(File.ReadAllBytes(
            FleetQuorum.FilePath(s.CredentialFile,8192,true)),new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow})
            ??throw new InvalidDataException("Missing BMC credential.");
        if(credentials.Username is not {Length:>0 and <=128}||credentials.Password is not {Length:>0 and <=1024}||
            credentials.Username.Contains(':')||credentials.Username.Any(char.IsControl)||credentials.Password.Any(char.IsControl))
            throw new InvalidDataException("Invalid BMC credential.");
        var ca=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(s.CaFile,65536));
        HttpClientHandler? handler=null;
        try
        {
            var pin=Convert.FromHexString(s.LeafSha256);
            handler=new HttpClientHandler{UseProxy=false,AllowAutoRedirect=false,UseCookies=false};
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
            var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(8),MaxResponseContentBufferSize=65536};
            client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials.Username+":"+credentials.Password)));
            return new(client,new Uri(origin,s.SystemPath),uuid,ca);
        }
        catch{handler?.Dispose();ca.Dispose();throw;}
    }
    private async Task<(string Power,bool CanOff,bool CanOn)> Observe(CancellationToken token)
    {
        using var response=await client.GetAsync(system,token);
        if(response.StatusCode!=HttpStatusCode.OK)throw new InvalidDataException("Redfish observation refused.");
        var bytes=await response.Content.ReadAsByteArrayAsync(token);
        if(bytes.Length>65536)throw new InvalidDataException("Oversized Redfish response.");
        using var doc=JsonDocument.Parse(bytes);
        var root=doc.RootElement;
        if(root.GetProperty("@odata.id").GetString()!=system.AbsolutePath||
            !Guid.TryParse(root.GetProperty("UUID").GetString(),out var id)||id!=uuid||
            root.GetProperty("PowerRestorePolicy").GetString()!="AlwaysOff")
            throw new InvalidDataException("BMC identity or persistent power policy not confirmed.");
        var power=root.GetProperty("PowerState").GetString();
        if(power is not ("On" or "Off" or "PoweringOff" or "PoweringOn"))
            throw new InvalidDataException("Unrecognized or unsafe BMC power state.");
        JsonElement allowed=default;
        bool hasAction=root.TryGetProperty("Actions",out var actions)&&
            actions.TryGetProperty("#ComputerSystem.Reset",out var reset)&&
            reset.TryGetProperty("target",out var target)&&target.GetString()==action&&
            reset.TryGetProperty("ResetType@Redfish.AllowableValues",out allowed)&&allowed.ValueKind==JsonValueKind.Array;
        return (power,hasAction&&allowed.EnumerateArray().Any(x=>x.GetString()=="ForceOff"),
            hasAction&&allowed.EnumerateArray().Any(x=>x.GetString()=="On"));
    }
    internal async Task<bool> IsOff(CancellationToken token)=>(await Observe(token)).Power=="Off";
    internal async Task ConfirmOn(Func<CancellationToken,Task> assertPeer,CancellationToken token)
    {
        await assertPeer(token);
        var first=await Observe(token);
        if(first.Power=="Off")
        {
            if(!first.CanOn||!first.CanOff)throw new InvalidDataException("Exact Redfish On and ForceOff actions required.");
            await assertPeer(token);
            using var response=await client.PostAsJsonAsync(new Uri(system,action),new Dictionary<string,string>{{"ResetType","On"}},token);
            if(response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Accepted or HttpStatusCode.NoContent))
                throw new InvalidDataException("BMC power-on not accepted.");
        }
        else if(first.Power is not ("On" or "PoweringOn"))throw new InvalidDataException("Unsafe rearm power state.");
        for(int i=0;i<30;i++)
        {
            await assertPeer(token);
            if((await Observe(token)).Power=="On")
            {
                await assertPeer(token);
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(1),token);
        }
        throw new InvalidOperationException("BMC power-on unconfirmed.");
    }
    internal async Task ConfirmOff(Func<CancellationToken,Task> assertRevoked,CancellationToken token)
    {
        await assertRevoked(token);
        var first=await Observe(token);
        if(first.Power=="On")
        {
            if(!first.CanOff)throw new InvalidDataException("Exact Redfish ForceOff action not advertised.");
            await assertRevoked(token);
            using var response=await client.PostAsJsonAsync(new Uri(system,action),new Dictionary<string,string>{{"ResetType","ForceOff"}},token);
            if(response.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.Accepted or HttpStatusCode.NoContent))
                throw new InvalidDataException("BMC power-off not accepted.");
        }
        // A 2xx mutation is not proof. The actual system must report Off
        // with the same UUID and persistent restore policy; no blind retries.
        for(int i=0;i<20;i++)
        {
            await assertRevoked(token);
            if((await Observe(token)).Power=="Off")
            {
                await assertRevoked(token);
                if((await Observe(token)).Power=="Off")return;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500),token);
        }
        throw new InvalidOperationException("BMC power-off unconfirmed.");
    }
    public void Dispose(){client.Dispose();ca?.Dispose();}
}
