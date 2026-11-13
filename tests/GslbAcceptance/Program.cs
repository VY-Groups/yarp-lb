using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
var repo=args.Length==1?Path.GetFullPath(args[0]):Directory.GetCurrentDirectory();
var dll=Path.Combine(repo,"engines","GslbDns","bin","Release","net10.0","GslbDns.dll");
if(!File.Exists(dll))throw new FileNotFoundException("Compile DNS server first",dll);
using var cancel=new CancellationTokenSource();
var s1=new ProbeState();var s2=new ProbeState();
using var healthA=new TcpListener(IPAddress.Loopback,19711);
using var healthB=new TcpListener(IPAddress.Loopback,19712);
healthA.Start();healthB.Start();
var tasks=new []{ProbeServer(healthA,s1,cancel.Token),ProbeServer(healthB,s2,cancel.Token)};
var temp=Path.Combine(Path.GetTempPath(),"yarp-dns-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var configuration=Path.Combine(temp,"zones.json");
File.WriteAllText(configuration,JsonSerializer.Serialize(new {
 AllowNonLoopbackListeners=false,
 ListenHost="127.0.0.1",ListenPort=15353,ProbeIntervalSeconds=1,
 Zones=new []{new{ Name="app.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=2 },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",Weight=1 }
 } } }
}));
var info=new ProcessStartInfo("dotnet"){ UseShellExecute=false,CreateNoWindow=true,
 WorkingDirectory=Path.GetDirectoryName(dll)!,RedirectStandardOutput=true,RedirectStandardError=true };
info.ArgumentList.Add(dll);info.ArgumentList.Add(configuration);
using var dns=Process.Start(info)??throw new Exception("DNS process could not start");
var outTask=dns.StandardOutput.ReadToEndAsync();
var errTask=dns.StandardError.ReadToEndAsync();
using var client=new UdpClient(AddressFamily.InterNetwork);
client.Connect(IPAddress.Loopback,15353);
try
{
    await Wait(async()=> (await Query("app.integration.test")).Status==0);
    var counts=new Dictionary<string,int> {["127.0.0.21"]=0,["127.0.0.22"]=0};
    for(var i=0;i<90;i++)
    {
        var response=await Query("app.integration.test");
        Must(response.Status==0 && response.Ttl==10,"healthy zone responds with configured TTL");
        counts[response.Address!]++;
    }
    Must(counts["127.0.0.21"]==60 && counts["127.0.0.22"]==30,
        "two active sites weighted exactly 2:1 across 90 queries");
    s1.Healthy=0;
    await Wait(async()=> (await Query("app.integration.test")).Address=="127.0.0.22");
    for(var i=0;i<30;i++) Must((await Query("app.integration.test")).Address=="127.0.0.22",
        "failed site not returned while secondary healthy");
    s2.Healthy=0;
    await Wait(async()=> (await Query("app.integration.test")).Status==2);
    Must((await Query("app.integration.test")).Address is null,"all-down DNS fails closed without stale site");
    s1.Healthy=1;
    await Wait(async()=> (await Query("app.integration.test")).Address=="127.0.0.21");
    Must((await Query("unknown.integration.test")).Status==5,"unknown zones explicitly refused");
    Console.WriteLine("GSLB REAL DNS HEALTH AND FAILOVER ACCEPTANCE PASSED");
}
finally
{
    cancel.Cancel();
    healthA.Stop();healthB.Stop();
    if(!dns.HasExited)dns.Kill(entireProcessTree:true);
    await dns.WaitForExitAsync();
    try {await Task.WhenAll(tasks);}catch{}
    try {Directory.Delete(temp,true);}catch{}
    Console.WriteLine("DNS stdout: "+(await outTask).Trim());
    var errors=(await errTask).Trim();
    if(errors.Length>0)Console.WriteLine("DNS stderr: "+errors);
}
return 0;

async Task<(int Status,string? Address,int Ttl)> Query(string domain)
{
    var request=new List<byte>(256);
    var tx=(ushort)Random.Shared.Next(0,65536);
    request.Add((byte)(tx>>8));request.Add((byte)tx);
    request.AddRange(new byte[]{1,0,0,1,0,0,0,0,0,0,0,0});
    foreach(var label in domain.Split('.'))
    {
        request.Add((byte)label.Length);
        request.AddRange(Encoding.ASCII.GetBytes(label));
    }
    request.AddRange(new byte[]{0,0,1,0,1});
    await client.SendAsync(request.ToArray());
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
    var msg=await client.ReceiveAsync(timeout.Token);
    var b=msg.Buffer;
    if(b.Length<12 || BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(0,2))!=tx)
        throw new Exception("DNS transaction ID mismatch or malformed response");
    var rcode=b[3]&0x0f;
    var answers=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(6,2));
    if(answers==0)return(rcode,null,0);
    var a=b.AsSpan(b.Length-16,16);
    var ttl=(int)BinaryPrimitives.ReadUInt32BigEndian(a.Slice(6,4));
    return (rcode,new IPAddress(a.Slice(12,4)).ToString(),ttl);
}
async Task Wait(Func<Task<bool>> condition)
{
    for(var i=0;i<80;i++)
    {
        try {if(await condition())return;}
        catch(SocketException){}
        catch(OperationCanceledException){}
        await Task.Delay(100);
    }
    throw new Exception("GSLB health-state convergence timeout");
}
void Must(bool ok,string description) {if(!ok)throw new Exception("FAIL: "+description);}
static async Task ProbeServer(TcpListener server,ProbeState state,CancellationToken ct)
{
    try
    {
        while(!ct.IsCancellationRequested)
        {
            var client=await server.AcceptTcpClientAsync(ct);
            _=Task.Run(async()=>{
                using(client)
                {
                    var bytes=Encoding.ASCII.GetBytes(state.Healthy==1
                        ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    try {await client.GetStream().WriteAsync(bytes,ct);}
                    catch(Exception ex) when(ex is IOException or ObjectDisposedException or OperationCanceledException){}
                }
            },ct);
        }
    }
    catch(OperationCanceledException){}
    catch(SocketException) when(ct.IsCancellationRequested){}
}
sealed class ProbeState {public volatile int Healthy=1;}