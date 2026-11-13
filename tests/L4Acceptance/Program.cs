using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

var repo = args.Length == 1 ? Path.GetFullPath(args[0]) : Directory.GetCurrentDirectory();
var dll = Path.Combine(repo, "engines", "L4", "bin", "Release", "net10.0", "L4Proxy.dll");
if (!File.Exists(dll)) throw new FileNotFoundException("Build L4 engine first", dll);
using var stop = new CancellationTokenSource();
var tcpA = new TcpListener(IPAddress.Loopback, 19111);
var tcpB = new TcpListener(IPAddress.Loopback, 19112);
tcpA.Start(); tcpB.Start();
var proxyBackend = new TcpListener(IPAddress.Loopback,19113);
var idleBackend = new TcpListener(IPAddress.Loopback,19114);
proxyBackend.Start(); idleBackend.Start();
using var udpA = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19121));
using var udpB = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19122));
var workers = new [] {
    TcpEcho(tcpA, "A", stop.Token), TcpEcho(tcpB, "B", stop.Token),
    ProxyProtocolBackend(proxyBackend, stop.Token), IdleBackend(idleBackend, stop.Token),
    UdpEcho(udpA, "A", stop.Token), UdpEcho(udpB, "B", stop.Token)
};
var scratch = Path.Combine(Path.GetTempPath(), "yarp-l4-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(scratch);
var configFile = Path.Combine(scratch, "l4.json");
File.WriteAllText(configFile, JsonSerializer.Serialize(new {
    AllowNonLoopbackListeners = false,
    Tcp = new object [] { new { Name = "tcp-echo", ListenHost="127.0.0.1", ListenPort=19011,
      Backends = new [] { new { Host="127.0.0.1", Port=19111 }, new { Host="127.0.0.1", Port=19112 } } },
      new { Name = "tcp-proxy-header", ListenHost="127.0.0.1", ListenPort=19012,
        SendProxyProtocolV1=true, TcpIdleTimeoutSeconds=2,
        Backends = new [] { new { Host="127.0.0.1", Port=19113 } } },
      new { Name = "tcp-idle", ListenHost="127.0.0.1", ListenPort=19013,
        TcpIdleTimeoutSeconds=1,
        Backends = new [] { new { Host="127.0.0.1", Port=19114 } } },
      new { Name = "tcp-drain", ListenHost="127.0.0.1", ListenPort=19014,
        Backends = new [] { new { Host="127.0.0.1", Port=19111, DrainNewConnections=true },
          new { Host="127.0.0.1", Port=19112, DrainNewConnections=false } } } },
    Udp = new [] { new { Name = "udp-echo", ListenHost="127.0.0.1", ListenPort=19021,
      Backends = new [] { new { Host="127.0.0.1", Port=19121 }, new { Host="127.0.0.1", Port=19122 } } } }
}));
var info=new ProcessStartInfo("dotnet") { WorkingDirectory=Path.GetDirectoryName(dll)!, UseShellExecute=false,
    RedirectStandardOutput=true, RedirectStandardError=true };
info.ArgumentList.Add(dll); info.ArgumentList.Add(configFile);
using var proxy=Process.Start(info) ?? throw new Exception("Unable to start L4 process");
var stdout=proxy.StandardOutput.ReadToEndAsync();
var stderr=proxy.StandardError.ReadToEndAsync();
try
{
    await WaitFor(async () =>
    {
        try { return (await TcpRoundTrip("ready")).Length > 0; } catch { return false; }
    });
    var tcpNodes=new Dictionary<string,int> {["A"]=0,["B"]=0};
    for (var i=0;i<24;i++)
    {
        var reply=await TcpRoundTrip("probe-"+i);
        var node=reply[..1];
        if(!tcpNodes.ContainsKey(node) || !reply.EndsWith("probe-"+i))
            throw new Exception("Bad TCP stream forwarding: "+reply);
        tcpNodes[node]++;
    }
    Assert(tcpNodes["A"]>=8 && tcpNodes["B"]>=8, "real TCP connections distributed to both backends");
    using var c1=new UdpClient(AddressFamily.InterNetwork);
    using var c2=new UdpClient(AddressFamily.InterNetwork);
    c1.Connect(IPAddress.Loopback,19021);
    c2.Connect(IPAddress.Loopback,19021);
    var first=await UdpRoundTrip(c1,"one");
    var second=await UdpRoundTrip(c2,"two");
    Assert(first[..1] != second[..1], "two UDP sessions distributed across both backends");
    for(int i=0;i<12;i++)
    {
        var reply=await UdpRoundTrip(c1,"repeat"+i);
        Assert(reply.StartsWith(first[..2]),"UDP source endpoint remains sticky to same backend");
    }
    for (var i=0;i<12;i++)
        Assert((await TcpRoundTrip("drain-"+i,19014)).StartsWith("B|"),
            "backend flagged draining does not receive new TCP streams");
    Assert(await ValidateProxyHeader(), "PROXY v1 reports source and destination before application bytes");
    Assert(await ValidateTcpIdle(), "idle TCP stream closed by configured timeout");
    // Verify active health rejects down nodes rather than repeatedly relying on connect exceptions.
    tcpA.Stop();
    await Task.Delay(2600);
    for(var i=0;i<20;i++)
        Assert((await TcpRoundTrip("unhealthy-"+i)).StartsWith("B|"),
            "active health probe removes down backend from new connection selection");
    Assert(await ValidatePublicBindDenied(), "public listener requires explicit opt-in");
    Console.WriteLine("L4 TCP+UDP REAL-SOCKET ACCEPTANCE PASSED");
}
finally
{
    stop.Cancel();
    tcpA.Stop();tcpB.Stop();proxyBackend.Stop();idleBackend.Stop();
    if(!proxy.HasExited)proxy.Kill(entireProcessTree:true);
    await proxy.WaitForExitAsync();
    try { await Task.WhenAll(workers); } catch {}
    try { Directory.Delete(scratch,true); } catch {}
    Console.WriteLine("L4 proxy stdout: "+(await stdout).Trim());
    var errors=(await stderr).Trim();
    if(errors.Length>0)Console.WriteLine("L4 proxy stderr: "+errors);
}
return 0;

async Task<string> TcpRoundTrip(string message, int port=19011)
{
    using var client=new TcpClient(AddressFamily.InterNetwork);
    await client.ConnectAsync(IPAddress.Loopback,port);
    using var stream=client.GetStream();
    var bytes=Encoding.UTF8.GetBytes(message+"\n");
    await stream.WriteAsync(bytes);
    var buffer=new byte[512];
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
    var received=await stream.ReadAsync(buffer,timeout.Token);
    if(received==0)throw new Exception("Unexpected TCP EOF");
    return Encoding.UTF8.GetString(buffer,0,received).Trim();
}
async Task<string> UdpRoundTrip(UdpClient c,string message)
{
    await c.SendAsync(Encoding.UTF8.GetBytes(message));
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
    var result=await c.ReceiveAsync(timeout.Token);
    return Encoding.UTF8.GetString(result.Buffer);
}
async Task<bool> ValidateProxyHeader()
{
    using var client = new TcpClient(AddressFamily.InterNetwork);
    await client.ConnectAsync(IPAddress.Loopback,19012);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    var bytes = new byte[256];
    var read = await client.GetStream().ReadAsync(bytes, timeout.Token);
    var reply = Encoding.ASCII.GetString(bytes,0,read);
    var tokens = reply.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
    return tokens.Length==6 && tokens[0]=="PROXY" && tokens[1]=="TCP4" &&
        tokens[2]=="127.0.0.1" && tokens[3]=="127.0.0.1" &&
        int.TryParse(tokens[4],out var sourcePort) && sourcePort>0 &&
        int.TryParse(tokens[5],out var targetPort) && targetPort==19012;
}
async Task<bool> ValidateTcpIdle()
{
    using var client = new TcpClient(AddressFamily.InterNetwork);
    await client.ConnectAsync(IPAddress.Loopback,19013);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try
    {
        return await client.GetStream().ReadAsync(new byte[1],timeout.Token)==0;
    }
    catch(OperationCanceledException) { return false; }
}
async Task<bool> ValidatePublicBindDenied()
{
    var forbidden=Path.Combine(scratch,"public.json");
    File.WriteAllText(forbidden,JsonSerializer.Serialize(new {
        AllowNonLoopbackListeners=false,
        Tcp=new [] { new { Name="blocked",ListenHost="0.0.0.0",ListenPort=19051,
        Backends=new [] {new {Host="127.0.0.1",Port=19111}} }},
        Udp=Array.Empty<object>()
    }));
    var start=new ProcessStartInfo("dotnet") { UseShellExecute=false,
        RedirectStandardOutput=true,RedirectStandardError=true };
    start.ArgumentList.Add(dll);start.ArgumentList.Add(forbidden);
    using var child=Process.Start(start)!;
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    await child.WaitForExitAsync(timeout.Token);
    return child.ExitCode != 0;
}
async Task WaitFor(Func<Task<bool>> check)
{
    for(var i=0;i<60;i++) { if(await check()) return; await Task.Delay(100); }
    throw new Exception("L4 service readiness timed out");
}
void Assert(bool value,string name)
{
    if(!value)throw new Exception("FAIL: "+name);
    Console.WriteLine("PASS: "+name);
}
static async Task TcpEcho(TcpListener listener,string id,CancellationToken token)
{
    try
    {
        while(!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client=await listener.AcceptTcpClientAsync(token); }
            catch (OperationCanceledException) { break; }
            _=Task.Run(async()=>
            {
                using(client)
                {
                    var stream=client.GetStream();
                    var buffer=new byte[1024];
                    try
                    {
                        var n=await stream.ReadAsync(buffer,token);
                        if(n>0)await stream.WriteAsync(Encoding.UTF8.GetBytes(id+"|"+
                            Encoding.UTF8.GetString(buffer,0,n)),token);
                    }
                    catch(Exception ex) when(ex is IOException or OperationCanceledException or SocketException) {}
                }
            },token);
        }
    }
    catch(SocketException) when(token.IsCancellationRequested){}
}
static async Task UdpEcho(UdpClient listener,string id,CancellationToken token)
{
    try
    {
        while(!token.IsCancellationRequested)
        {
            var packet=await listener.ReceiveAsync(token);
            var msg=id+"|"+Encoding.UTF8.GetString(packet.Buffer);
            await listener.SendAsync(Encoding.UTF8.GetBytes(msg),packet.RemoteEndPoint,token);
        }
    }
    catch(OperationCanceledException){}
    catch(ObjectDisposedException){}
}
static async Task ProxyProtocolBackend(TcpListener listener, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client=await listener.AcceptTcpClientAsync(token);
            _=Task.Run(async()=>
            {
                using(client)
                {
                    try
                    {
                        using var reader=new StreamReader(client.GetStream(),Encoding.ASCII,leaveOpen:true);
                        var header=await reader.ReadLineAsync(token);
                        if(header is not null && header.StartsWith("PROXY TCP4 "))
                            await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(header+"\n"),token);
                    }
                    catch(Exception ex) when(ex is IOException or SocketException or OperationCanceledException) { }
                }
            },token);
        }
    }
    catch(OperationCanceledException) { }
    catch(SocketException) when(token.IsCancellationRequested) { }
}
static async Task IdleBackend(TcpListener listener, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client=await listener.AcceptTcpClientAsync(token);
            _=Task.Run(async()=>
            {
                using(client)
                {
                    try { await Task.Delay(TimeSpan.FromSeconds(10),token); }
                    catch(OperationCanceledException) { }
                }
            },token);
        }
    }
    catch(OperationCanceledException) { }
    catch(SocketException) when(token.IsCancellationRequested) { }
}
