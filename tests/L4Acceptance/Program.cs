using System.Diagnostics;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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
var halfCloseBackend = new TcpListener(IPAddress.Loopback,19115);
var admissionBackend = new TcpListener(IPAddress.Loopback,19116);
proxyBackend.Start(); idleBackend.Start(); halfCloseBackend.Start(); admissionBackend.Start();
using var udpA = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19121));
using var udpB = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19122));
long udpAReceived = 0;
long udpLossA = 0, udpLossB = 0;
var udpLost = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
using var resetBackend = new TcpListener(IPAddress.Loopback, 19117);
resetBackend.Start();
using var refusedPortListener = new TcpListener(IPAddress.Loopback, 0);
refusedPortListener.Start();
var refusedPort = ((IPEndPoint)refusedPortListener.LocalEndpoint).Port;
refusedPortListener.Stop();
long resetRequests = 0, replayRequests = 0;
var resetSeen = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
long udpBReceived = 0;
var udpAProbeHealthy = 1;
var udpAUnhealthy = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var udpARecovered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var workers = new [] {
    TcpEcho(tcpA, "A", stop.Token), TcpEcho(tcpB, "B", stop.Token, request => { if (request.Contains("reset-unique", StringComparison.Ordinal)) Interlocked.Increment(ref replayRequests); }),
    ProxyProtocolBackend(proxyBackend, stop.Token), IdleBackend(idleBackend, stop.Token),
    HalfCloseBackend(halfCloseBackend, stop.Token), AdmissionBackend(admissionBackend, stop.Token),
    ResetBackend(resetBackend, stop.Token, () => { Interlocked.Increment(ref resetRequests); resetSeen.TrySetResult(); }),
    UdpEcho(udpA, "A", stop.Token, () => Interlocked.Increment(ref udpAReceived), () => Volatile.Read(ref udpAProbeHealthy) == 1,
        request => { if (request != "loss-unique") return false; Interlocked.Increment(ref udpLossA); udpLost.TrySetResult(); return true; }),
    UdpEcho(udpB, "B", stop.Token, () => Interlocked.Increment(ref udpBReceived), null,
        request => { if (request == "loss-unique") Interlocked.Increment(ref udpLossB); return false; })
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
      new { Name = "tcp-half-close", ListenHost="127.0.0.1", ListenPort=19015,
        TcpIdleTimeoutSeconds=5,
        Backends = new [] { new { Host="127.0.0.1", Port=19115 } } },
      new { Name = "tcp-admission", ListenHost="127.0.0.1", ListenPort=19016,
        TcpMaxConnections=2, TcpIdleTimeoutSeconds=30,
        Backends = new [] { new { Host="127.0.0.1", Port=19116 } } },
      new { Name = "tcp-reset", ListenHost="127.0.0.1", ListenPort=19017,
        TcpIdleTimeoutSeconds=3,
        Backends = new [] { new { Host="127.0.0.1", Port=19117 }, new { Host="127.0.0.1", Port=19112 } } },
      new { Name = "tcp-connect-failure", ListenHost="127.0.0.1", ListenPort=19028,
        ProbeIntervalSeconds=60, Backends = new [] { new { Host="127.0.0.1", Port=refusedPort } } },
      new { Name = "tcp-all-drained", ListenHost="127.0.0.1", ListenPort=19029,
        Backends = new [] { new { Host="127.0.0.1", Port=19111, DrainNewConnections=true },
          new { Host="127.0.0.1", Port=19112, DrainNewConnections=true } } },
      new { Name = "tcp-drain", ListenHost="127.0.0.1", ListenPort=19014,
        Backends = new [] { new { Host="127.0.0.1", Port=19111, DrainNewConnections=true },
          new { Host="127.0.0.1", Port=19112, DrainNewConnections=false } } } },
    Udp = new object [] { new { Name = "udp-echo", ListenHost="127.0.0.1", ListenPort=19021, UdpIdleTimeoutSeconds=30,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=false }, new { Host="127.0.0.1", Port=19122, DrainNewConnections=false } } },
      new { Name = "udp-drain", ListenHost="127.0.0.1", ListenPort=19022, UdpIdleTimeoutSeconds=30,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=true }, new { Host="127.0.0.1", Port=19122, DrainNewConnections=false } } },
      new { Name = "udp-idle", ListenHost="127.0.0.1", ListenPort=19024, UdpIdleTimeoutSeconds=2,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=false }, new { Host="127.0.0.1", Port=19122, DrainNewConnections=false } } },
      new { Name = "udp-admission", ListenHost="127.0.0.1", ListenPort=19025, UdpMaxSessions=1, UdpIdleTimeoutSeconds=2,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=false } } },
      new { Name = "udp-all-drained", ListenHost="127.0.0.1", ListenPort=19023, UdpIdleTimeoutSeconds=30,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=true }, new { Host="127.0.0.1", Port=19122, DrainNewConnections=true } } },
      new { Name = "udp-loss", ListenHost="127.0.0.1", ListenPort=19027,
      Backends = new [] { new { Host="127.0.0.1", Port=19121 }, new { Host="127.0.0.1", Port=19122 } } },
      new { Name = "udp-health", ListenHost="127.0.0.1", ListenPort=19026, UdpProbePayload="health-check",
      UdpProbeExpectedResponse="healthy", UdpProbeIntervalSeconds=1, UdpIdleTimeoutSeconds=30,
      Backends = new [] { new { Host="127.0.0.1", Port=19121, DrainNewConnections=false }, new { Host="127.0.0.1", Port=19122, DrainNewConnections=false } } } }
}));
var info=new ProcessStartInfo("dotnet") { WorkingDirectory=Path.GetDirectoryName(dll)!, UseShellExecute=false,
    RedirectStandardOutput=true, RedirectStandardError=true };
info.ArgumentList.Add(dll); info.ArgumentList.Add(configFile);
using var proxy=Process.Start(info) ?? throw new Exception("Unable to start L4 process");
var udpReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var idleRetired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var admissionRetired = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var stdout=ReadProxyOutput();
async Task<string> ReadProxyOutput()
{
    var output = new StringBuilder();
    var expected = new HashSet<string>(StringComparer.Ordinal)
    {
        "L4_UDP_READY udp-echo 127.0.0.1:19021",
        "L4_UDP_READY udp-drain 127.0.0.1:19022",
        "L4_UDP_READY udp-all-drained 127.0.0.1:19023",
        "L4_UDP_READY udp-idle 127.0.0.1:19024",
        "L4_UDP_READY udp-admission 127.0.0.1:19025",
        "L4_UDP_READY udp-health 127.0.0.1:19026",
        "L4_TCP_READY tcp-admission 127.0.0.1:19016",
        "L4_TCP_READY tcp-reset 127.0.0.1:19017",
        "L4_TCP_READY tcp-connect-failure 127.0.0.1:19028",
        "L4_TCP_READY tcp-all-drained 127.0.0.1:19029",
        "L4_UDP_READY udp-loss 127.0.0.1:19027"
    };
    while (await proxy.StandardOutput.ReadLineAsync() is { } line)
    {
        output.AppendLine(line);
        if (line == "L4_UDP_HEALTH udp-health 127.0.0.1:19121 healthy=False") udpAUnhealthy.TrySetResult();
        if (line == "L4_UDP_HEALTH udp-health 127.0.0.1:19121 healthy=True") udpARecovered.TrySetResult();
        expected.Remove(line);
        if (line == "L4_UDP_RETIRED udp-idle count=1") idleRetired.TrySetResult();
        if (line == "L4_UDP_RETIRED udp-admission count=1") admissionRetired.TrySetResult();
        if (expected.Count == 0) udpReady.TrySetResult();
    }
    if (expected.Count != 0)
        udpReady.TrySetException(new InvalidOperationException(
            "L4 exited before binding UDP listeners: " + string.Join(", ", expected)));
    return output.ToString();
}
var stderr=proxy.StandardError.ReadToEndAsync();
try
{
    await WaitFor(async () =>
    {
        try { return (await TcpRoundTrip("ready")).Length > 0; } catch { return false; }
    });
    // TCP can accept connections before the UDP sockets are bound. Windows
    // reports an early ICMP Port Unreachable as WSAECONNRESET (10054).
    // Wait for every actual UDP bind; never hide dropped test datagrams by retry.
    await udpReady.Task.WaitAsync(TimeSpan.FromSeconds(10));
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
    using (var malformed = new UdpClient(AddressFamily.InterNetwork))
    {
        malformed.Connect(IPAddress.Loopback, 19021);
        var payload = new byte[] { 0xff, 0x00, 0x80, 0x41, 0x0d, 0x0a };
        await malformed.SendAsync(payload);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        var response = await malformed.ReceiveAsync(timeout.Token);
        Assert(response.Buffer.Length == payload.Length + 2 &&
               response.Buffer.AsSpan(2).SequenceEqual(payload),
            "opaque malformed UDP payload bytes pass unchanged through the relay");
    }
    for(int i=0;i<12;i++)
    {
        var reply=await UdpRoundTrip(c1,"repeat"+i);
        Assert(reply.StartsWith(first[..2]),"UDP source endpoint remains sticky to same backend");
    }
    for (var i=0;i<8;i++)
    {
        using var udpDrain=new UdpClient(AddressFamily.InterNetwork);
        udpDrain.Connect(IPAddress.Loopback,19022);
        Assert((await UdpRoundTrip(udpDrain,"udp-drain-"+i)).StartsWith("B|"),
            "UDP new sessions exclude drained backends");
    }
    using (var allDrained=new UdpClient(AddressFamily.InterNetwork))
    {
        allDrained.Connect(IPAddress.Loopback,19023);
        var backendAReceived = Interlocked.Read(ref udpAReceived);
        var backendBReceived = Interlocked.Read(ref udpBReceived);
        await allDrained.SendAsync(Encoding.UTF8.GetBytes("must-not-forward"));
        using var noReply=new CancellationTokenSource(TimeSpan.FromMilliseconds(700));
        var receivedReply=false;
        try { await allDrained.ReceiveAsync(noReply.Token); receivedReply=true; }
        catch (OperationCanceledException) when (noReply.IsCancellationRequested) { }
        catch (SocketException ex) when (OperatingSystem.IsWindows() &&
            ex.SocketErrorCode == SocketError.ConnectionReset)
        {
            // Windows may surface the expected no-response as ICMP port-unreachable.
        }
        Assert(!receivedReply,"all-drained UDP listener fails closed");
        Assert(Interlocked.Read(ref udpAReceived) == backendAReceived &&
               Interlocked.Read(ref udpBReceived) == backendBReceived,
            "all-drained UDP datagram reaches neither backend");
    }
    Assert(!proxy.HasExited && (await UdpRoundTrip(c1,"still-sticky")).StartsWith(first[..2]),
        "L4 engine remains alive and drain checks preserve unrelated UDP sessions");
    Volatile.Write(ref udpAProbeHealthy, 0);
    await udpAUnhealthy.Task.WaitAsync(TimeSpan.FromSeconds(5));
    for (var i = 0; i < 8; i++)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, 19026);
        Assert((await UdpRoundTrip(client, "after-probe-failure")).StartsWith("B|"),
            "failed UDP application probe excludes that backend from new sessions");
    }
    Volatile.Write(ref udpAProbeHealthy, 1);
    await udpARecovered.Task.WaitAsync(TimeSpan.FromSeconds(5));
    var recoveredBackendA = false;
    for (var i = 0; i < 12 && !recoveredBackendA; i++)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, 19026);
        recoveredBackendA = (await UdpRoundTrip(client, "after-probe-recovery")).StartsWith("A|");
    }
    Assert(recoveredBackendA, "healthy UDP application probe restores backend to new sessions");
    using (var idleUdp = new UdpClient(AddressFamily.InterNetwork))
    {
        idleUdp.Connect(IPAddress.Loopback, 19024);
        var initial = await UdpRoundTrip(idleUdp, "before-idle");
        await idleRetired.Task.WaitAsync(TimeSpan.FromSeconds(6));
        var afterIdle = await UdpRoundTrip(idleUdp, "after-idle");
        Assert(initial[..1] != afterIdle[..1] && afterIdle.EndsWith("after-idle"),
            "idle UDP socket is retired without inbound traffic; same endpoint establishes a fresh relay");
    }
    for (var i=0;i<12;i++)
        Assert((await TcpRoundTrip("drain-"+i,19014)).StartsWith("B|"),
            "backend flagged draining does not receive new TCP streams");
    Assert(await ValidateProxyHeader(), "PROXY v1 reports source and destination before application bytes");
    Assert(await ValidateTcpHalfClose(), "client half-close reaches backend while backend response still drains");
    Assert(await ValidateTcpIdle(), "idle TCP stream closed by configured timeout");
    await ValidateAdmission();
    await ValidateTcpFailureBoundaries();
    await ValidateNoReplay();
    // Verify active health rejects down nodes rather than repeatedly relying on connect exceptions.
    tcpA.Stop();
    await Task.Delay(2600);
    for(var i=0;i<20;i++)
        Assert((await TcpRoundTrip("unhealthy-"+i)).StartsWith("B|"),
            "active health probe removes down backend from new connection selection");
    Assert(await ValidatePublicBindDenied(), "public listener requires explicit opt-in");
    await ValidatePartialStartupFailure();
    if (OperatingSystem.IsLinux()) await ValidateGracefulShutdown();
    else if (OperatingSystem.IsWindows()) await ValidateWindowsConsoleShutdown();
    Console.WriteLine("L4 TCP+UDP REAL-SOCKET ACCEPTANCE PASSED");
}
finally
{
    stop.Cancel();
    resetBackend.Stop();
    tcpA.Stop();tcpB.Stop();proxyBackend.Stop();idleBackend.Stop();halfCloseBackend.Stop();admissionBackend.Stop();
    if(!proxy.HasExited)proxy.Kill(entireProcessTree:true);
    await proxy.WaitForExitAsync();
    try { await Task.WhenAll(workers); } catch {}
    try { Directory.Delete(scratch,true); } catch {}
    Console.WriteLine("L4 proxy stdout: "+(await stdout).Trim());
    var errors=(await stderr).Trim();
    if(errors.Length>0)Console.WriteLine("L4 proxy stderr: "+errors);
}
return 0;

async Task ValidateGracefulShutdown()
{
    // The admission backend sends a greeting only after the upstream
    // connection exists, so both streams are established before SIGTERM.
    using var drain = new TcpClient(AddressFamily.InterNetwork);
    using var held = new TcpClient(AddressFamily.InterNetwork);
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var token = deadline.Token;
    await drain.ConnectAsync(IPAddress.Loopback, 19016, token);
    await held.ConnectAsync(IPAddress.Loopback, 19016, token);
    var drainStream = drain.GetStream();
    var heldStream = held.GetStream();
    var greeting = new byte[1];
    await drainStream.ReadExactlyAsync(greeting, token);
    Assert(greeting[0] == 1, "draining TCP stream established before SIGTERM");
    await heldStream.ReadExactlyAsync(greeting, token);
    Assert(greeting[0] == 1, "held TCP stream established before SIGTERM");

    var elapsed = Stopwatch.StartNew();
    var signal = new ProcessStartInfo("kill") { UseShellExecute = false };
    signal.ArgumentList.Add("-TERM");
    signal.ArgumentList.Add(proxy.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
    using (var sender = Process.Start(signal) ?? throw new Exception("Cannot send SIGTERM"))
    {
        await sender.WaitForExitAsync(token);
        Assert(sender.ExitCode == 0, "SIGTERM delivered to shipping process");
    }

    // A rejected connect is evidence that admission has actually stopped,
    // not merely that the signal command has returned.
    var admissionStopped = false;
    while (elapsed.Elapsed < TimeSpan.FromSeconds(3))
    {
        using var candidate = new TcpClient(AddressFamily.InterNetwork);
        try { await candidate.ConnectAsync(IPAddress.Loopback, 19016, token); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        { admissionStopped = true; break; }
        await Task.Delay(25, token);
    }
    Assert(admissionStopped, "SIGTERM stops accepting new TCP connections");
    Assert(!proxy.HasExited, "process remains alive while established streams drain");

    var payload = Encoding.ASCII.GetBytes("finish-during-drain");
    await drainStream.WriteAsync(payload, token);
    var reply = new byte[payload.Length];
    await drainStream.ReadExactlyAsync(reply, token);
    Assert(reply.AsSpan().SequenceEqual(payload), "established TCP transaction finishes after admission stops");
    drain.Client.Shutdown(SocketShutdown.Send);
    Assert(await drainStream.ReadAsync(new byte[1], token) == 0, "completed stream drains through EOF");

    // Leave the other stream open. Its 30-second idle deadline is longer
    // than the process drain budget, so shutdown must actively cancel it.
    await proxy.WaitForExitAsync(token);
    Assert(proxy.ExitCode == 0 && elapsed.Elapsed < TimeSpan.FromSeconds(10),
        "SIGTERM exits successfully within bounded drain and cleanup time");
    var heldClosed = false;
    try { heldClosed = await heldStream.ReadAsync(new byte[1], token) == 0; }
    catch (IOException) { heldClosed = true; }
    Assert(heldClosed, "held TCP stream is released after bounded shutdown");
    using var udpRebound = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19021));
    Assert(true, "UDP listener released on graceful process exit");
}

async Task ValidateWindowsConsoleShutdown()
{
    const int listenPort = 19040;
    const int udpPort = 19041;
    var configPath = Path.Combine(scratch, "l4-windows-console-shutdown.json");
    File.WriteAllText(configPath, JsonSerializer.Serialize(new
    {
        AllowNonLoopbackListeners = false,
        Tcp = new[] { new {
            Name = "windows-console-shutdown", ListenHost = "127.0.0.1", ListenPort = listenPort,
            TcpIdleTimeoutSeconds = 30,
            Backends = new[] { new { Host = "127.0.0.1", Port = 19116 } }
        } },
        Udp = new[] { new {
            Name = "windows-console-shutdown-udp", ListenHost = "127.0.0.1", ListenPort = udpPort,
            UdpIdleTimeoutSeconds = 30,
            Backends = new[] { new { Host = "127.0.0.1", Port = 19121 } }
        } }
    }));

    using var child = WindowsConsoleProcess.StartNewGroup(dll, configPath);
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var token = deadline.Token;
    using var drain = await ConnectWhenReady(listenPort, child, token);
    using var held = await ConnectWhenReady(listenPort, child, token);
    var drainStream = drain.GetStream();
    var heldStream = held.GetStream();
    var greeting = new byte[1];
    await drainStream.ReadExactlyAsync(greeting, token);
    Assert(greeting[0] == 1, "Windows console-control drain stream reached its backend");
    await heldStream.ReadExactlyAsync(greeting, token);
    Assert(greeting[0] == 1, "Windows console-control held stream reached its backend");

    var elapsed = Stopwatch.StartNew();
    WindowsConsoleProcess.SendBreak(child.Id);
    var admissionStopped = false;
    while (elapsed.Elapsed < TimeSpan.FromSeconds(3))
    {
        using var candidate = new TcpClient(AddressFamily.InterNetwork);
        try { await candidate.ConnectAsync(IPAddress.Loopback, listenPort, token); }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        { admissionStopped = true; break; }
        await Task.Delay(25, token);
    }
    Assert(admissionStopped, "Windows CTRL+BREAK stops new TCP admission");
    Assert(!child.HasExited, "Windows engine remains alive while established streams drain");

    var payload = Encoding.ASCII.GetBytes("finish-during-console-drain");
    await drainStream.WriteAsync(payload, token);
    var reply = new byte[payload.Length];
    await drainStream.ReadExactlyAsync(reply, token);
    Assert(reply.AsSpan().SequenceEqual(payload), "Windows established TCP transaction completes during drain");
    drain.Client.Shutdown(SocketShutdown.Send);
    Assert(await drainStream.ReadAsync(new byte[1], token) == 0,
        "Windows completed TCP stream drains through EOF");

    await child.WaitForExitAsync(token);
    Assert(child.ExitCode == 0 && elapsed.Elapsed < TimeSpan.FromSeconds(10),
        "Windows console-control shutdown exits within the bounded drain budget");
    var heldClosed = false;
    try { heldClosed = await heldStream.ReadAsync(new byte[1], token) == 0; }
    catch (IOException) { heldClosed = true; }
    Assert(heldClosed, "Windows held TCP stream is released after bounded shutdown");
    using var udpRebound = new UdpClient(new IPEndPoint(IPAddress.Loopback, udpPort));
    Assert(true, "Windows UDP listener is released after console-control shutdown");
}

async Task<TcpClient> ConnectWhenReady(int port, WindowsConsoleProcess child, CancellationToken token)
{
    var limit = Stopwatch.StartNew();
    while (limit.Elapsed < TimeSpan.FromSeconds(10))
    {
        token.ThrowIfCancellationRequested();
        if (child.HasExited)
            throw new InvalidOperationException($"Windows L4 child exited before binding (code {child.ExitCode}).");
        var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            await client.ConnectAsync(IPAddress.Loopback, port, token);
            return client;
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            client.Dispose();
            await Task.Delay(50, token);
        }
    }
    throw new TimeoutException("Windows L4 child did not bind its shutdown listener.");
}

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
async Task ValidateNoReplay()
{
    using (var client = new TcpClient(AddressFamily.InterNetwork))
    {
        await client.ConnectAsync(IPAddress.Loopback, 19017);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("reset-unique"), timeout.Token);
        await resetSeen.Task.WaitAsync(timeout.Token);
        var received = 0;
        try { received = await stream.ReadAsync(new byte[128], timeout.Token); }
        catch (IOException) { }
        catch (SocketException) { }
        Assert(received == 0 && Interlocked.Read(ref resetRequests) == 1,
            "established TCP backend reset terminates the original stream");
    }
    Assert((await TcpRoundTrip("new-after-reset", 19017)).StartsWith("B|"),
        "new TCP connection reaches surviving backend after reset");
    Assert(Interlocked.Read(ref replayRequests) == 0 && Interlocked.Read(ref resetRequests) == 1,
        "reset transaction never replayed to another TCP backend");

    using var udp = new UdpClient(AddressFamily.InterNetwork);
    udp.Connect(IPAddress.Loopback, 19027);
    await udp.SendAsync(Encoding.ASCII.GetBytes("loss-unique"));
    await udpLost.Task.WaitAsync(TimeSpan.FromSeconds(3));
    using (var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(700)))
    {
        var replied = false;
        try { await udp.ReceiveAsync(timeout.Token); replied = true; }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
        Assert(!replied, "lost UDP response is not retried");
    }
    Assert((await UdpRoundTrip(udp, "new-after-loss")).StartsWith("A|"),
        "UDP endpoint remains pinned after dropped backend response");
    using var fresh = new UdpClient(AddressFamily.InterNetwork);
    fresh.Connect(IPAddress.Loopback, 19027);
    Assert((await UdpRoundTrip(fresh, "new-endpoint")).StartsWith("B|"),
        "new UDP endpoint can reach alternate backend");
    Assert(Interlocked.Read(ref udpLossA) == 1 && Interlocked.Read(ref udpLossB) == 0,
        "lost UDP transaction delivered exactly once to original backend and never replayed");
}
async Task ValidateTcpFailureBoundaries()
{
    using (var failedConnect = new TcpClient(AddressFamily.InterNetwork))
    {
        await failedConnect.ConnectAsync(IPAddress.Loopback, 19028);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        Assert(await failedConnect.GetStream().ReadAsync(new byte[1], timeout.Token) == 0,
            "failed upstream connect closes downstream without forwarding application bytes");
    }
    using (var allDrained = new TcpClient(AddressFamily.InterNetwork))
    {
        await allDrained.ConnectAsync(IPAddress.Loopback, 19029);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        Assert(await allDrained.GetStream().ReadAsync(new byte[1], timeout.Token) == 0,
            "all-drained TCP listener rejects new streams without selecting a backend");
    }
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
async Task ValidateAdmission()
{
    async Task<TcpClient> Connect()
    {
        var client = new TcpClient(AddressFamily.InterNetwork);
        try { await client.ConnectAsync(IPAddress.Loopback,19016); return client; }
        catch { client.Dispose(); throw; }
    }
    async Task<bool> Ready(TcpClient client)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { return await client.Client.ReceiveAsync(new byte[1].AsMemory(),SocketFlags.None,timeout.Token) == 1; }
        catch (IOException) { return false; }
        catch (SocketException) { return false; }
    }
    using var one = await Connect();
    using var two = await Connect();
    Assert(await Ready(one) && await Ready(two), "two TCP streams acquire configured slots");
    using (var extra = await Connect())
        Assert(!await Ready(extra), "TCP overload closes extra connection before backend greeting");
    // Retain the stream before shutdown: TcpClient.GetStream can reject
    // a socket whose peer FIN arrives before the subsequent method call.
    var oneStream = one.GetStream();
    one.Client.Shutdown(SocketShutdown.Send);
    using (var eof = new CancellationTokenSource(TimeSpan.FromSeconds(3)))
        Assert(await oneStream.ReadAsync(new byte[1],eof.Token)==0, "half-close releases first TCP stream");
    await WaitFor(async () =>
    {
        using var recovered = await Connect();
        return await Ready(recovered);
    });
    await two.GetStream().WriteAsync(new byte[] { 42 });
    using (var response = new CancellationTokenSource(TimeSpan.FromSeconds(3)))
    {
        var echoed = new byte[1];
        Assert(await two.GetStream().ReadAsync(echoed,response.Token)==1 && echoed[0]==42,
            "TCP overload and slot recovery preserve established stream");
    }

    using var first = new UdpClient(AddressFamily.InterNetwork);
    using var extraUdp = new UdpClient(AddressFamily.InterNetwork);
    first.Connect(IPAddress.Loopback,19025); extraUdp.Connect(IPAddress.Loopback,19025);
    Assert((await UdpRoundTrip(first,"admitted")).EndsWith("admitted"), "UDP first session acquires slot");
    var before = Interlocked.Read(ref udpAReceived);
    await extraUdp.SendAsync(Encoding.UTF8.GetBytes("must-not-forward"));
    using (var noReply = new CancellationTokenSource(TimeSpan.FromMilliseconds(500)))
    {
        var reply = false;
        try { await extraUdp.ReceiveAsync(noReply.Token); reply = true; }
        catch (OperationCanceledException) when (noReply.IsCancellationRequested) { }
        catch (SocketException ex) when (OperatingSystem.IsWindows() && ex.SocketErrorCode==SocketError.ConnectionReset) { }
        Assert(!reply && Interlocked.Read(ref udpAReceived)==before, "UDP full table drops new session without forwarding");
    }
    Assert((await UdpRoundTrip(first,"preserved")).EndsWith("preserved"), "UDP capacity preserves existing session");
    await admissionRetired.Task.WaitAsync(TimeSpan.FromSeconds(6));
    Assert((await UdpRoundTrip(extraUdp,"recovered")).EndsWith("recovered"), "UDP capacity recovers after idle expiry");
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
async Task<bool> ValidateTcpHalfClose()
{
    using var client = new TcpClient(AddressFamily.InterNetwork);
    await client.ConnectAsync(IPAddress.Loopback,19015);
    var stream = client.GetStream();
    await stream.WriteAsync(Encoding.UTF8.GetBytes("request-"));
    await Task.Delay(150);
    await stream.WriteAsync(Encoding.UTF8.GetBytes("body"));
    client.Client.Shutdown(SocketShutdown.Send);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    using var response = new MemoryStream();
    var buffer = new byte[128];
    while (true)
    {
        var count = await stream.ReadAsync(buffer,timeout.Token);
        if (count == 0) break;
        response.Write(buffer,0,count);
    }
    return Encoding.UTF8.GetString(response.ToArray()) == "complete|request-body";
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
    var start=new ProcessStartInfo("dotnet") { WorkingDirectory=Path.GetDirectoryName(dll)!, UseShellExecute=false,
        RedirectStandardOutput=true,RedirectStandardError=true };
    start.ArgumentList.Add(dll);start.ArgumentList.Add(forbidden);
    using var child=Process.Start(start)!;
    var childOutput=child.StandardOutput.ReadToEndAsync();
    var childError=child.StandardError.ReadToEndAsync();
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(15));
    try { await child.WaitForExitAsync(timeout.Token); }
    catch (OperationCanceledException) when (timeout.IsCancellationRequested)
    {
        if (!child.HasExited) child.Kill(entireProcessTree:true);
        await child.WaitForExitAsync();
        throw new Exception("L4 public-bind rejection process timed out; " +
            $"stdout={await childOutput}; stderr={await childError}");
    }
    var output=await childOutput;
    var error=await childError;
    return child.ExitCode != 0 && error.Contains(
        "public binds require explicit opt-in",StringComparison.Ordinal);
}
async Task ValidatePartialStartupFailure()
{
    using var occupied = new TcpListener(IPAddress.Loopback, 0);
    occupied.Start();
    var blocked = ((IPEndPoint)occupied.LocalEndpoint).Port;
    var failureConfig = Path.Combine(scratch, "partial-bind.json");
    // First listener is valid and stays alive unless sibling failure stops it.
    File.WriteAllText(failureConfig, JsonSerializer.Serialize(new {
        AllowNonLoopbackListeners = false,
        Tcp = new [] {
            new { Name = "first-tcp", ListenHost = "127.0.0.1", ListenPort = 19052,
                Backends = new [] { new { Host = "127.0.0.1", Port = 19112 } } },
            new { Name = "blocked-tcp", ListenHost = "127.0.0.1", ListenPort = blocked,
                Backends = new [] { new { Host = "127.0.0.1", Port = 19112 } } }
        },
        Udp = new [] { new { Name = "sibling-udp", ListenHost = "127.0.0.1", ListenPort = 19053,
            Backends = new [] { new { Host = "127.0.0.1", Port = 19122 } } } }
    }));
    var start = new ProcessStartInfo("dotnet") { WorkingDirectory = Path.GetDirectoryName(dll)!,
        UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add(dll); start.ArgumentList.Add(failureConfig);
    using var child = Process.Start(start)!;
    var output = child.StandardOutput.ReadToEndAsync();
    var errors = child.StandardError.ReadToEndAsync();
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
    try { await child.WaitForExitAsync(timeout.Token); }
    catch (OperationCanceledException) when (timeout.IsCancellationRequested)
    {
        if (!child.HasExited) child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync();
        throw new Exception("Partial listener startup hung: " + await output + await errors);
    }
    var log = await output;
    Assert(child.ExitCode != 0 && log.Contains("L4_TCP_READY first-tcp") &&
        !log.Contains("L4_ENGINE_READY"), "partial bind failure exits nonzero without advertising engine readiness");
    Assert((await errors).Contains("SocketException"), "bind failure retains socket diagnostic");
    using var rebound = new TcpListener(IPAddress.Loopback, 19052);
    rebound.Start();
    using var reboundUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 19053));
    Assert(true, "sibling TCP and UDP listeners released on startup failure");
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
static async Task ResetBackend(TcpListener listener, CancellationToken token, Action recorded)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(token);
            _ = Task.Run(async () =>
            {
                using (client)
                {
                    try
                    {
                        var payload = new byte["reset-unique".Length];
                        await client.GetStream().ReadExactlyAsync(payload, token);
                        if (!payload.AsSpan().SequenceEqual(Encoding.ASCII.GetBytes("reset-unique"))) return;
                        client.Client.LingerState = new LingerOption(true, 0);
                        recorded();
                    }
                    catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { }
                }
            });
        }
    }
    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    catch (SocketException) when (token.IsCancellationRequested) { }
}
static async Task TcpEcho(TcpListener listener,string id,CancellationToken token, Action<string>? record = null)
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
                        if(n>0)
                        {
                            var request = Encoding.UTF8.GetString(buffer,0,n);
                            record?.Invoke(request);
                            await stream.WriteAsync(Encoding.UTF8.GetBytes(id+"|"+request),token);
                        }
                    }
                    catch(Exception ex) when(ex is IOException or OperationCanceledException or SocketException) {}
                }
            },token);
        }
    }
    catch(SocketException) when(token.IsCancellationRequested){}
}
static async Task UdpEcho(UdpClient listener,string id,CancellationToken token,Action recordReceived,Func<bool>? probeHealthy = null, Func<string,bool>? dropResponse = null)
{
    try
    {
        while(!token.IsCancellationRequested)
        {
            var packet=await listener.ReceiveAsync(token);
            if (packet.Buffer.Length > 0 && packet.Buffer[0] == 0xff)
            {
                var prefix = Encoding.ASCII.GetBytes(id + "|");
                var opaqueReply = new byte[prefix.Length + packet.Buffer.Length];
                prefix.CopyTo(opaqueReply, 0);
                packet.Buffer.CopyTo(opaqueReply, prefix.Length);
                await listener.SendAsync(opaqueReply, packet.RemoteEndPoint, token);
                continue;
            }
            var request = Encoding.UTF8.GetString(packet.Buffer);
            if (request == "health-check")
            {
                if (probeHealthy?.Invoke() ?? true)
                    await listener.SendAsync(Encoding.UTF8.GetBytes("healthy"),packet.RemoteEndPoint,token);
                continue;
            }
            recordReceived();
            if (dropResponse?.Invoke(request) == true) continue;
            var msg=id+"|"+request;
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
static async Task HalfCloseBackend(TcpListener listener, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client=await listener.AcceptTcpClientAsync(token);
            _=Task.Run(async() =>
            {
                using(client)
                using(var payload = new MemoryStream())
                {
                    var stream=client.GetStream();
                    var buffer=new byte[128];
                    try
                    {
                        int count;
                        while((count=await stream.ReadAsync(buffer,token))>0)
                            payload.Write(buffer,0,count);
                        var result=Encoding.UTF8.GetBytes("complete|"+
                            Encoding.UTF8.GetString(payload.ToArray()));
                        await stream.WriteAsync(result,token);
                    }
                    catch(Exception ex) when(ex is IOException or SocketException or OperationCanceledException) { }
                }
            },token);
        }
    }
    catch(OperationCanceledException) { }
    catch(SocketException) when(token.IsCancellationRequested) { }
}

static async Task AdmissionBackend(TcpListener listener, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(token);
            _ = Task.Run(async () =>
            {
                using (client)
                {
                    try
                    {
                        var stream = client.GetStream();
                        await stream.WriteAsync(new byte[] { 1 },token);
                        var buffer = new byte[64];
                        int count;
                        while ((count = await stream.ReadAsync(buffer,token)) > 0)
                            await stream.WriteAsync(buffer.AsMemory(0,count),token);
                    }
                    catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { }
                }
            });
        }
    }
    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    catch (SocketException) when (token.IsCancellationRequested) { }
}

internal sealed class WindowsConsoleProcess : IDisposable
{
    private const uint CreateNewProcessGroup = 0x00000200;
    private const uint CtrlBreakEvent = 1;
    private readonly Process process;
    private readonly bool ownsConsole;
    private readonly IntPtr processHandle;

    private WindowsConsoleProcess(Process process, bool ownsConsole, IntPtr processHandle)
    {
        this.process = process;
        this.ownsConsole = ownsConsole;
        this.processHandle = processHandle;
    }

    internal int Id => process.Id;
    internal bool HasExited => process.HasExited;
    internal int ExitCode => GetExitCodeProcess(processHandle, out var code)
        ? checked((int)code)
        : throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read L4 process exit code.");
    internal Task WaitForExitAsync(CancellationToken token) => process.WaitForExitAsync(token);

    internal static WindowsConsoleProcess StartNewGroup(string dll, string config)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows console-control acceptance requires Windows.");
        var ownsConsole = false;
        if (GetConsoleWindow() == IntPtr.Zero)
        {
            if (AllocConsole())
                ownsConsole = true;
            else
            {
                var error = Marshal.GetLastWin32Error();
                // Pseudoconsole hosts can be attached without exposing a normal
                // console window; AllocConsole reports ERROR_ACCESS_DENIED there.
                if (error != 5)
                    throw new Win32Exception(error, "Could not attach a console for CTRL+BREAK acceptance.");
            }
        }

        var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>() };
        var command = new StringBuilder($"\"dotnet.exe\" \"{dll}\" \"{config}\"");
        if (!CreateProcessW(null, command, IntPtr.Zero, IntPtr.Zero, false,
                CreateNewProcessGroup, IntPtr.Zero, Path.GetDirectoryName(dll), ref startup, out var info))
        {
            var error = Marshal.GetLastWin32Error();
            if (ownsConsole) _ = FreeConsole();
            throw new Win32Exception(error, "Could not start the L4 child in an isolated console process group.");
        }

        try
        {
            return new WindowsConsoleProcess(Process.GetProcessById(checked((int)info.dwProcessId)),
                ownsConsole, info.hProcess);
        }
        catch
        {
            _ = TerminateProcess(info.hProcess, 1);
            _ = CloseHandle(info.hProcess);
            if (ownsConsole) _ = FreeConsole();
            throw;
        }
        finally
        {
            _ = CloseHandle(info.hThread);
        }
    }

    internal static void SendBreak(int processGroupId)
    {
        if (!GenerateConsoleCtrlEvent(CtrlBreakEvent, checked((uint)processGroupId)))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not send CTRL+BREAK to the L4 process group.");
    }

    public void Dispose()
    {
        if (!process.HasExited)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
        }
        process.Dispose();
        _ = CloseHandle(processHandle);
        if (ownsConsole) _ = FreeConsole();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpReserved;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpDesktop;
        [MarshalAs(UnmanagedType.LPWStr)] public string? lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateProcessW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(string? applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags, IntPtr environment, string? currentDirectory, ref StartupInfo startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GenerateConsoleCtrlEvent(uint controlEvent, uint processGroupId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
}
