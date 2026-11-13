using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Separate experimental L4 engine. Not YARP or an ASP.NET HTTP route.
if (args.Length != 1 || !File.Exists(args[0]))
{
    Console.Error.WriteLine("Usage: dotnet L4Proxy.dll <absolute path to JSON config>");
    return 64;
}
var config = JsonSerializer.Deserialize<L4Config>(File.ReadAllText(args[0]), new JsonSerializerOptions
{
    PropertyNameCaseInsensitive = true
}) ?? throw new InvalidDataException("Missing L4 config");
var listeners = config.Tcp.Concat(config.Udp).ToArray();
if (listeners.Length == 0 || listeners.Length > 20)
    throw new InvalidDataException("Expect 1..20 TCP/UDP listeners");
var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var listener in listeners)
{
    if (!names.Add(listener.Name) || string.IsNullOrWhiteSpace(listener.Name) ||
        listener.ListenPort is < 1025 or > 65535 ||
        !IPAddress.TryParse(listener.ListenHost, out var bind) ||
        bind.AddressFamily != AddressFamily.InterNetwork ||
        (!config.AllowNonLoopbackListeners && !IPAddress.IsLoopback(bind)) ||
        listener.Backends is not { Length: > 0 and <= 16 } ||
        listener.TcpIdleTimeoutSeconds is < 1 or > 3600 ||
        listener.ProbeIntervalSeconds is < 1 or > 60 ||
        listener.Backends.Any(b => b.Port is < 1 or > 65535 ||
            !IPAddress.TryParse(b.Host, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork))
        throw new InvalidDataException($"Invalid listener {listener.Name}; addresses must be IPv4 literals and public binds require explicit opt-in.");
}
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
using var sigterm = OperatingSystem.IsLinux()
    ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, e => { e.Cancel = true; stop.Cancel(); })
    : null;
var activeTcp = new ConcurrentDictionary<long, Task>();
long nextTcp = 0;
var loops = new List<Task>();
foreach (var tcp in config.Tcp)
    loops.Add(RunTcp(tcp, stop.Token));
foreach (var udp in config.Udp)
    loops.Add(RunUdp(udp, stop.Token));
Console.WriteLine($"L4_ENGINE_READY TCP={config.Tcp.Length} UDP={config.Udp.Length}; version 0.1 experimental");
try { await Task.WhenAll(loops); }
catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
finally
{
    // Existing TCP streams may finish before forceful process exit.
    var all = Task.WhenAll(activeTcp.Values.ToArray());
    await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(5)));
}
return 0;

async Task RunTcp(L4Listener cfg, CancellationToken token)
{
    var listener = new TcpListener(IPAddress.Parse(cfg.ListenHost), cfg.ListenPort);
    listener.Start(256);
    Console.WriteLine($"L4_TCP_READY {cfg.Name} {cfg.ListenHost}:{cfg.ListenPort}");
    long cursor = -1;
    var targets = cfg.Backends.Select(b => new TcpTarget(b)).ToArray();
    var probes = ProbeTcpTargets(targets, cfg.ProbeIntervalSeconds, token);
    try
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (SocketException) when (token.IsCancellationRequested) { break; }
            var id = Interlocked.Increment(ref nextTcp);
            var task = ProxyTcp(client, cfg, targets, Interlocked.Increment(ref cursor), token);
            activeTcp[id] = task;
            _ = task.ContinueWith(completed => { activeTcp.TryRemove(id, out var removed); }, TaskScheduler.Default);
        }
    }
    finally
    {
        listener.Stop();
        try { await probes; }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
}
async Task ProbeTcpTargets(TcpTarget[] targets, int intervalSeconds, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            foreach (var target in targets)
            {
                if (target.Backend.DrainNewConnections) continue;
                using var client = new TcpClient(AddressFamily.InterNetwork);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(TimeSpan.FromMilliseconds(500));
                var healthy = 0;
                try
                {
                    await client.ConnectAsync(IPAddress.Parse(target.Backend.Host), target.Backend.Port, timeout.Token);
                    healthy = 1;
                }
                catch (Exception e) when (e is SocketException or OperationCanceledException) { }
                Volatile.Write(ref target.Healthy, healthy);
            }
            await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), token);
        }
    }
    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
}
async Task ProxyTcp(TcpClient downstream, L4Listener cfg, TcpTarget[] targets, long chosen, CancellationToken stopToken)
{
    using (downstream)
    {
        downstream.NoDelay = true;
        TcpClient? upstream = null;
        // Draining targets never receive NEW streams. If every active probe fails,
        // attempt configured non-draining backends rather than creating a probe-only outage.
        var available = targets.Where(t => !t.Backend.DrainNewConnections).ToArray();
        if (available.Length == 0) return;
        var healthy = available.Where(t => Volatile.Read(ref t.Healthy) == 1).ToArray();
        var candidates = healthy.Length > 0 ? healthy : available;
        // Try another target only during CONNECT, before any application payload is sent.
        for (var i = 0; i < candidates.Length; i++)
        {
            var target = candidates[(int)((chosen + i) % candidates.Length)].Backend;
            var next = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                await next.ConnectAsync(IPAddress.Parse(target.Host), target.Port, timeout.Token);
                upstream = next; break;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            { next.Dispose(); }
        }
        if (upstream is null) return;
        using (upstream)
        {
            using var clientStream = downstream.GetStream();
            using var serverStream = upstream.GetStream();
            // Explicitly opt in only when the upstream knows and TRUSTS PROXY v1.
            if (cfg.SendProxyProtocolV1)
            {
                var source = (IPEndPoint)downstream.Client.RemoteEndPoint!;
                var destination = (IPEndPoint)downstream.Client.LocalEndPoint!;
                var header = Encoding.ASCII.GetBytes(
                    $"PROXY TCP4 {source.Address} {destination.Address} {source.Port} {destination.Port}\r\n");
                await serverStream.WriteAsync(header);
            }
            // Shared idle timer is refreshed by successful traffic in EITHER direction.
            // Closing idle streams never triggers replay to a different backend.
            using var idle = new CancellationTokenSource();
            var timeout = TimeSpan.FromSeconds(cfg.TcpIdleTimeoutSeconds);
            idle.CancelAfter(timeout);
            var towardBackend = Pump(clientStream, serverStream, upstream.Client, idle, timeout);
            var towardClient = Pump(serverStream, clientStream, downstream.Client, idle, timeout);
            await Task.WhenAll(towardBackend, towardClient);
        }
    }
}
static async Task Pump(Stream from, Stream to, Socket destination,
    CancellationTokenSource idle, TimeSpan timeout)
{
    var buffer = new byte[32_768];
    try
    {
        while (true)
        {
            var count = await from.ReadAsync(buffer.AsMemory(), idle.Token);
            if (count == 0) break;
            idle.CancelAfter(timeout);
            await to.WriteAsync(buffer.AsMemory(0, count), idle.Token);
            idle.CancelAfter(timeout);
        }
    }
    catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException) { }
    finally
    {
        try { destination.Shutdown(SocketShutdown.Send); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }
}
async Task RunUdp(L4Listener cfg, CancellationToken token)
{
    using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    listener.Bind(new IPEndPoint(IPAddress.Parse(cfg.ListenHost), cfg.ListenPort));
    Console.WriteLine($"L4_UDP_READY {cfg.Name} {cfg.ListenHost}:{cfg.ListenPort}");
    var sessions = new Dictionary<string, UdpSession>();
    long cursor = -1;
    var buffer = new byte[65_535];
    try
    {
        while (!token.IsCancellationRequested)
        {
            SocketReceiveFromResult received;
            try
            {
                received = await listener.ReceiveFromAsync(buffer, SocketFlags.None,
                    new IPEndPoint(IPAddress.Any, 0), token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (SocketException) when (token.IsCancellationRequested) { break; }
            var now = Environment.TickCount64;
            foreach (var (expiredKey, value) in sessions.ToArray())
            {
                if (now - value.LastSeenMs <= 30_000) continue;
                sessions.Remove(expiredKey);
                value.Close();
            }
            var remote = (IPEndPoint)received.RemoteEndPoint;
            var key = remote.ToString();
            if (!sessions.TryGetValue(key, out var session))
            {
                if (sessions.Count >= 1024) continue; // explicit bound; drop new sessions
                var selected = cfg.Backends[(int)(Interlocked.Increment(ref cursor) % cfg.Backends.Length)];
                var peer = new UdpClient(AddressFamily.InterNetwork);
                peer.Connect(IPAddress.Parse(selected.Host), selected.Port);
                session = new UdpSession(peer, remote, now);
                sessions.Add(key, session);
                _ = RelayUdpResponse(session, listener, token);
            }
            session.LastSeenMs = now;
            try { await session.Upstream.SendAsync(buffer.AsMemory(0, received.ReceivedBytes), token); }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
        }
    }
    finally { foreach (var entry in sessions.Values) entry.Close(); }
}
static async Task RelayUdpResponse(UdpSession session, Socket downstream, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var reply = await session.Upstream.ReceiveAsync(token);
            if (Environment.TickCount64 - session.LastSeenMs > 30_000) break;
            await downstream.SendToAsync(reply.Buffer, SocketFlags.None, session.Client, token);
        }
    }
    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException) { }
}
sealed record L4Config(bool AllowNonLoopbackListeners, L4Listener[] Tcp, L4Listener[] Udp);
sealed record L4Listener(string Name, string ListenHost, int ListenPort, L4Backend[] Backends,
    int TcpIdleTimeoutSeconds = 300, int ProbeIntervalSeconds = 2, bool SendProxyProtocolV1 = false);
sealed record L4Backend(string Host, int Port, bool DrainNewConnections = false);
sealed class TcpTarget
{
    public TcpTarget(L4Backend backend) => Backend = backend;
    public L4Backend Backend { get; }
    public int Healthy = 1; // unknown until first probe; connect-time fallback still applies
}
sealed class UdpSession
{
    public UdpSession(UdpClient upstream, IPEndPoint client, long now) =>
        (Upstream, Client, LastSeenMs) = (upstream, client, now);
    public UdpClient Upstream { get; }
    public IPEndPoint Client { get; }
    public long LastSeenMs;
    public void Close() => Upstream.Dispose();
}