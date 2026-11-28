using System.Runtime.InteropServices;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

#if GATEWAYCORE_COMMERCIAL
if(EngineLicenseGate.VerifyReleaseOrExit(args,out var releaseExit))return releaseExit;
if(EngineLicenseGate.Command(args,out var licenseExit))return licenseExit;
using var engineLicense=EngineLicenseGate.Start("l4");
#endif
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
        listener.TcpMaxConnections is < 1 or > 4096 ||
        listener.UdpMaxSessions is < 1 or > 4096 ||
        listener.TcpIdleTimeoutSeconds is < 1 or > 3600 ||
        listener.UdpIdleTimeoutSeconds is < 1 or > 3600 ||
        listener.ProbeIntervalSeconds is < 1 or > 60 ||
        listener.UdpProbeIntervalSeconds is < 1 or > 60 ||
        ((listener.UdpProbePayload is null) != (listener.UdpProbeExpectedResponse is null)) ||
        (listener.UdpProbePayload is { } probePayload && Encoding.UTF8.GetByteCount(probePayload) is < 1 or > 512) ||
        (listener.UdpProbeExpectedResponse is { } probeResponse && Encoding.UTF8.GetByteCount(probeResponse) is < 1 or > 512) ||
        listener.BalancingPolicy is not ("RoundRobin" or "WeightedRoundRobin" or "WeightedLeastConnections") ||
        (config.Udp.Contains(listener) && listener.BalancingPolicy == "WeightedLeastConnections") ||
        listener.Backends.Any(b => b.Weight is < 1 or > 100 || b.Port is < 1 or > 65535 ||
            !IPAddress.TryParse(b.Host, out var ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork))
        throw new InvalidDataException($"Invalid listener {listener.Name}; addresses must be IPv4 literals and public binds require explicit opt-in.");
}
var plan = AdcListenerPlan.ReadFromEnvironment();
if (plan is not null)
    plan.RequireExact(config.Tcp.Select(x => new AdcListenerPlan.Entry(x.Name,x.ListenHost,x.ListenPort,"TCP"))
        .Concat(config.Udp.Select(x => new AdcListenerPlan.Entry(x.Name,x.ListenHost,x.ListenPort,"UDP"))), true);
// Bind every socket before starting any forwarding loop. A failed bind disposes
// all earlier reservations and never publishes partial engine readiness.
using var reserved = new L4SocketReservations();
foreach (var tcp in config.Tcp) reserved.ReserveTcp(tcp);
foreach (var udp in config.Udp) reserved.ReserveUdp(udp);
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
using var sigterm = OperatingSystem.IsLinux()
    ? PosixSignalRegistration.Create(PosixSignal.SIGTERM, e => { e.Cancel = true; stop.Cancel(); })
    : null;
using var forceTcpStop = new CancellationTokenSource();
#if GATEWAYCORE_COMMERCIAL
// A single watchdog cancels all in-flight TCP/UDP work, including idle or
// blocked socket reads, on feature loss. An explicit restart is required
// after recovery; existing connections must never resume on a new license.
var entitlementLost=0;
var licenseWatch=WatchEntitlement();
async Task WatchEntitlement()
{
    using var timer=new PeriodicTimer(TimeSpan.FromMilliseconds(100));
    try
    {
        while(await timer.WaitForNextTickAsync(stop.Token))
        {
            if(engineLicense.Allows("l4"))continue;
            Interlocked.Exchange(ref entitlementLost,1);
            Console.Error.WriteLine("L4_ENTITLEMENT_LOST: terminating established flows and listeners");
            forceTcpStop.Cancel();
            stop.Cancel();
            return;
        }
    }
    catch(OperationCanceledException) when(stop.IsCancellationRequested){}
}
#endif
var activeTcp = new ConcurrentDictionary<long, Task>();
long nextTcp = 0;
var loops = new List<Task>();
foreach (var tcp in config.Tcp)
    loops.Add(RunTcp(tcp, reserved.Tcp[tcp.Name], stop.Token));
foreach (var udp in config.Udp)
    loops.Add(RunUdp(udp, reserved.Udp[udp.Name], stop.Token));
try
{
    // A listener can fail during bind or later while other listeners are
    // still running. Waiting for all before signalling stop would hang the
    // process in a partially available state.
    if (!loops.Any(loop => loop.IsCompleted))
        Console.WriteLine($"L4_ENGINE_READY TCP={config.Tcp.Length} UDP={config.Udp.Length}; version 0.1 experimental");
    await Task.WhenAny(loops);
    var requestedStop = stop.IsCancellationRequested;
    stop.Cancel();
    await Task.WhenAll(loops);
    if (!requestedStop)
        throw new InvalidOperationException("L4 listener exited unexpectedly");
}
catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
finally
{
    // Existing TCP streams may finish before forceful process exit.
    var all = Task.WhenAll(activeTcp.Values.ToArray());
    if (await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(5))) != all)
    {
        forceTcpStop.Cancel();
        await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(2)));
    }
    if (all.IsCompleted) await all;
#if GATEWAYCORE_COMMERCIAL
    stop.Cancel();
    await licenseWatch;
#endif
}
#if GATEWAYCORE_COMMERCIAL
return Volatile.Read(ref entitlementLost)!=0?78:0;
#else
return 0;
#endif

async Task RunTcp(L4Listener cfg, TcpListener listener, CancellationToken token)
{
    Console.WriteLine($"L4_TCP_READY {cfg.Name} {cfg.ListenHost}:{cfg.ListenPort}");
    long cursor = -1;
    int admitted = 0;
    long rejected = 0;
    var targets = cfg.Backends.Select(b => new TcpTarget(b)).ToArray();
    async Task ForwardAdmitted(TcpClient client, long chosen)
    {
        try { await ProxyTcp(client, cfg, targets, chosen, token, forceTcpStop.Token); }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or OperationCanceledException)
        { /* A transport failure terminates this stream, never replays bytes. */ }
        finally { client.Dispose(); Interlocked.Decrement(ref admitted); }
    }
    var probes = ProbeTcpTargets(targets, cfg.ProbeIntervalSeconds, token);
    try
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await listener.AcceptTcpClientAsync(token); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { break; }
            catch (SocketException) when (token.IsCancellationRequested) { break; }
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4")){client.Dispose();continue;}
#endif
            // Only the accept loop acquires slots; every forwarding exit
            // releases one. Reject before allocating upstream sockets/pumps.
            if (Interlocked.Increment(ref admitted) > cfg.TcpMaxConnections)
            {
                Interlocked.Decrement(ref admitted);
                Interlocked.Increment(ref rejected);
                client.Dispose();
                continue;
            }
            var id = Interlocked.Increment(ref nextTcp);
            var task = ForwardAdmitted(client, Interlocked.Increment(ref cursor));
            activeTcp[id] = task;
            _ = task.ContinueWith(completed =>
            {
                activeTcp.TryRemove(id, out _);
                // Observe unexpected faults even after the task leaves the registry.
                if (completed.IsFaulted) _ = completed.Exception;
            }, TaskScheduler.Default);
        }
    }
    finally
    {
        listener.Stop();
        Console.WriteLine($"L4_TCP_ADMISSION_STOP {cfg.Name} active={Volatile.Read(ref admitted)} rejected={Interlocked.Read(ref rejected)}");
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
async Task ProxyTcp(TcpClient downstream, L4Listener cfg, TcpTarget[] targets, long chosen,
    CancellationToken stopToken, CancellationToken forceToken)
{
    using (downstream)
    {
        downstream.NoDelay = true;
        TcpClient? upstream = null;
        TcpTarget? reserved = null;
        try
        {
        // Draining targets never receive NEW streams. If every active probe fails,
        // attempt configured non-draining backends rather than creating a probe-only outage.
        var available = targets.Where(t => !t.Backend.DrainNewConnections).ToArray();
        if (available.Length == 0) return;
        var healthy = available.Where(t => Volatile.Read(ref t.Healthy) == 1).ToArray();
        var candidates = healthy.Length > 0 ? healthy : available;
        // Try another target only during CONNECT, before any application payload is sent.
        var ordered = OrderTcpCandidates(candidates, cfg.BalancingPolicy, chosen);
        for (var i = 0; i < ordered.Length; i++)
        {
            if (stopToken.IsCancellationRequested) return;
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4"))return;
#endif
            var selected = ordered[i];
            var target = selected.Backend;
            var next = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            Interlocked.Increment(ref selected.ActiveConnections);
            reserved = selected;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                await next.ConnectAsync(IPAddress.Parse(target.Host), target.Port, timeout.Token);
                upstream = next; break;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                next.Dispose();
                Interlocked.Decrement(ref selected.ActiveConnections);
                reserved = null;
            }
        }
        if (upstream is null) return;
        using (upstream)
        {
            using var clientStream = downstream.GetStream();
            using var serverStream = upstream.GetStream();
            // The same idle/forced-stop bound covers the optional header and
            // both pumps. Shutdown allows established streams a bounded drain.
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(forceToken);
            var timeout = TimeSpan.FromSeconds(cfg.TcpIdleTimeoutSeconds);
            idle.CancelAfter(timeout);
            // Explicitly opt in only when the upstream knows and TRUSTS PROXY v1.
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4"))return;
#endif
            if (cfg.SendProxyProtocolV1)
            {
                var source = (IPEndPoint)downstream.Client.RemoteEndPoint!;
                var destination = (IPEndPoint)downstream.Client.LocalEndPoint!;
                var header = Encoding.ASCII.GetBytes(
                    $"PROXY TCP4 {source.Address} {destination.Address} {source.Port} {destination.Port}\r\n");
                await serverStream.WriteAsync(header, idle.Token);
                idle.CancelAfter(timeout);
            }
            // Shared idle timer is refreshed by successful traffic in EITHER direction.
            // Closing idle streams never triggers replay to a different backend.
            var towardBackend = Pump(clientStream, serverStream, upstream.Client, idle, timeout);
            var towardClient = Pump(serverStream, clientStream, downstream.Client, idle, timeout);
            await Task.WhenAll(towardBackend, towardClient);
        }
        }
        finally { if (reserved is not null) Interlocked.Decrement(ref reserved.ActiveConnections); }
    }
}

static int WeightedIndex(int[] weights, long cursor)
{
    var ticket = (int)((ulong)cursor % (ulong)weights.Sum());
    for (var i = 0; i < weights.Length; i++)
    {
        if (ticket < weights[i]) return i;
        ticket -= weights[i];
    }
    throw new InvalidOperationException("Invalid weighted selection");
}
static TcpTarget[] OrderTcpCandidates(TcpTarget[] candidates, string policy, long cursor)
{
    var start = policy == "WeightedRoundRobin"
        ? WeightedIndex(candidates.Select(t => t.Backend.Weight).ToArray(), cursor)
        : (int)((ulong)cursor % (ulong)candidates.Length);
    var ordered = Enumerable.Range(0, candidates.Length)
        .Select(i => candidates[(start + i) % candidates.Length]);
    // Stable ties preserve the rotated order. Count connecting and established
    // streams, never active health probes. Selection/reservation starts on the
    // single accept loop before its first asynchronous connect.
    if (policy == "WeightedLeastConnections")
        ordered = ordered.OrderBy(t => ((double)Volatile.Read(ref t.ActiveConnections) + 1) / t.Backend.Weight);
    return ordered.ToArray();
}
async Task Pump(Stream from, Stream to, Socket destination,
    CancellationTokenSource idle, TimeSpan timeout)
{
    var buffer = new byte[32_768];
    try
    {
        while (true)
        {
            var count = await from.ReadAsync(buffer.AsMemory(), idle.Token);
            if (count == 0) break;
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4")){idle.Cancel();break;}
#endif
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
async Task RunUdp(L4Listener cfg, Socket listener, CancellationToken token)
{
    Console.WriteLine($"L4_UDP_READY {cfg.Name} {cfg.ListenHost}:{cfg.ListenPort}");
    var sessions = new Dictionary<string, UdpSession>();
    var targets = cfg.Backends.Select(b => new UdpTarget(b)).ToArray();
    long cursor = -1;
    var buffer = new byte[65_535];
    var idleMs = cfg.UdpIdleTimeoutSeconds * 1000L;
    using var sweepTimer = new PeriodicTimer(TimeSpan.FromSeconds(1));
    using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
    var ct = lifetime.Token;
    var probes = ProbeUdpTargets(cfg, targets, ct);
    Task<SocketReceiveFromResult> Receive() => listener.ReceiveFromAsync(buffer.AsMemory(),
        SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct).AsTask();
    var receive = Receive();
    var tick = sweepTimer.WaitForNextTickAsync(ct).AsTask();
    bool Expired(UdpSession session, long now) =>
        session.IsClosed || now - Interlocked.Read(ref session.LastSeenMs) >= idleMs;
    try
    {
        while (!ct.IsCancellationRequested)
        {
            // One outstanding receive and one timer. Idle cleanup continues
            // even without traffic; avoid a full table scan for every packet.
            if (!receive.IsCompleted && !tick.IsCompleted)
                await Task.WhenAny(receive, tick);
            if (tick.IsCompleted)
            {
                if (!await tick) break;
                var sweepNow = Environment.TickCount64;
                var retired = 0;
                foreach (var (expiredKey, expiredSession) in sessions.ToArray())
                {
                    if (!Expired(expiredSession, sweepNow)) continue;
                    sessions.Remove(expiredKey);
                    expiredSession.Close();
                    retired++;
                }
                if (retired > 0)
                    Console.WriteLine($"L4_UDP_RETIRED {cfg.Name} count={retired}");
                tick = sweepTimer.WaitForNextTickAsync(ct).AsTask();
            }
            if (!receive.IsCompleted) continue;
            var received = await receive;
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4")){receive=Receive();continue;}
#endif
            var now = Environment.TickCount64;
            var remote = (IPEndPoint)received.RemoteEndPoint;
            var key = remote.ToString();
            if (sessions.TryGetValue(key, out var session) && Expired(session, now))
            {
                sessions.Remove(key);
                session.Close();
                session = null;
            }
            var eligibleBackends = targets.Where(t => !t.Backend.DrainNewConnections).ToArray();
            var healthyBackends = eligibleBackends.Where(t => Volatile.Read(ref t.Healthy) == 1).ToArray();
            // Keep the same availability-first contract as TCP: if every probe fails,
            // try configured non-draining targets rather than creating a probe-only outage.
            var candidates = healthyBackends.Length > 0 ? healthyBackends : eligibleBackends;
            if (session is null && sessions.Count < cfg.UdpMaxSessions && candidates.Length != 0)
            {
                var ticket = Interlocked.Increment(ref cursor);
                var index = cfg.BalancingPolicy == "WeightedRoundRobin"
                    ? WeightedIndex(candidates.Select(t => t.Backend.Weight).ToArray(), ticket)
                    : (int)((ulong)ticket % (ulong)candidates.Length);
                var selected = candidates[index].Backend;
                var peer = new UdpClient(AddressFamily.InterNetwork);
                peer.Connect(IPAddress.Parse(selected.Host), selected.Port);
                session = new UdpSession(peer, remote, now);
                sessions.Add(key, session);
                _ = RelayUdpResponse(session, listener, idleMs, ct);
            }
            if (session is not null)
            {
                Interlocked.Exchange(ref session.LastSeenMs, now);
                try { await session.Upstream.SendAsync(buffer.AsMemory(0, received.ReceivedBytes), ct); }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    // Retire the broken relay; never retry this datagram.
                    session.Close();
                    sessions.Remove(key);
                }
            }
            receive = Receive();
        }
    }
    catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    catch (SocketException) when (ct.IsCancellationRequested) { }
    finally
    {
        lifetime.Cancel();
        foreach (var entry in sessions.Values) entry.Close();
        // Observe outstanding asynchronous operations before disposing sockets.
        try { await receive; } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (SocketException) when (ct.IsCancellationRequested) { }
        try { await tick; } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        try { await probes; } catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }
}
static async Task ProbeUdpTargets(L4Listener cfg, UdpTarget[] targets, CancellationToken token)
{
    if (cfg.UdpProbePayload is null || cfg.UdpProbeExpectedResponse is null) return;
    var payload = Encoding.UTF8.GetBytes(cfg.UdpProbePayload);
    var expected = Encoding.UTF8.GetBytes(cfg.UdpProbeExpectedResponse);
    try
    {
        while (!token.IsCancellationRequested)
        {
            foreach (var target in targets)
            {
                if (target.Backend.DrainNewConnections) continue;
                var healthy = false;
                try
                {
                    using var probe = new UdpClient(AddressFamily.InterNetwork);
                    probe.Connect(IPAddress.Parse(target.Backend.Host), target.Backend.Port);
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                    timeout.CancelAfter(TimeSpan.FromMilliseconds(500));
                    await probe.SendAsync(payload, timeout.Token);
                    var response = await probe.ReceiveAsync(timeout.Token);
                    healthy = response.Buffer.AsSpan().SequenceEqual(expected);
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException) { }
                var previous = Interlocked.Exchange(ref target.Healthy, healthy ? 1 : 0);
                if (previous != (healthy ? 1 : 0))
                    Console.WriteLine($"L4_UDP_HEALTH {cfg.Name} {target.Backend.Host}:{target.Backend.Port} healthy={healthy}");
            }
            await Task.Delay(TimeSpan.FromSeconds(cfg.UdpProbeIntervalSeconds), token);
        }
    }
    catch (OperationCanceledException) when (token.IsCancellationRequested) { }
}
async Task RelayUdpResponse(UdpSession session, Socket downstream, long idleMs, CancellationToken token)
{
    try
    {
        while (!token.IsCancellationRequested)
        {
            var reply = await session.Upstream.ReceiveAsync(token);
#if GATEWAYCORE_COMMERCIAL
            if(!engineLicense.Allows("l4"))break;
#endif
            if (session.IsClosed || Environment.TickCount64 - Interlocked.Read(ref session.LastSeenMs) >= idleMs) break;
            await downstream.SendToAsync(reply.Buffer, SocketFlags.None, session.Client, token);
        }
    }
    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException) { }
    finally { session.Close(); }
}
sealed record L4Config(bool AllowNonLoopbackListeners, L4Listener[] Tcp, L4Listener[] Udp);
sealed record L4Listener(string Name, string ListenHost, int ListenPort, L4Backend[] Backends)
{
    public string BalancingPolicy { get; init; } = "RoundRobin";
    public int TcpMaxConnections { get; init; } = 1024;
    public int UdpMaxSessions { get; init; } = 1024;
    public int TcpIdleTimeoutSeconds { get; init; } = 300;
    public int UdpIdleTimeoutSeconds { get; init; } = 30;
    public int ProbeIntervalSeconds { get; init; } = 2;
    public string? UdpProbePayload { get; init; }
    public string? UdpProbeExpectedResponse { get; init; }
    public int UdpProbeIntervalSeconds { get; init; } = 2;
    public bool SendProxyProtocolV1 { get; init; }
}
sealed record L4Backend(string Host, int Port)
{
    public int Weight { get; init; } = 1;
    public bool DrainNewConnections { get; init; }
}
sealed class TcpTarget
{
    public TcpTarget(L4Backend backend) => Backend = backend;
    public L4Backend Backend { get; }
    public int ActiveConnections;
    public int Healthy = 1; // unknown until first probe; connect-time fallback still applies
}
sealed class UdpTarget
{
    public UdpTarget(L4Backend backend) => Backend = backend;
    public L4Backend Backend { get; }
    public int Healthy = 1;
}
sealed class UdpSession
{
    public UdpSession(UdpClient upstream, IPEndPoint client, long now) =>
        (Upstream, Client, LastSeenMs) = (upstream, client, now);
    public UdpClient Upstream { get; }
    public IPEndPoint Client { get; }
    public long LastSeenMs;
    private int closed;
    public bool IsClosed => Volatile.Read(ref closed) != 0;
    public void Close()
    {
        if (Interlocked.Exchange(ref closed, 1) == 0) Upstream.Dispose();
    }
}

sealed class L4SocketReservations : IDisposable
{
    public Dictionary<string,TcpListener> Tcp { get; } = new(StringComparer.Ordinal);
    public Dictionary<string,Socket> Udp { get; } = new(StringComparer.Ordinal);
    public void ReserveTcp(L4Listener cfg)
    {
        var socket = new TcpListener(IPAddress.Parse(cfg.ListenHost),cfg.ListenPort);
        try
        {
            if (OperatingSystem.IsWindows()) socket.ExclusiveAddressUse = true;
            socket.Start(256);
            Tcp.Add(cfg.Name,socket);
        }
        catch { socket.Stop(); throw; }
    }
    public void ReserveUdp(L4Listener cfg)
    {
        var socket = new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
        try
        {
            if (OperatingSystem.IsWindows()) socket.ExclusiveAddressUse = true;
            socket.Bind(new IPEndPoint(IPAddress.Parse(cfg.ListenHost),cfg.ListenPort));
            Udp.Add(cfg.Name,socket);
        }
        catch { socket.Dispose(); throw; }
    }
    public void Dispose()
    {
        foreach (var socket in Tcp.Values) socket.Stop();
        foreach (var socket in Udp.Values) socket.Dispose();
    }
}
