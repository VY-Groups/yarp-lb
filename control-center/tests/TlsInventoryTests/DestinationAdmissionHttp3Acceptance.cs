using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;

internal static class DestinationAdmissionHttp3Acceptance
{
    public static async Task RunAsync()
    {
        var supportsHttp3 = QuicConnection.IsSupported;
        if (!supportsHttp3)
            Console.WriteLine("SKIP: HTTP/3 admission requires MsQuic; running the real WebSocket lifecycle over HTTP/1.1 instead");
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("CI") != "true")
        {
            Console.WriteLine("SKIP: real GatewayCore process acceptance uses EC2 lab mode, restricted to disposable GitHub Actions runners");
            return;
        }

        static void Check(bool condition, string message)
        {
            if (!condition) throw new Exception("FAIL: " + message);
            Console.WriteLine("PASS: " + message);
        }

        var gatewayDll = new[]
        {
            Path.Combine(Directory.GetCurrentDirectory(), "bin", "Release", "net10.0", "GatewayCoreYarp.dll"),
            Path.Combine(Directory.GetCurrentDirectory(), "control-center", "bin", "Release", "net10.0", "GatewayCoreYarp.dll"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
                "../../../../../bin/Release/net10.0/GatewayCoreYarp.dll"))
        }.FirstOrDefault(File.Exists) ?? Path.Combine(Directory.GetCurrentDirectory(),
            "bin", "Release", "net10.0", "GatewayCoreYarp.dll");
        if (!File.Exists(gatewayDll))
            throw new FileNotFoundException("Build the shipping GatewayCoreYarp app before admission HTTP/3 acceptance", gatewayDll);

        var backendReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backendAttempts = new ConcurrentQueue<string>();
        var backendWebSocketAttempts = new ConcurrentQueue<string>();
        var backendWebSocketsInFlight = 0;
        var backendInFlight = 0;
        var backendPeak = 0;
        var backendBuilder = WebApplication.CreateBuilder();
        backendBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.Protocols = HttpProtocols.Http1));
        await using var backend = backendBuilder.Build();
        backend.UseWebSockets();
        backend.Map("/ws", async context =>
        {
            if (!context.WebSockets.IsWebSocketRequest)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            var id = context.Request.Query["id"].ToString();
            using var socket = await context.WebSockets.AcceptWebSocketAsync();
            backendWebSocketAttempts.Enqueue(id);
            Interlocked.Increment(ref backendWebSocketsInFlight);
            var buffer = new byte[256];
            try
            {
                while (true)
                {
                    var message = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), context.RequestAborted);
                    if (message.MessageType == WebSocketMessageType.Close)
                    {
                        await socket.CloseAsync(message.CloseStatus ?? WebSocketCloseStatus.NormalClosure,
                            message.CloseStatusDescription, CancellationToken.None);
                        break;
                    }
                    await socket.SendAsync(buffer.AsMemory(0, message.Count), message.MessageType,
                        message.EndOfMessage, context.RequestAborted);
                }
            }
            finally { Interlocked.Decrement(ref backendWebSocketsInFlight); }
        });
        backend.MapPost("/slow", async (HttpContext context) =>
        {
            var id = context.Request.Query["id"].ToString();
            backendAttempts.Enqueue(id);
            var current = Interlocked.Increment(ref backendInFlight);
            while (true)
            {
                var previous = Volatile.Read(ref backendPeak);
                if (previous >= current || Interlocked.CompareExchange(ref backendPeak, current, previous) == previous) break;
            }
            backendReady.TrySetResult();
            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(1500), context.RequestAborted);
                await context.Response.WriteAsync(id, context.RequestAborted);
            }
            finally { Interlocked.Decrement(ref backendInFlight); }
        });
        await backend.StartAsync();
        var backendAddress = backend.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        var root = Path.Combine(Path.GetTempPath(), "gatewaycore-admission-h3-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var rootCleanup = new TempDirectory(root);
        var privateDir = Path.Combine(root, "private");
        Directory.CreateDirectory(privateDir);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(privateDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        const string password = "acceptance-only-";
        using var trafficCert = CreateCertificate("localhost", ca: false, serverAndClient: false);
        using var managementCert = CreateCertificate("localhost", ca: true, serverAndClient: true);
        var trafficPfx = Path.Combine(root, "traffic.pfx");
        var trafficPassword = Path.Combine(root, "traffic-password.txt");
        var managementPfx = Path.Combine(root, "management.pfx");
        var managementPassword = Path.Combine(root, "management-password.txt");
        var caPem = Path.Combine(root, "client-ca.pem");
        WritePrivate(trafficPfx, trafficCert.Export(X509ContentType.Pfx, password));
        WritePrivate(trafficPassword, password);
        WritePrivate(managementPfx, managementCert.Export(X509ContentType.Pfx, password));
        WritePrivate(managementPassword, password);
        File.WriteAllText(caPem, managementCert.ExportCertificatePem());
        var managementClientKeyFlags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        using var managementClientCert = X509CertificateLoader.LoadPkcs12FromFile(
            managementPfx, password, managementClientKeyFlags);

        var tlsPort = GetDualTransportPort();
        var httpPort = GetTcpPort();
        var adminPort = GetTcpPort();
        var metricsPort = GetTcpPort();
        while (new[] { httpPort, adminPort, metricsPort, tlsPort }.Distinct().Count() != 4)
        {
            httpPort = GetTcpPort(); adminPort = GetTcpPort(); metricsPort = GetTcpPort();
        }

        var listenerConfig = Path.Combine(root, "listeners.json");
        var listeners = new
        {
            TrafficIp = "127.0.0.1", TrafficHttpPort = httpPort, TrafficHttpsPort = tlsPort,
            ManagementIp = "127.0.0.2", AdminPort = adminPort, MetricsPort = metricsPort,
            TrafficPfxPath = trafficPfx, TrafficPfxPasswordFile = trafficPassword,
            ManagementPfxPath = managementPfx, ManagementPfxPasswordFile = managementPassword,
            ClientCaPemPath = caPem, ClientThumbprints = new[] { managementCert.Thumbprint },
            AllowedAdminCidrs = new[] { "127.0.0.0/8" }, MaxConcurrentConnections = 64L,
            HttpVersion = supportsHttp3 ? "3" : "1.1"
        };
        WritePrivate(listenerConfig, JsonSerializer.Serialize(listeners));
        var appSettings = new
        {
            ReverseProxy = new
            {
                Routes = new Dictionary<string, object>
                {
                    ["admission"] = new { ClusterId = "admission", Match = new { Path = "/admit/{**catch-all}" },
                        Transforms = new[] { new { PathRemovePrefix = "/admit" } } }
                },
                Clusters = new Dictionary<string, object>
                {
                    ["admission"] = new
                    {
                        LoadBalancingPolicy = "RoundRobin",
                        Destinations = new Dictionary<string, object>
                        {
                            ["only"] = new { Address = backendAddress, Metadata = new Dictionary<string, string>
                            {
                                ["GatewayCore.Admission.MaxInFlight"] = "1",
                                ["GatewayCore.Admission.MaxPending"] = "1",
                                ["GatewayCore.Admission.QueueTimeoutMs"] = "5000"
                            } }
                        }
                    }
                }
            }
        };
        WritePrivate(Path.Combine(root, "appsettings.json"), JsonSerializer.Serialize(appSettings));

        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = root,
            UseShellExecute = false,
            RedirectStandardOutput = false,
            RedirectStandardError = false
        };
        start.ArgumentList.Add(gatewayDll);
        start.Environment["YARP_EC2_LAB_MODE"] = "1";
        start.Environment["YARP_EC2_LAB_PRIVATE_DIR"] = privateDir;
        start.Environment["YARP_LISTENERS_CONFIG_FILE"] = listenerConfig;
        start.Environment["ASPNETCORE_URLS"] = $"http://127.0.0.1:{httpPort}";
        start.Environment["BACKEND_A_HOST"] = "ec2-54-10-20-30.ap-south-1.compute.amazonaws.com";
        start.Environment["BACKEND_B_HOST"] = "ec2-52-20-30-40.ap-south-1.compute.amazonaws.com";
        // Keep listener diagnostics in the runner log. This acceptance exercises
        // the production certificate loader and isolated Kestrel endpoints; TLS
        // failures before HTTP dispatch otherwise surface only as client EOFs.
        start.Environment["Logging__LogLevel__Microsoft.AspNetCore.Server.Kestrel"] = "Debug";
        start.Environment["Logging__LogLevel__Microsoft.AspNetCore.Server.Kestrel.Https"] = "Trace";
        start.Environment["Logging__LogLevel__Microsoft.AspNetCore.Hosting.Diagnostics"] = "Debug";
        using var appProcess = Process.Start(start) ?? throw new Exception("Could not start real GatewayCore YARP process");
        var expectedStop = false;
        try
        {
            using var handler = new SocketsHttpHandler
            {
                UseProxy = false,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true
                },
                EnableMultipleHttp2Connections = true
            };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            using var managementHandler = new SocketsHttpHandler
            {
                UseProxy = false,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                    ClientCertificates = new X509CertificateCollection { managementClientCert }
                }
            };
            using var managementClient = new HttpClient(managementHandler) { Timeout = Timeout.InfiniteTimeSpan };
            var endpoint = new Uri($"https://127.0.0.1:{tlsPort}/admit/slow");
            using (var discoveryWarmup = new HttpRequestMessage(HttpMethod.Get,
                $"https://127.0.0.1:{tlsPort}/gateway/health")
            { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact })
            using (var discoveryTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(12)))
            using (var discoveryResponse = await client.SendAsync(discoveryWarmup, discoveryTimeout.Token))
            {
                Check(discoveryResponse.IsSuccessStatusCode && discoveryResponse.Version == HttpVersion.Version11,
                    "real GatewayCore HTTPS listener is ready over HTTP/1.1 before HTTP/3 admission traffic");
                if (supportsHttp3)
                    Check(discoveryResponse.Headers.TryGetValues("Alt-Svc", out var altSvc) &&
                        altSvc.Any(value => value.Contains("h3=", StringComparison.OrdinalIgnoreCase)),
                        "HTTP/1.1 readiness response advertises the listener's HTTP/3 endpoint");
            }

            if (supportsHttp3)
            {
                using (var readinessTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
                {
                    while (true)
                    {
                        if (appProcess.HasExited)
                            throw new Exception($"GatewayCore exited before readiness with code {appProcess.ExitCode}");
                        try
                        {
                            using var readiness = new HttpRequestMessage(HttpMethod.Get,
                                $"https://127.0.0.1:{tlsPort}/gateway/health")
                            { Version = HttpVersion.Version30, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                            using var response = await client.SendAsync(readiness, readinessTimeout.Token);
                            if (response.StatusCode == HttpStatusCode.OK) break;
                        }
                        catch (HttpRequestException) { }
                        await Task.Delay(100, readinessTimeout.Token);
                    }
                }
                await Task.Delay(500); // allow the initial applied-config admission reconciliation to complete

            async Task<HttpResponseMessage> Send(string id, CancellationToken cancellationToken = default)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint + "?id=" + Uri.EscapeDataString(id))
                {
                    Version = HttpVersion.Version30,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                    Content = new StringContent("non-idempotent-" + id)
                };
                request.Headers.TryAddWithoutValidation("X-Acceptance-Request", id);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(12));
                return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            }

            async Task WaitForAttempts(int count)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                while (backendAttempts.Count < count)
                    await Task.Delay(10, timeout.Token);
            }

            async Task WaitForServerCancellationAsync()
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var metricsEndpoint = new Uri($"https://127.0.0.2:{metricsPort}/gateway/metrics");
                while (true)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get, metricsEndpoint)
                    { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                    using var response = await managementClient.SendAsync(request, timeout.Token);
                    var body = await response.Content.ReadAsStringAsync(timeout.Token);
                    if (response.IsSuccessStatusCode && body.Split('\n').Any(line =>
                            line.StartsWith("yarp_control_destination_admission_waiter_canceled_total{", StringComparison.Ordinal) &&
                            line.TrimEnd().EndsWith(" 1", StringComparison.Ordinal)))
                        return;
                    await Task.Delay(25, timeout.Token);
                }
            }

            var firstTask = Send("active");
            await backendReady.Task.WaitAsync(TimeSpan.FromSeconds(12));
            var secondTask = Send("queued");
            await Task.Delay(150);
            Check(!secondTask.IsCompleted, "HTTP/3 second POST waits in the configured destination queue");
            using var overflow = await Send("overflow");
            Check(overflow.StatusCode == HttpStatusCode.ServiceUnavailable &&
                overflow.Headers.TryGetValues("X-GatewayCore-Rejection", out var rejection) &&
                rejection.Single() == "destination_queue_full",
                "HTTP/3 queue saturation returns a distinct local overload response");
            var first = await firstTask;
            using (first)
            {
                Check(first.IsSuccessStatusCode && first.Version == HttpVersion.Version30 &&
                    await first.Content.ReadAsStringAsync() == "active",
                    "HTTP/3 in-flight POST holds its destination permit through the upstream response");
            }
            using var second = await secondTask;
            Check(second.IsSuccessStatusCode && second.Version == HttpVersion.Version30 &&
                await second.Content.ReadAsStringAsync() == "queued",
                "HTTP/3 queued POST acquires the released destination slot and completes");
            var cancelActiveTask = Send("cancel-active");
            await WaitForAttempts(3);
            using var cancelWaiter = new CancellationTokenSource();
            var cancelWaiterTask = Send("cancel-waiter", cancelWaiter.Token);
            await Task.Delay(100);
            cancelWaiter.Cancel();
            var cancellationObserved = false;
            try { using var unexpected = await cancelWaiterTask; }
            catch (OperationCanceledException) { cancellationObserved = true; }
            Check(cancellationObserved, "HTTP/3 client cancellation terminates a queued POST");
            await WaitForServerCancellationAsync();
            var afterCancellationTask = Send("after-cancel");
            await Task.Delay(100);
            Check(!afterCancellationTask.IsCompleted,
                "canceling an HTTP/3 waiter frees the bounded queue while the active request retains its permit");
            using (var cancelActive = await cancelActiveTask)
                Check(cancelActive.IsSuccessStatusCode && await cancelActive.Content.ReadAsStringAsync() == "cancel-active",
                    "active HTTP/3 POST completes normally while a queued request is canceled");
            using var afterCancellation = await afterCancellationTask;
            Check(afterCancellation.IsSuccessStatusCode &&
                await afterCancellation.Content.ReadAsStringAsync() == "after-cancel",
                "a new HTTP/3 request uses queue capacity released by client cancellation");
            Check(backendPeak == 1 && backendInFlight == 0,
                $"real upstream concurrency never exceeds max-inflight=1; peak={backendPeak}, current={backendInFlight}");
            Check(backendAttempts.Order(StringComparer.Ordinal).SequenceEqual(
                    new[] { "active", "after-cancel", "cancel-active", "queued" }),
                "rejected and canceled non-idempotent HTTP/3 POSTs never reach or replay to an upstream backend");
            Console.WriteLine("PASS: real HTTP/3 request lifecycle exercised GatewayCore per-destination admission");
            }

            async Task<ClientWebSocket> ConnectWebSocket(string id)
            {
                var socket = new ClientWebSocket();
                socket.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;
                socket.Options.SetRequestHeader("X-Acceptance-Request", id);
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                try
                {
                    await socket.ConnectAsync(new Uri($"wss://127.0.0.1:{tlsPort}/admit/ws?id={Uri.EscapeDataString(id)}"), timeout.Token);
                    return socket;
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }

            using var activeWebSocket = await ConnectWebSocket("ws-active");
            using var queuedWebSocketTaskTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            var queuedWebSocketTask = ConnectWebSocket("ws-queued");
            await Task.Delay(150);
            Check(!queuedWebSocketTask.IsCompleted && backendWebSocketAttempts.Count == 1 &&
                Volatile.Read(ref backendWebSocketsInFlight) == 1,
                "an open WebSocket holds its destination slot while a second handshake queues");

            using var overflowRequest = new HttpRequestMessage(HttpMethod.Get,
                $"https://127.0.0.1:{tlsPort}/admit/ws?id=ws-overflow")
            { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            overflowRequest.Headers.TryAddWithoutValidation("Connection", "Upgrade");
            overflowRequest.Headers.TryAddWithoutValidation("Upgrade", "websocket");
            overflowRequest.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
            overflowRequest.Headers.TryAddWithoutValidation("Sec-WebSocket-Key", Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)));
            using var overflowTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var overflowResponse = await client.SendAsync(overflowRequest,
                HttpCompletionOption.ResponseHeadersRead, overflowTimeout.Token);
            Check(overflowResponse.StatusCode == HttpStatusCode.ServiceUnavailable &&
                overflowResponse.Headers.TryGetValues("X-GatewayCore-Rejection", out var wsRejection) &&
                wsRejection.Single() == "destination_queue_full",
                "WebSocket queue saturation returns local 503 without opening an upstream session");
            Check(backendWebSocketAttempts.Count == 1,
                "overloaded WebSocket handshake never reaches or replays to the backend");

            using (var activeCloseTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
                await activeWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "release admission slot", activeCloseTimeout.Token);
            using var queuedWebSocket = await queuedWebSocketTask.WaitAsync(queuedWebSocketTaskTimeout.Token);
            Check(queuedWebSocket.State == WebSocketState.Open && backendWebSocketAttempts.Count == 2,
                "closing the active WebSocket releases its permit and admits the queued handshake");
            var echo = System.Text.Encoding.UTF8.GetBytes("websocket-admitted");
            using (var echoTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
            {
                await queuedWebSocket.SendAsync(echo, WebSocketMessageType.Text, true, echoTimeout.Token);
                var echoed = new byte[64];
                var result = await queuedWebSocket.ReceiveAsync(new ArraySegment<byte>(echoed), echoTimeout.Token);
                Check(result.MessageType == WebSocketMessageType.Text &&
                    System.Text.Encoding.UTF8.GetString(echoed, 0, result.Count) == "websocket-admitted",
                    "admitted WebSocket keeps the permit for bidirectional streaming");
                await queuedWebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "complete", echoTimeout.Token);
            }
            Check(Volatile.Read(ref backendWebSocketsInFlight) == 0 &&
                backendWebSocketAttempts.Order(StringComparer.Ordinal).SequenceEqual(new[] { "ws-active", "ws-queued" }),
                "WebSocket drain releases all destination permits without admitting the overflow session");
            Console.WriteLine("PASS: real WebSocket session lifecycle exercised GatewayCore per-destination admission");
        }
        finally
        {
            if (!appProcess.HasExited)
            {
                expectedStop = true;
                appProcess.Kill(entireProcessTree: true);
                await appProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
            if (!expectedStop && appProcess.ExitCode != 0)
                throw new Exception($"GatewayCore process exited with code {appProcess.ExitCode}");
            await backend.StopAsync();
        }

        static X509Certificate2 CreateCertificate(string subject, bool ca, bool serverAndClient)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest($"CN={subject}", key, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, ca, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                ca ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature : X509KeyUsageFlags.DigitalSignature, true));
            var eku = new OidCollection();
            eku.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            if (serverAndClient) eku.Add(new Oid("1.3.6.1.5.5.7.3.2"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(2));
        }

        static int GetTcpPort()
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)socket.LocalEndPoint!).Port;
        }

        static int GetDualTransportPort() => TrafficHttp3Acceptance.SelectDualTransportPort(() =>
        {
            var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return (((IPEndPoint)udp.LocalEndPoint!).Port, udp);
        }, port =>
        {
            using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcp.Bind(new IPEndPoint(IPAddress.Loopback, port));
        });

    }

    private static void WritePrivate(string path, string value) =>
        WritePrivate(path, System.Text.Encoding.UTF8.GetBytes(value));

    private static void WritePrivate(string path, byte[] value)
    {
        File.WriteAllBytes(path, value);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private sealed class TempDirectory(string path) : IDisposable
    {
        public void Dispose()
        {
            try { Directory.Delete(path, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
