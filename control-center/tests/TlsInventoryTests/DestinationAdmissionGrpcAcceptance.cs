using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
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

internal static class DestinationAdmissionGrpcAcceptance
{
    public static async Task RunAsync()
    {
        await RunProtocolAsync(useHttp3: false);
        if (!QuicConnection.IsSupported)
        {
            if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true" &&
                Environment.GetEnvironmentVariable("GATEWAYCORE_REQUIRE_HTTP3_ACCEPTANCE") == "1")
                throw new InvalidOperationException("Required HTTP/3 gRPC acceptance cannot run without MsQuic");
            Console.WriteLine("SKIP: HTTP/3 gRPC acceptance requires a QUIC-capable runtime");
            return;
        }
        await RunProtocolAsync(useHttp3: true);
    }

    private static async Task RunProtocolAsync(bool useHttp3)
    {
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
            throw new FileNotFoundException("Build the shipping GatewayCoreYarp app before gRPC admission acceptance", gatewayDll);

        var version = useHttp3 ? HttpVersion.Version30 : HttpVersion.Version20;
        var protocol = useHttp3 ? "HTTP/3" : "HTTP/2";
        var versionSetting = useHttp3 ? "3" : "2";
        // An empty protobuf message is a valid five-byte gRPC frame.
        // Require the same negotiated protocol on both transport legs.
        byte[] frame = [0, 0, 0, 0, 0];
        var releaseActive = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseDrain = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backendAttempts = new ConcurrentQueue<string>();
        // Trust a unique disposable CA only in the CI account's root store.
        // Never disable shipping outbound certificate validation.
        Console.WriteLine($"START: {protocol} gRPC origin setup");
        using var originTrust = useHttp3 ? new OriginTrust() : null;
        Console.WriteLine($"START: {protocol} gRPC origin trust ready");
        var backendPort = useHttp3 ? GetDualTransportPort() : 0;
        var backendBuilder = WebApplication.CreateBuilder();
        backendBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, backendPort, listen =>
        {
            listen.Protocols = useHttp3 ? HttpProtocols.Http3 : HttpProtocols.Http2;
            if (originTrust is not null) listen.UseHttps(originTrust.ServerCertificate);
        }));
        await using var backend = backendBuilder.Build();
        backend.MapPost("/lab.Stream/Watch", async (HttpContext context) =>
        {
            Check(context.Request.Protocol == protocol &&
                context.Request.ContentType == "application/grpc", $"real {protocol} gRPC origin receives the request");
            var id = context.Request.Query["id"].ToString();
            backendAttempts.Enqueue(id);
            var received = new byte[5];
            await context.Request.Body.ReadExactlyAsync(received, context.RequestAborted);
            Check(received.SequenceEqual(frame), "origin receives an intact protobuf frame");
            context.Response.ContentType = "application/grpc";
            await context.Response.Body.WriteAsync(frame, context.RequestAborted);
            await context.Response.Body.FlushAsync(context.RequestAborted);
            if (id == "active")
                await releaseActive.Task.WaitAsync(TimeSpan.FromSeconds(30), context.RequestAborted);
            if (id == "drain-active")
                await releaseDrain.Task.WaitAsync(TimeSpan.FromSeconds(30), context.RequestAborted);
            await context.Response.Body.WriteAsync(frame, context.RequestAborted);
            context.Response.AppendTrailer("grpc-status", "0");
        });
        var chatAttempts = 0;
        // Two distinct, valid protobuf messages, each with field 1 (varint).
        byte[] chatFirst = [0, 0, 0, 0, 2, 8, 1];
        byte[] chatSecond = [0, 0, 0, 0, 2, 8, 2];
        backend.MapPost("/lab.Stream/Chat", async (HttpContext context) =>
        {
            Interlocked.Increment(ref chatAttempts);
            Check(context.Request.Protocol == protocol &&
                context.Request.ContentType == "application/grpc", $"real {protocol} duplex origin receives gRPC");
            context.Response.ContentType = "application/grpc";
            foreach (var expected in new[] { chatFirst, chatSecond })
            {
                var received = new byte[expected.Length];
                await context.Request.Body.ReadExactlyAsync(received, context.RequestAborted);
                Check(received.SequenceEqual(expected), "duplex origin reads expected protobuf message");
                await context.Response.Body.WriteAsync(received, context.RequestAborted);
                await context.Response.Body.FlushAsync(context.RequestAborted);
            }
            Check(await context.Request.Body.ReadAsync(new byte[1], context.RequestAborted) == 0,
                "duplex origin observes request half-close");
            context.Response.AppendTrailer("grpc-status", "0");
        });
        using (var startup = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
            await backend.StartAsync(startup.Token);
        Console.WriteLine($"START: {protocol} gRPC origin listening");
        var backendAddress = useHttp3 ? $"https://127.0.0.1:{backendPort}" :
            backend.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();

        // Separate real TLS/QUIC origins for active-health failover. Mixed
        // listener protocols permit an HTTP/1.1 probe without allowing
        // application POSTs to silently downgrade.
        var primaryHealthy = 1;
        var backupHealthy = 1;
        var primaryChecks = 0;
        var backupChecks = 0;
        var failoverPostAttempts = new ConcurrentQueue<string>();
        int primaryPort = 0, backupPort = 0;
        WebApplication MakeFailoverOrigin(string id, int port)
        {
            var builder = WebApplication.CreateBuilder();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, port, listen =>
            {
                listen.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                listen.UseHttps(originTrust!.ServerCertificate);
            }));
            var origin = builder.Build();
            origin.MapGet("/ready", () =>
            {
                if (id == "primary") Interlocked.Increment(ref primaryChecks);
                else Interlocked.Increment(ref backupChecks);
                var healthy = id == "primary" ? Volatile.Read(ref primaryHealthy) : Volatile.Read(ref backupHealthy);
                return Results.StatusCode(healthy == 1 ? 200 : 503);
            });
            origin.MapGet("/who", (HttpContext context) =>
                context.Request.Protocol == "HTTP/3" ? Results.Text(id) : Results.StatusCode(505));
            origin.MapPost("/work", async (HttpContext context) =>
            {
                Check(context.Request.Protocol == "HTTP/3", "failover origin receives exact HTTP/3 POST");
                var transaction = context.Request.Query["id"].ToString();
                failoverPostAttempts.Enqueue(id + ":" + transaction);
                var received = new byte[frame.Length];
                await context.Request.Body.ReadExactlyAsync(received, context.RequestAborted);
                Check(received.SequenceEqual(frame), "failover origin receives intact request frame");
                if (id == "primary" && transaction == "break-primary")
                {
                    Volatile.Write(ref primaryHealthy, 0);
                    context.Abort(); // abort after the non-idempotent request was received
                    return;
                }
                await context.Response.WriteAsync(id, context.RequestAborted);
            });
            return origin;
        }
        if (useHttp3)
        {
            primaryPort = GetDualTransportPort();
            while (primaryPort == backendPort) primaryPort = GetDualTransportPort();
            backupPort = GetDualTransportPort();
            while (backupPort == primaryPort || backupPort == backendPort) backupPort = GetDualTransportPort();
        }
        await using var primary = useHttp3 ? MakeFailoverOrigin("primary", primaryPort) : null;
        await using var backup = useHttp3 ? MakeFailoverOrigin("backup", backupPort) : null;
        using (var originStartup = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
        {
            if (primary is not null) await primary.StartAsync(originStartup.Token);
            if (backup is not null) await backup.StartAsync(originStartup.Token);
        }

        var root = Path.Combine(Path.GetTempPath(), "gatewaycore-admission-grpc-" + Guid.NewGuid().ToString("N"));
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

        var tlsPort = useHttp3 ? GetDualTransportPort() : GetTcpPort();
        while (useHttp3 && tlsPort == backendPort) tlsPort = GetDualTransportPort();
        var httpPort = GetTcpPort();
        var adminPort = GetTcpPort();
        var metricsPort = GetTcpPort();
        while (new[] { httpPort, adminPort, metricsPort, tlsPort }.Distinct().Count() != 4 ||
            (useHttp3 && new[] { httpPort, adminPort, metricsPort, tlsPort }.Contains(backendPort)))
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
            AllowedAdminCidrs = new[] { "127.0.0.0/8" }, MaxConcurrentConnections = 64L, HttpVersion = versionSetting
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
                        HttpRequest = new { Version = versionSetting, VersionPolicy = "RequestVersionExact" },
                        Destinations = new Dictionary<string, object>
                        {
                            ["only"] = new { Address = backendAddress, Metadata = new Dictionary<string, string>
                            {
                                ["GatewayCore.Admission.MaxInFlight"] = "1",
                                ["GatewayCore.Admission.MaxPending"] = "1",
                                ["GatewayCore.Admission.QueueTimeoutMs"] = "10000"
                            } }
                        }
                    }
                }
            }
        };
        if (useHttp3)
        {
            appSettings.ReverseProxy.Routes["failover"] = new { ClusterId = "failover",
                Match = new { Path = "/failover/{**catch-all}" },
                Transforms = new[] { new { PathRemovePrefix = "/failover" } } };
            appSettings.ReverseProxy.Clusters["failover"] = new
            {
                LoadBalancingPolicy = "PrimaryBackup",
                HttpRequest = new { Version = "3", VersionPolicy = "RequestVersionExact" },
                HealthCheck = new { Active = new { Enabled = true, Path = "/ready",
                    Interval = "00:00:01", Timeout = "00:00:01", Policy = "ConsecutiveFailures" } },
                Destinations = new Dictionary<string, object>
                {
                    ["primary"] = new { Address = $"https://127.0.0.1:{primaryPort}/",
                        Metadata = new Dictionary<string,string> { ["TrafficRole"] = "primary" } },
                    ["backup"] = new { Address = $"https://127.0.0.1:{backupPort}/",
                        Metadata = new Dictionary<string,string> { ["TrafficRole"] = "backup" } }
                }
            };
        }
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
                EnableMultipleHttp2Connections = false
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
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            var ct = deadline.Token;
            var endpoint = $"https://127.0.0.1:{tlsPort}/admit/lab.Stream/Watch";
            // Warm the TCP endpoint before exact QUIC requests, as in the existing H3 fixture.
            if (useHttp3)
            {
                while (true)
                {
                    if (appProcess.HasExited) throw new Exception($"GatewayCore exited before QUIC readiness: {appProcess.ExitCode}");
                    try
                    {
                        using var warmup = new HttpRequestMessage(HttpMethod.Get, $"https://127.0.0.1:{tlsPort}/gateway/health")
                        { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                        using var response = await client.SendAsync(warmup, ct);
                        if (response.IsSuccessStatusCode) break;
                    }
                    catch (HttpRequestException) { }
                    await Task.Delay(100, ct);
                }
            }
            while (true)
            {
                if (appProcess.HasExited)
                    throw new Exception($"GatewayCore exited before readiness: {appProcess.ExitCode}");
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get,
                        $"https://127.0.0.1:{tlsPort}/gateway/health")
                    { Version = version, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                    using var response = await client.SendAsync(request, ct);
                    if (response.IsSuccessStatusCode && response.Version == version) break;
                }
                catch (HttpRequestException) { }
                await Task.Delay(100, ct);
            }
            async Task<HttpResponseMessage> Send(string id)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint + "?id=" + id)
                {
                    Version = version,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                    Content = new ByteArrayContent(frame)
                };
                request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");
                request.Headers.TryAddWithoutValidation("TE", "trailers");
                return await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            }
            async Task WaitMetric(string name, int count)
            {
                var expected = $"yarp_control_destination_admission_{name}{{destination=\"admission/only\"}} {count}";
                while (true)
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get,
                        $"https://127.0.0.2:{metricsPort}/gateway/metrics")
                    { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                    using var response = await managementClient.SendAsync(request, ct);
                    var body = await response.Content.ReadAsStringAsync(ct);
                    if (response.IsSuccessStatusCode && body.Split('\n').Any(line =>
                        line.TrimEnd().Equals(expected, StringComparison.Ordinal))) return;
                    await Task.Delay(25, ct);
                }
            }
            async Task ReadFrame(Stream stream)
            {
                var received = new byte[5];
                await stream.ReadExactlyAsync(received, ct);
                Check(received.SequenceEqual(frame), "gateway forwards an intact streamed gRPC frame");
            }
            async Task Finish(HttpResponseMessage response, Stream stream)
            {
                await ReadFrame(stream);
                Check(await stream.ReadAsync(new byte[1], ct) == 0, "gRPC stream terminates after both frames");
                Check(response.TrailingHeaders.TryGetValues("grpc-status", out var status) &&
                    status.Single() == "0", "gRPC status trailer survives real YARP forwarding");
            }
            await WaitMetric("inflight_requests", 0);
            using var active = await Send("active");
            Check(active.IsSuccessStatusCode && active.Version == version &&
                active.Content.Headers.ContentType?.MediaType == "application/grpc",
                $"real gateway negotiates {protocol} and preserves gRPC content type");
            await using var activeStream = await active.Content.ReadAsStreamAsync(ct);
            await ReadFrame(activeStream);
            await WaitMetric("inflight_requests", 1);
            var queued = Send("queued");
            await WaitMetric("queued_requests", 1);
            Check(!queued.IsCompleted && backendAttempts.SequenceEqual(new[] { "active" }),
                "active gRPC response retains destination permit before trailers");
            using (var overflow = await Send("overflow"))
                Check(overflow.Version == version && overflow.StatusCode == HttpStatusCode.ServiceUnavailable &&
                    overflow.Headers.TryGetValues("X-GatewayCore-Rejection", out var rejection) &&
                    rejection.Single() == "destination_queue_full",
                    "concurrent gRPC overload fails locally rather than forwarding a non-idempotent POST");
            releaseActive.TrySetResult();
            await Finish(active, activeStream);
            using var next = await queued;
            Check(next.IsSuccessStatusCode && next.Version == version, "queued gRPC call receives released permit");
            await using var nextStream = await next.Content.ReadAsStreamAsync(ct);
            await ReadFrame(nextStream);
            await Finish(next, nextStream);
            await WaitMetric("inflight_requests", 0);
            await WaitMetric("queued_requests", 0);
            Check(backendAttempts.SequenceEqual(new[] { "active", "queued" }),
                "only accepted gRPC POSTs reach the real backend exactly once");
            Console.WriteLine($"PASS: real {protocol} gRPC framing, trailers, admission saturation and release");

            // Hold the upload open until the first echoed response is received.
            // A buffering or half-duplex proxy cannot satisfy this handshake.
            using var duplexDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var duplexToken = duplexDeadline.Token;
            using var duplexBody = new DuplexGrpcContent(chatFirst, chatSecond, duplexToken);
            using var duplexRequest = new HttpRequestMessage(HttpMethod.Post,
                $"https://127.0.0.1:{tlsPort}/admit/lab.Stream/Chat")
            {
                Version = version, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = duplexBody
            };
            duplexRequest.Headers.TryAddWithoutValidation("TE", "trailers");
            using var duplexResponse = await client.SendAsync(duplexRequest,
                HttpCompletionOption.ResponseHeadersRead, duplexToken);
            Check(duplexResponse.IsSuccessStatusCode && duplexResponse.Version == version,
                $"real {protocol} bidirectional gRPC headers arrive before upload completes");
            await using var duplexStream = await duplexResponse.Content.ReadAsStreamAsync(duplexToken);
            var firstEcho = new byte[chatFirst.Length];
            await duplexStream.ReadExactlyAsync(firstEcho, duplexToken);
            Check(firstEcho.SequenceEqual(chatFirst) && !duplexBody.UploadCompleted,
                "first echoed message arrives while client upload is still open");
            await WaitMetric("inflight_requests", 1);
            duplexBody.SendSecond();
            var secondEcho = new byte[chatSecond.Length];
            await duplexStream.ReadExactlyAsync(secondEcho, duplexToken);
            Check(secondEcho.SequenceEqual(chatSecond), "second duplex message arrives intact");
            Check(await duplexStream.ReadAsync(new byte[1], duplexToken) == 0 &&
                duplexResponse.TrailingHeaders.TryGetValues("grpc-status", out var duplexStatus) &&
                duplexStatus.Single() == "0", "duplex half-close preserves successful gRPC trailers");
            await WaitMetric("inflight_requests", 0);
            Check(chatAttempts == 1, "bidirectional gRPC POST reaches upstream exactly once");
            Console.WriteLine($"PASS: real {protocol} bidirectional gRPC streaming and half-close");

            if (useHttp3)
            {
                using var failoverDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
                var fc = failoverDeadline.Token;
                async Task<HttpResponseMessage> FailoverRequest(HttpMethod method, string path)
                {
                    using var request = new HttpRequestMessage(method, $"https://127.0.0.1:{tlsPort}/failover/{path}")
                    {
                        Version = HttpVersion.Version30, VersionPolicy = HttpVersionPolicy.RequestVersionExact
                    };
                    if (method == HttpMethod.Post) request.Content = new ByteArrayContent(frame);
                    return await client.SendAsync(request, fc);
                }
                async Task WaitForOrigin(string expected)
                {
                    // Only idempotent GETs observe route convergence.
                    while (true)
                    {
                        if (appProcess.HasExited) throw new Exception("Gateway exited during failover test");
                        try
                        {
                            using var response = await FailoverRequest(HttpMethod.Get, "who");
                            if (response.IsSuccessStatusCode && response.Version == HttpVersion.Version30 &&
                                await response.Content.ReadAsStringAsync(fc) == expected) return;
                        }
                        catch (HttpRequestException) { }
                        await Task.Delay(100, fc);
                    }
                }
                while (Volatile.Read(ref primaryChecks) == 0 || Volatile.Read(ref backupChecks) == 0)
                    await Task.Delay(100, fc);
                await WaitForOrigin("primary");
                try
                {
                    using var failed = await FailoverRequest(HttpMethod.Post, "work?id=break-primary");
                    Check(!failed.IsSuccessStatusCode, "aborted primary transaction is not reported successful");
                }
                catch (HttpRequestException) { Console.WriteLine("PASS: primary transaction fails at transport"); }
                Check(failoverPostAttempts.SequenceEqual(new[] { "primary:break-primary" }),
                    "failed non-idempotent HTTP/3 POST is not replayed to backup");
                await WaitForOrigin("backup");
                using (var recovered = await FailoverRequest(HttpMethod.Post, "work?id=fresh-backup"))
                    Check(recovered.IsSuccessStatusCode && recovered.Version == HttpVersion.Version30 &&
                        await recovered.Content.ReadAsStringAsync(fc) == "backup",
                        "new HTTP/3 POST reaches healthy backup after active health convergence");
                Volatile.Write(ref primaryHealthy, 1);
                await WaitForOrigin("primary");
                Check(failoverPostAttempts.SequenceEqual(new[] { "primary:break-primary", "backup:fresh-backup" }),
                    "failback does not replay any transaction");
                Console.WriteLine("PASS: real HTTP/3 upstream failure, backup selection and primary recovery without POST replay");
            }
            if (useHttp3 && OperatingSystem.IsLinux())
            {
                // Real OS SIGTERM, not Kill() or a fake shutdown endpoint.
                using var draining = await Send("drain-active");
                Check(draining.IsSuccessStatusCode && draining.Version == version,
                    "HTTP/3 active call starts before SIGTERM");
                await using var drainingStream = await draining.Content.ReadAsStreamAsync(ct);
                await ReadFrame(drainingStream);
                await WaitMetric("inflight_requests", 1);
                var drainQueued = Send("drain-queued");
                await WaitMetric("queued_requests", 1);
                using var signal = Process.Start(new ProcessStartInfo("kill")
                {
                    UseShellExecute = false,
                    ArgumentList = { "-TERM", appProcess.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) }
                }) ?? throw new Exception("Unable to send SIGTERM");
                await signal.WaitForExitAsync(ct);
                Check(signal.ExitCode == 0, "sent SIGTERM to shipping gateway");
                // The queued call must be refused, either by the gateway's
                // shutdown fence or QUIC shutdown. Never accept a successful POST.
                async Task AssertRefused(Task<HttpResponseMessage> task)
                {
                    try
                    {
                        using var response = await task.WaitAsync(TimeSpan.FromSeconds(8), ct);
                        Check(response.StatusCode == HttpStatusCode.ServiceUnavailable &&
                            response.Headers.TryGetValues("X-GatewayCore-Rejection", out var reason) &&
                            reason.Single() == "gateway_shutdown",
                            "shutdown refused pending/new work explicitly");
                    }
                    catch (HttpRequestException)
                    {
                        Console.WriteLine("PASS: shutdown refused pending/new QUIC work at transport");
                    }
                }
                await AssertRefused(drainQueued);
                await AssertRefused(Send("drain-new"));
                Check(!appProcess.HasExited, "gateway remains alive while accepted HTTP/3 response is held");
                releaseDrain.TrySetResult();
                await Finish(draining, drainingStream);
                await appProcess.WaitForExitAsync(ct);
                Check(appProcess.ExitCode == 0, "gateway exits cleanly after accepted stream completes");
                Check(backendAttempts.SequenceEqual(new[] { "active", "queued", "drain-active" }),
                    "queued and new shutdown POSTs are never forwarded or replayed");
                Console.WriteLine("PASS: real HTTP/3 graceful SIGTERM drain, accepted trailers, no new POSTs");
            }
            else if (useHttp3)
                Console.WriteLine("SKIP: POSIX SIGTERM graceful shutdown scenario is Linux-only");
        }
        finally
        {
            releaseActive.TrySetResult();
            releaseDrain.TrySetResult();
            if (!appProcess.HasExited)
            {
                expectedStop = true;
                appProcess.Kill(entireProcessTree: true);
                await appProcess.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            }
            if (!expectedStop && appProcess.ExitCode != 0)
                throw new Exception($"GatewayCore process exited with code {appProcess.ExitCode}");
            Console.WriteLine($"CLEANUP: {protocol} gRPC origin stopping");
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await backend.StopAsync(shutdown.Token);
            Console.WriteLine($"CLEANUP: {protocol} gRPC origin stopped");
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


    }

    private sealed class DuplexGrpcContent : HttpContent
    {
        private readonly byte[] first, second;
        private readonly CancellationToken deadline;
        private readonly TaskCompletionSource sendSecond = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int completed;
        public bool UploadCompleted => Volatile.Read(ref completed) == 1;

        public DuplexGrpcContent(byte[] first, byte[] second, CancellationToken deadline)
        {
            this.first = first;
            this.second = second;
            this.deadline = deadline;
            Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");
        }
        public void SendSecond() => sendSecond.TrySetResult();
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, deadline);
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context,
            CancellationToken cancellationToken)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(deadline, cancellationToken);
            await stream.WriteAsync(first, linked.Token);
            await stream.FlushAsync(linked.Token);
            await sendSecond.Task.WaitAsync(linked.Token);
            await stream.WriteAsync(second, linked.Token);
            await stream.FlushAsync(linked.Token);
            Volatile.Write(ref completed, 1);
        }
    }

    private static int GetDualTransportPort() => TrafficHttp3Acceptance.SelectDualTransportPort(() =>
    {
        var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (((IPEndPoint)udp.LocalEndPoint!).Port, udp);
    }, port =>
    {
        using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        tcp.Bind(new IPEndPoint(IPAddress.Loopback, port));
    });

    private sealed class OriginTrust : IDisposable
    {
        private readonly X509Certificate2 root;
        private readonly StoreLocation trustLocation;
        public X509Certificate2 ServerCertificate { get; }

        public OriginTrust()
        {
            // Adding to the Windows CurrentUser Root store can block on a
            // confirmation dialog in unattended CI. Only a disposable
            // GitHub-hosted Windows runner may use its machine trust store.
            if (OperatingSystem.IsWindows() &&
                Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
                throw new InvalidOperationException("Windows gRPC test trust requires a disposable GitHub-hosted runner");
            trustLocation = OperatingSystem.IsWindows() ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            using var caKey = RSA.Create(2048);
            var ca = new CertificateRequest("CN=GatewayCore CI gRPC " + Guid.NewGuid().ToString("N"),
                caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            ca.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            ca.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var issuer = ca.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
            root = X509CertificateLoader.LoadCertificate(issuer.Export(X509ContentType.Cert));
            using var leafKey = RSA.Create(2048);
            var leaf = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost"); san.AddIpAddress(IPAddress.Loopback);
            leaf.CertificateExtensions.Add(san.Build());
            leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            leaf.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            leaf.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            using var signed = leaf.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(1),
                RandomNumberGenerator.GetBytes(16));
            using var withKey = signed.CopyWithPrivateKey(leafKey);
            ServerCertificate = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null,
                OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
            try
            {
                using var store = new X509Store(StoreName.Root, trustLocation);
                store.Open(OpenFlags.ReadWrite);
                Console.WriteLine($"START: installing disposable gRPC CA in {trustLocation} Root");
                store.Add(root);
                Console.WriteLine("START: disposable gRPC CA installed");
            }
            catch { ServerCertificate.Dispose(); root.Dispose(); throw; }
        }

        public void Dispose()
        {
            try
            {
                using var store = new X509Store(StoreName.Root, trustLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Remove(root);
                Console.WriteLine("CLEANUP: disposable gRPC CA removed");
            }
            finally { ServerCertificate.Dispose(); root.Dispose(); }
        }
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
