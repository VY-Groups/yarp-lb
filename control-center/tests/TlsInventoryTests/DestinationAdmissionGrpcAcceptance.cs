using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
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

        // An empty protobuf message is a valid five-byte gRPC frame.
        // Exercise the actual HTTP/2 framing and trailers without adding a
        // NuGet dependency or substituting an ordinary HTTP/1 origin.
        byte[] frame = [0, 0, 0, 0, 0];
        var releaseActive = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backendAttempts = new ConcurrentQueue<string>();
        var backendBuilder = WebApplication.CreateBuilder();
        backendBuilder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            listen => listen.Protocols = HttpProtocols.Http2));
        await using var backend = backendBuilder.Build();
        backend.MapPost("/lab.Stream/Watch", async (HttpContext context) =>
        {
            Check(context.Request.Protocol == "HTTP/2" &&
                context.Request.ContentType == "application/grpc", "real HTTP/2 gRPC origin receives the request");
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
            await context.Response.Body.WriteAsync(frame, context.RequestAborted);
            context.Response.AppendTrailer("grpc-status", "0");
        });
        await backend.StartAsync();
        var backendAddress = backend.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();

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

        var tlsPort = GetTcpPort();
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
            AllowedAdminCidrs = new[] { "127.0.0.0/8" }, MaxConcurrentConnections = 64L, HttpVersion = "2"
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
                        HttpRequest = new { Version = "2", VersionPolicy = "RequestVersionExact" },
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
            while (true)
            {
                if (appProcess.HasExited)
                    throw new Exception($"GatewayCore exited before readiness: {appProcess.ExitCode}");
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Get,
                        $"https://127.0.0.1:{tlsPort}/gateway/health")
                    { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
                    using var response = await client.SendAsync(request, ct);
                    if (response.IsSuccessStatusCode && response.Version == HttpVersion.Version20) break;
                }
                catch (HttpRequestException) { }
                await Task.Delay(100, ct);
            }
            async Task<HttpResponseMessage> Send(string id)
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint + "?id=" + id)
                {
                    Version = HttpVersion.Version20,
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
            Check(active.IsSuccessStatusCode && active.Version == HttpVersion.Version20 &&
                active.Content.Headers.ContentType?.MediaType == "application/grpc",
                "real gateway negotiates HTTP/2 and preserves gRPC content type");
            await using var activeStream = await active.Content.ReadAsStreamAsync(ct);
            await ReadFrame(activeStream);
            await WaitMetric("inflight_requests", 1);
            var queued = Send("queued");
            await WaitMetric("queued_requests", 1);
            Check(!queued.IsCompleted && backendAttempts.SequenceEqual(new[] { "active" }),
                "active gRPC response retains destination permit before trailers");
            using (var overflow = await Send("overflow"))
                Check(overflow.StatusCode == HttpStatusCode.ServiceUnavailable &&
                    overflow.Headers.TryGetValues("X-GatewayCore-Rejection", out var rejection) &&
                    rejection.Single() == "destination_queue_full",
                    "concurrent gRPC overload fails locally rather than forwarding a non-idempotent POST");
            releaseActive.TrySetResult();
            await Finish(active, activeStream);
            using var next = await queued;
            Check(next.IsSuccessStatusCode && next.Version == HttpVersion.Version20, "queued gRPC call receives released permit");
            await using var nextStream = await next.Content.ReadAsStreamAsync(ct);
            await ReadFrame(nextStream);
            await Finish(next, nextStream);
            await WaitMetric("inflight_requests", 0);
            await WaitMetric("queued_requests", 0);
            Check(backendAttempts.SequenceEqual(new[] { "active", "queued" }),
                "only accepted gRPC POSTs reach the real backend exactly once");
            Console.WriteLine("PASS: real HTTP/2 gRPC framing, trailers, admission saturation and release");
        }
        finally
        {
            releaseActive.TrySetResult();
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
