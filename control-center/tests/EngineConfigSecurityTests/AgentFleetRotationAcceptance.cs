using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

/// <summary>
/// Exercises overlapping mTLS controller-certificate rotation against two
/// independent real Gateway Agent processes. The test uses only loopback and
/// disposable keys; no private key is emitted as test output or an artifact.
/// </summary>
public static class AgentFleetRotationAcceptance
{
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan ConvergenceTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan RollbackTimeout = TimeSpan.FromSeconds(5);

    public static async Task RunAsync()
    {
        var dll = Path.Combine(Directory.GetCurrentDirectory(), "GatewayAgent", "bin",
            "Release", "net10.0", "GatewayCoreGatewayAgent.dll");
        if (!File.Exists(dll)) throw new FileNotFoundException("Build real agent first", dll);

        var root = Path.Combine(Path.GetTempPath(), "agent-fleet-rotation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var processes = new List<Process>();
        var stdoutTasks = new List<Task<string>>();
        var stderrTasks = new List<Task<string>>();
        var serverCertificates = new List<X509Certificate2>();
        try
        {
            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest("CN=ephemeral-fleet-rotation-ca", caKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
            var caPemPath = Path.Combine(root, "rotation-test-root.pem");
            File.WriteAllText(caPemPath, ca.ExportCertificatePem());

            using var oldController = Issue(ca, "old-controller");
            using var newController = Issue(ca, "new-controller");
            using var wrongController = Issue(ca, "wrong-controller");
            var nodes = new List<Node>();
            for (var i = 0; i < 2; i++)
            {
                var nodeDirectory = Path.Combine(root, "node-" + (i + 1));
                Directory.CreateDirectory(nodeDirectory);
                var port = ReservePort();
                var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
                var server = IssueServer(ca, "node-" + (i + 1));
                serverCertificates.Add(server);
                var serverPfx = Path.Combine(nodeDirectory, "https-listener.pfx");
                File.WriteAllBytes(serverPfx, server.Export(X509ContentType.Pfx, password));
                var configPath = Path.Combine(nodeDirectory, "appsettings.json");
                WritePins(configPath, caPemPath, [oldController.Thumbprint]);

                var start = new ProcessStartInfo("dotnet")
                {
                    WorkingDirectory = nodeDirectory,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                start.ArgumentList.Add(dll);
                start.Environment["Kestrel__Endpoints__AgentHttps__Url"] = "https://127.0.0.1:" + port;
                start.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Path"] = serverPfx;
                start.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Password"] = password;
                var process = Process.Start(start) ?? throw new InvalidOperationException("Agent process failed to start");
                processes.Add(process);
                stdoutTasks.Add(process.StandardOutput.ReadToEndAsync());
                stderrTasks.Add(process.StandardError.ReadToEndAsync());
                nodes.Add(new Node(i + 1, process, port, configPath, server));
            }

            foreach (var node in nodes)
                await WaitUntilReady(node, oldController, stdoutTasks[node.Index - 1], stderrTasks[node.Index - 1]);

            var originalPids = nodes.Select(node => node.Process.Id).ToArray();
            foreach (var node in nodes)
            {
                await RequireStatus(node, oldController, HttpStatusCode.OK,
                    $"old controller is initially authorized on node {node.Index}");
                await RequireStatus(node, newController, HttpStatusCode.Forbidden,
                    $"new controller is rejected before rotation on node {node.Index}");
            }

            // A deliberately incomplete fleet rollout must keep the established
            // old identity usable everywhere, then restore both nodes to the
            // captured last-known-good configuration within a bounded interval.
            var lastKnownGoodConfigs = nodes.ToDictionary(node => node.Index,
                node => File.ReadAllBytes(node.ConfigPath));
            var uninterruptedOldProbes = StartContinuousProbes(nodes, _ => oldController);
            try
            {
                WritePins(nodes[0].ConfigPath, caPemPath, [oldController.Thumbprint, newController.Thumbprint]);
                WritePins(nodes[1].ConfigPath, caPemPath, [oldController.Thumbprint, wrongController.Thumbprint]);
                await RequireEventually(nodes[0], newController, HttpStatusCode.OK,
                    "node 1 accepts candidate new identity during partial rollout");
                await RequireStatus(nodes[1], newController, HttpStatusCode.Forbidden,
                    "node 2 rejects candidate identity after bad pin delivery");

                var rollbackStarted = Stopwatch.StartNew();
                foreach (var node in nodes)
                    WriteConfigAtomically(node.ConfigPath, lastKnownGoodConfigs[node.Index]);
                await RequireEventually(nodes[0], newController, HttpStatusCode.Forbidden,
                    "rollback removes candidate identity on node 1");
                await RequireEventually(nodes[1], oldController, HttpStatusCode.OK,
                    "rollback preserves established identity on node 2");
                if (rollbackStarted.Elapsed > RollbackTimeout)
                    throw new Exception($"FAIL: fleet rollback exceeded {RollbackTimeout.TotalSeconds:0}s");
                Console.WriteLine("PASS: incomplete rollout detected and both nodes rolled back within 5 seconds");
            }
            finally
            {
                uninterruptedOldProbes.Cancel();
                await uninterruptedOldProbes.Completion;
            }
            if (uninterruptedOldProbes.Failures.Count != 0)
                throw new Exception("FAIL: established management identity had request failures during bounded rollback: " +
                    string.Join("; ", uninterruptedOldProbes.Failures.Take(5)));
            Console.WriteLine($"PASS: old identity had {uninterruptedOldProbes.Successes} uninterrupted management probes through failed rollout/rollback");

            // Successful fleet rollout: overlap remains active until both nodes
            // prove acceptance of the new cert; only then is the old pin retired.
            foreach (var node in nodes)
                WritePins(node.ConfigPath, caPemPath, [oldController.Thumbprint, newController.Thumbprint]);
            foreach (var node in nodes)
                await RequireEventually(node, newController, HttpStatusCode.OK,
                    $"new controller is accepted on node {node.Index} before old pin retirement");
            foreach (var node in nodes)
                await RequireStatus(node, oldController, HttpStatusCode.OK,
                    $"old controller remains accepted during overlap on node {node.Index}");

            var rotationProbes = StartContinuousProbes(nodes, _ => oldController);
            try
            {
                foreach (var node in nodes)
                {
                    // Move the live management probe to the already-authorized
                    // new identity before removing the old pin on this node.
                    rotationProbes.SetCertificate(node.Index, newController);
                    WritePins(node.ConfigPath, caPemPath, [newController.Thumbprint]);
                    await RequireEventually(node, newController, HttpStatusCode.OK,
                        $"new controller remains accepted after old pin retirement on node {node.Index}");
                    await RequireEventually(node, oldController, HttpStatusCode.Forbidden,
                        $"retired old controller is denied on node {node.Index}");
                }
            }
            finally
            {
                rotationProbes.Cancel();
                await rotationProbes.Completion;
            }
            if (rotationProbes.Failures.Count != 0)
                throw new Exception("FAIL: management probes failed during successful certificate rotation: " +
                    string.Join("; ", rotationProbes.Failures.Take(5)));
            Console.WriteLine($"PASS: new management identity had {rotationProbes.Successes} uninterrupted probes through successful fleet rotation");

            if (nodes.Where((node, index) => node.Process.HasExited || node.Process.Id != originalPids[index]).Any())
                throw new Exception("FAIL: Gateway Agent process restarted or exited during certificate rotation");
            Console.WriteLine("PASS: two independent real agent processes completed overlapping mTLS rotation without restart");
        }
        finally
        {
            foreach (var process in processes)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
                catch (InvalidOperationException) { }
                process.Dispose();
            }
            foreach (var task in stdoutTasks.Concat(stderrTasks))
            {
                try { _ = await task; } catch (IOException) { }
            }
            // Listener certificates hold only disposable test keys and stay
            // alive until all clients and child processes have stopped.
            foreach (var certificate in serverCertificates) certificate.Dispose();
            try { Directory.Delete(root, recursive: true); } catch (IOException) { }
        }
    }

    private static X509Certificate2 Issue(X509Certificate2 ca, string commonName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + commonName, key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-2),
            DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
        using var withKey = issued.CopyWithPrivateKey(key);
        var flags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.EphemeralKeySet;
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx, "ephemeral-test"),
            "ephemeral-test", flags);
    }

    private static X509Certificate2 IssueServer(X509Certificate2 ca, string commonName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + commonName, key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using var issued = request.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-2),
            DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
        return issued.CopyWithPrivateKey(key);
    }

    private static void WritePins(string path, string caPemPath, string[] pins)
    {
        var json = JsonSerializer.Serialize(new
        {
            Agent = new
            {
                TrustedClientThumbprints = pins,
                RevokedClientThumbprints = Array.Empty<string>(),
                LabOnlyClientCaCertificatePath = caPemPath,
                EnableConfigChanges = false,
                EnableEngineConfigChanges = false,
                EnableServiceActions = false
            }
        });
        WriteConfigAtomically(path, System.Text.Encoding.UTF8.GetBytes(json));
    }

    private static void WriteConfigAtomically(string path, byte[] contents)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllBytes(temporary, contents);
        File.Move(temporary, path, overwrite: true);
    }

    private static int ReservePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static HttpClient CreateClient(Node node, X509Certificate2 controller)
    {
        var handler = new HttpClientHandler { UseProxy = false, ClientCertificateOptions = ClientCertificateOption.Manual };
        handler.ClientCertificates.Add(controller);
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            certificate?.Thumbprint == node.ServerCertificate.Thumbprint;
        return new HttpClient(handler) { Timeout = RequestTimeout };
    }

    private static async Task WaitUntilReady(Node node, X509Certificate2 oldController,
        Task<string> stdout, Task<string> stderr)
    {
        var until = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(15);
        Exception? last = null;
        while (DateTimeOffset.UtcNow < until && !node.Process.HasExited)
        {
            try
            {
                await RequireStatus(node, oldController, HttpStatusCode.OK, "agent readiness");
                return;
            }
            catch (Exception error) { last = error; await Task.Delay(100); }
        }
        if (node.Process.HasExited)
        {
            var outText = await stdout;
            var errText = await stderr;
            throw new Exception("Agent exited before becoming ready (" + node.Process.ExitCode + "); stdout=" +
                outText[..Math.Min(2000, outText.Length)] + " stderr=" + errText[..Math.Min(5000, errText.Length)], last);
        }
        node.Process.Kill(entireProcessTree: true);
        await node.Process.WaitForExitAsync();
        var failedOut = await stdout;
        var failedErr = await stderr;
        throw new Exception("Agent did not become ready within 15 seconds; last probe: " + last +
            "; stdout=" + failedOut[..Math.Min(3000, failedOut.Length)] +
            "; stderr=" + failedErr[..Math.Min(5000, failedErr.Length)]);
    }

    private static async Task RequireStatus(Node node, X509Certificate2 clientCertificate,
        HttpStatusCode expected, string description)
    {
        using var client = CreateClient(node, clientCertificate);
        using var response = await client.GetAsync($"https://127.0.0.1:{node.Port}/agent/v1/status");
        if (response.StatusCode != expected)
            throw new Exception($"FAIL: {description}: expected {(int)expected}, got {(int)response.StatusCode}");
    }

    private static async Task RequireEventually(Node node, X509Certificate2 cert,
        HttpStatusCode expected, string description)
    {
        var until = DateTimeOffset.UtcNow + ConvergenceTimeout;
        Exception? last = null;
        while (DateTimeOffset.UtcNow < until)
        {
            try
            {
                await RequireStatus(node, cert, expected, description);
                Console.WriteLine("PASS: " + description);
                return;
            }
            catch (Exception error) { last = error; await Task.Delay(100); }
        }
        throw new Exception("FAIL: timed out waiting for " + description, last);
    }

    private static ContinuousProbe StartContinuousProbes(List<Node> nodes,
        Func<Node, X509Certificate2> certForNode)
    {
        var probe = new ContinuousProbe();
        foreach (var node in nodes) probe.SetCertificate(node.Index, certForNode(node));
        probe.Completion = Task.Run(async () =>
        {
            while (!probe.Cancellation.IsCancellationRequested)
            {
                foreach (var node in nodes)
                {
                    if (probe.Cancellation.IsCancellationRequested) break;
                    try
                    {
                        await RequireStatus(node, probe.CertificateFor(node), HttpStatusCode.OK, "continuous established identity");
                        Interlocked.Increment(ref probe.SuccessCount);
                    }
                    catch (Exception error)
                    {
                        lock (probe.Failures) probe.Failures.Add($"node {node.Index}: {error.Message}");
                    }
                }
                try { await Task.Delay(50, probe.Cancellation.Token); }
                catch (OperationCanceledException) when (probe.Cancellation.IsCancellationRequested) { }
            }
        });
        return probe;
    }

    private sealed record Node(int Index, Process Process, int Port, string ConfigPath, X509Certificate2 ServerCertificate);

    private sealed class ContinuousProbe
    {
        public CancellationTokenSource Cancellation { get; } = new();
        public Task Completion { get; set; } = Task.CompletedTask;
        public List<string> Failures { get; } = [];
        public int SuccessCount;
        public int Successes => Volatile.Read(ref SuccessCount);
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, X509Certificate2> certificates = new();
        public void SetCertificate(int nodeIndex, X509Certificate2 certificate) => certificates[nodeIndex] = certificate;
        public X509Certificate2 CertificateFor(Node node) => certificates[node.Index];
        public void Cancel() => Cancellation.Cancel();
    }
}
