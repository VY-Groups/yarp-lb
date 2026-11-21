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

    public static Task RunAsync() => RunCoreAsync(injectFailureDuringAudit: false, _ => { });

    public static async Task RunCleanupFailureAcceptanceAsync()
    {
        string? createdDirectory = null;
        try
        {
            await RunCoreAsync(injectFailureDuringAudit: true, path => createdDirectory = path);
            throw new Exception("FAIL: injected startup failure was not raised");
        }
        catch (InjectedRotationFailureException) { }

        if (createdDirectory is null || Directory.Exists(createdDirectory))
            throw new Exception("FAIL: temporary PKI directory survived injected startup failure");
        Console.WriteLine("PASS: injected audit-assertion failure killed both agents and removed temporary PKI");
        await VerifyProbeCancellationCompletesAsync();
    }

    private static async Task RunCoreAsync(bool injectFailureDuringAudit, Action<string> directoryCreated)
    {
        var dll = Path.Combine(Directory.GetCurrentDirectory(), "GatewayAgent", "bin",
            "Release", "net10.0", "GatewayCoreGatewayAgent.dll");
        if (!File.Exists(dll)) throw new FileNotFoundException("Build real agent first", dll);

        var root = Path.Combine(Path.GetTempPath(), "agent-fleet-rotation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        directoryCreated(root);
        var processes = new List<Process>();
        var stdoutTasks = new List<Task<string>>();
        var stderrTasks = new List<Task<string>>();
        var serverCertificates = new List<X509Certificate2>();
        var pfxPasswords = new List<string>();
        var expectedPinRevisions = Array.Empty<string>();
        // Audit final transitions only if the scenario actually reached them.
        // Otherwise a cleanup assertion masks the original rollback failure.
        var completedFullRotation = false;
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
            expectedPinRevisions = [
                PinSetRevision(LegacyPin(oldController)),
                PinSetRevision(LegacyPin(oldController), Sha256Pin(newController)),
                PinSetRevision(Sha256Pin(newController))
            ];
            Console.WriteLine("NOTICE: pin-set changes are recorded in local agent logs; this is not immutable centralized audit evidence.");
            var nodes = new List<Node>();
            for (var i = 0; i < 2; i++)
            {
                var nodeDirectory = Path.Combine(root, "node-" + (i + 1));
                Directory.CreateDirectory(nodeDirectory);
                var port = ReservePort();
                var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
                pfxPasswords.Add(password);
                var server = IssueServer(ca, "node-" + (i + 1));
                serverCertificates.Add(server);
                var serverPfx = Path.Combine(nodeDirectory, "https-listener.pfx");
                File.WriteAllBytes(serverPfx, server.Export(X509ContentType.Pfx, password));
                var configPath = Path.Combine(nodeDirectory, "appsettings.json");
                WritePins(configPath, caPemPath, [LegacyPin(oldController)]);

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
                LogRotationOutcome(node.Index, "initial", oldController, "accepted");
                await RequireStatus(node, newController, HttpStatusCode.Forbidden,
                    $"new controller is rejected before rotation on node {node.Index}");
                LogRotationOutcome(node.Index, "initial", newController, "denied");
            }

            // A deliberately incomplete fleet rollout must keep the established
            // old identity usable everywhere, then restore both nodes to the
            // captured last-known-good configuration within a bounded interval.
            var lastKnownGoodConfigs = nodes.ToDictionary(node => node.Index,
                node => File.ReadAllBytes(node.ConfigPath));
            var uninterruptedOldProbes = StartContinuousProbes(nodes, _ => oldController);
            try
            {
                WritePins(nodes[0].ConfigPath, caPemPath, [LegacyPin(oldController), Sha256Pin(newController)]);
                WritePins(nodes[1].ConfigPath, caPemPath, [LegacyPin(oldController), Sha256Pin(wrongController)]);
                await RequireEventually(nodes[0], newController, HttpStatusCode.OK,
                    "node 1 accepts candidate new identity during partial rollout");
                LogRotationOutcome(nodes[0].Index, "partial-rollout", newController, "accepted");
                // Prove the deliberately wrong pin was actually applied.
                // A forbidden response to the intended new controller alone
                // also matches the pre-rollout config and is not evidence that
                // the bad config ever became active on node 2.
                await RequireEventually(nodes[1], wrongController, HttpStatusCode.OK,
                    "node 2 applied the deliberately wrong controller pin before rollback");
                LogRotationOutcome(nodes[1].Index, "partial-rollout", wrongController, "accepted");
                await RequireStatus(nodes[1], newController, HttpStatusCode.Forbidden,
                    "node 2 rejects candidate identity after bad pin delivery");
                LogRotationOutcome(nodes[1].Index, "partial-rollout", newController, "denied");

                var rollbackStarted = Stopwatch.StartNew();
                foreach (var node in nodes)
                    WriteConfigAtomically(node.ConfigPath, lastKnownGoodConfigs[node.Index]);
                await RequireEventually(nodes[0], newController, HttpStatusCode.Forbidden,
                    "rollback removes candidate identity on node 1");
                LogRotationOutcome(nodes[0].Index, "rollback", newController, "denied");
                await RequireEventually(nodes[1], oldController, HttpStatusCode.OK,
                    "rollback preserves established identity on node 2");
                LogRotationOutcome(nodes[1].Index, "rollback", oldController, "accepted");
                await RequireStatus(nodes[0], oldController, HttpStatusCode.OK,
                    "rollback preserves established identity on node 1");
                LogRotationOutcome(nodes[0].Index, "rollback", oldController, "accepted");
                // Reading an authorized old pin does not establish that the
                // wrong candidate pin has disappeared: live IConfiguration
                // reload is asynchronous. Wait for actual denial, then retain
                // the existing strict elapsed-time rollback gate below.
                await RequireEventually(nodes[1], wrongController, HttpStatusCode.Forbidden,
                    "rollback removes incorrectly delivered pin from node 2");
                LogRotationOutcome(nodes[1].Index, "rollback", wrongController, "denied");
                await RequireStatus(nodes[0], newController, HttpStatusCode.Forbidden,
                    "rollback removes candidate pin from node 1");
                LogRotationOutcome(nodes[0].Index, "rollback", newController, "denied");
                await RequireStatus(nodes[1], newController, HttpStatusCode.Forbidden,
                    "rollback keeps candidate pin absent from node 2");
                LogRotationOutcome(nodes[1].Index, "rollback", newController, "denied");
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
                WritePins(node.ConfigPath, caPemPath, [LegacyPin(oldController), Sha256Pin(newController)]);
            foreach (var node in nodes)
                await RequireEventually(node, newController, HttpStatusCode.OK,
                    $"new controller is accepted on node {node.Index} before old pin retirement");
            foreach (var node in nodes)
                LogRotationOutcome(node.Index, "overlap", newController, "accepted");
            foreach (var node in nodes)
                await RequireStatus(node, oldController, HttpStatusCode.OK,
                    $"old controller remains accepted during overlap on node {node.Index}");
            foreach (var node in nodes)
                LogRotationOutcome(node.Index, "overlap", oldController, "accepted");

            var rotationProbes = StartContinuousProbes(nodes, _ => oldController);
            try
            {
                foreach (var node in nodes)
                {
                    // Move the live management probe to the already-authorized
                    // new identity before removing the old pin on this node.
                    await rotationProbes.SetCertificateAsync(node.Index, newController);
                    WritePins(node.ConfigPath, caPemPath, [Sha256Pin(newController)]);
                    await RequireEventually(node, newController, HttpStatusCode.OK,
                        $"new controller remains accepted after old pin retirement on node {node.Index}");
                    LogRotationOutcome(node.Index, "new-pin-active", newController, "accepted");
                    await RequireEventually(node, oldController, HttpStatusCode.Forbidden,
                        $"retired old controller is denied on node {node.Index}");
                    LogRotationOutcome(node.Index, "old-pin-retired", oldController, "denied");
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
            completedFullRotation = true;
        }
        finally
        {
            try
            {
                foreach (var process in processes)
                {
                    await StopProcessAsync(process);
                }
                var capturedAgentOutput = new System.Text.StringBuilder();
                var capturedOutputByNode = new List<string>();
                for (var i = 0; i < processes.Count; i++)
                {
                    var nodeOutput = new System.Text.StringBuilder();
                    try { nodeOutput.AppendLine(await stdoutTasks[i]); } catch (IOException) { }
                    try { nodeOutput.AppendLine(await stderrTasks[i]); } catch (IOException) { }
                    capturedOutputByNode.Add(nodeOutput.ToString());
                    capturedAgentOutput.AppendLine(nodeOutput.ToString());
                }
                var agentOutput = capturedAgentOutput.ToString();
                if (pfxPasswords.Any(password => agentOutput.Contains(password, StringComparison.Ordinal)) ||
                    agentOutput.Contains("PRIVATE KEY-----", StringComparison.Ordinal))
                    throw new Exception("FAIL: captured Gateway Agent output contains a PFX password or private-key marker");
                Console.WriteLine("PASS: captured Gateway Agent output contains no PFX password or private-key material");
                if (injectFailureDuringAudit) throw new InjectedRotationFailureException();
                if (!injectFailureDuringAudit && completedFullRotation)
                {
                    foreach (var (nodeOutput, index) in capturedOutputByNode.Select((output, index) => (output, index)))
                    {
                        var initialRevisionLoaded = nodeOutput.Contains(
                            $"Controller mTLS pin-set revision loaded: {expectedPinRevisions[0]}", StringComparison.Ordinal);
                        var overlapRevisionObserved = nodeOutput.Contains(
                            $"Controller mTLS pin-set revision changed: {expectedPinRevisions[0]} -> {expectedPinRevisions[1]}",
                            StringComparison.Ordinal);
                        var finalRevisionObserved = nodeOutput.Contains(
                            $"Controller mTLS pin-set revision changed: {expectedPinRevisions[1]} -> {expectedPinRevisions[2]}",
                            StringComparison.Ordinal);
                        if (!initialRevisionLoaded || !overlapRevisionObserved || !finalRevisionObserved)
                            throw new Exception($"FAIL: agent node {index + 1} did not log expected pin-set revision transitions (initial={initialRevisionLoaded}, overlap={overlapRevisionObserved}, final={finalRevisionObserved})");
                    }
                    Console.WriteLine("PASS: each agent logged SHA-256 pin-set revision changes for the overlap and final rotation states");
                }
            }
            finally
            {
                var cleanupErrors = new List<Exception>();
                foreach (var process in processes)
                {
                    try { await StopProcessAsync(process); }
                    catch (Exception error) { cleanupErrors.Add(error); }
                    try { process.Dispose(); }
                    catch (Exception error) { cleanupErrors.Add(error); }
                }
                foreach (var certificate in serverCertificates)
                {
                    try { certificate.Dispose(); }
                    catch (Exception error) { cleanupErrors.Add(error); }
                }
                // This cleanup executes even when process, log, or certificate
                // assertions fail; cleanup errors are reported after all items
                // and the directory have been handled.
                try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
                catch (Exception error) { cleanupErrors.Add(error); }
                if (Directory.Exists(root))
                    cleanupErrors.Add(new Exception("Temporary rotation PKI directory was not removed"));
                if (cleanupErrors.Count == 0)
                    Console.WriteLine("PASS: disposable rotation PKI and PFX files were removed");
                else
                    throw new AggregateException("Rotation acceptance cleanup failed", cleanupErrors);
            }
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

    private static async Task StopProcessAsync(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (Exception error) when (error is InvalidOperationException or System.ComponentModel.Win32Exception) { }

        try
        {
            if (!process.HasExited) await process.WaitForExitAsync();
        }
        catch (InvalidOperationException) { }
    }

    private static async Task VerifyProbeCancellationCompletesAsync()
    {
        var probe = new ContinuousProbe();
        await probe.probeGate.WaitAsync();
        probe.Completion = Task.Run(async () =>
        {
            if (await probe.TryAcquireProbeGateAsync()) probe.probeGate.Release();
        });
        probe.Cancel();
        probe.probeGate.Release();
        await probe.Completion;
        if (probe.Completion.IsFaulted)
            throw new Exception("FAIL: cancellation while waiting for the probe gate faulted completion");
        Console.WriteLine("PASS: cancellation while waiting for the probe gate completes without fault");
    }

    private sealed class InjectedRotationFailureException : Exception { }

    private static HttpClient CreateClient(Node node, X509Certificate2 controller)
    {
        var handler = new HttpClientHandler { UseProxy = false, ClientCertificateOptions = ClientCertificateOption.Manual };
        handler.ClientCertificates.Add(controller);
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
            certificate?.Thumbprint == node.ServerCertificate.Thumbprint;
        return new HttpClient(handler) { Timeout = RequestTimeout };
    }

    private static void LogRotationOutcome(int nodeIndex, string phase,
        X509Certificate2 certificate, string status)
    {
        var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
        Console.WriteLine($"ROTATION_TEST node={nodeIndex} phase={phase} sha256={fingerprint} status={status}");
    }

    private static string PinSetRevision(params string[] pins)
    {
        var canonical = string.Join("\n", pins.Select(pin =>
                pin.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)
                    ? pin.Replace(" ", "").ToUpperInvariant()
                    : "SHA1:" + pin.Replace(" ", "").Replace("SHA1:", "", StringComparison.OrdinalIgnoreCase)
                        .ToUpperInvariant())
            .OrderBy(pin => pin, StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));
    }

    private static string LegacyPin(X509Certificate2 certificate) => certificate.Thumbprint;

    private static string Sha256Pin(X509Certificate2 certificate) =>
        "SHA256:" + Convert.ToHexString(SHA256.HashData(certificate.RawData));

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
        foreach (var node in nodes) probe.InitializeCertificate(node.Index, certForNode(node));
        probe.Completion = Task.Run(async () =>
        {
            while (!probe.Cancellation.IsCancellationRequested)
            {
                foreach (var node in nodes)
                {
                    if (probe.Cancellation.IsCancellationRequested) break;
                    if (!await probe.TryAcquireProbeGateAsync()) return;
                    try
                    {
                        await RequireStatus(node, probe.CertificateFor(node), HttpStatusCode.OK, "continuous established identity");
                        Interlocked.Increment(ref probe.SuccessCount);
                    }
                    catch (Exception error)
                    {
                        lock (probe.Failures) probe.Failures.Add($"node {node.Index}: {error.Message}");
                    }
                    finally { probe.probeGate.Release(); }
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
        public readonly SemaphoreSlim probeGate = new(1, 1);
        public void InitializeCertificate(int nodeIndex, X509Certificate2 certificate) => certificates[nodeIndex] = certificate;
        public async Task SetCertificateAsync(int nodeIndex, X509Certificate2 certificate)
        {
            await probeGate.WaitAsync();
            try { certificates[nodeIndex] = certificate; }
            finally { probeGate.Release(); }
        }
        public async Task<bool> TryAcquireProbeGateAsync()
        {
            try
            {
                await probeGate.WaitAsync(Cancellation.Token);
                return true;
            }
            catch (OperationCanceledException) when (Cancellation.IsCancellationRequested)
            {
                return false;
            }
        }
        public X509Certificate2 CertificateFor(Node node) => certificates[node.Index];
        public void Cancel() => Cancellation.Cancel();
    }
}
