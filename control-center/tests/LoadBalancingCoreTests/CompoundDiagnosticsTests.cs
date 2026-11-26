using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;

internal static class CompoundDiagnosticsTests
{
    public static async Task RunAsync()
    {
        static void Check(bool ok, string name)
        {
            if (!ok) throw new Exception("Compound diagnostic failed: " + name);
            Console.WriteLine("PASS: compound diagnostic " + name);
        }
        var cluster = JsonNode.Parse("""
        {"HealthCheck":{"Active":{"Path":"/ready"}},"Metadata":{"ADC.Diagnostics.CompoundMode":"AND","ADC.Diagnostics.SecondaryPath":"/other"}}
        """)!.AsObject();
        Check(CompoundProbeSettings.TryRead(cluster, out var settings) && settings is not null, "valid configuration");
        foreach (var bad in new[] { "//other.invalid/", "/\\other.invalid/", "http://other.invalid/", "/ready", "/x#fragment" })
        {
            cluster["Metadata"]![CompoundProbeSettings.SecondaryPathKey] = bad;
            Check(!CompoundProbeSettings.TryRead(cluster, out _), "reject unsafe or duplicate path");
        }
        cluster["Metadata"]![CompoundProbeSettings.SecondaryPathKey] = "/other";
        cluster["Metadata"]![CompoundProbeSettings.ModeKey] = "invalid";
        Check(!CompoundProbeSettings.TryRead(cluster, out _), "reject mode");
        cluster["Metadata"]![CompoundProbeSettings.ModeKey] = "AND";
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var origin = new Uri("http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/");
            using var client = new HttpClient(new TestHandler(origin));
            Check(!CompoundProbeSettings.TryTarget(origin, "//other.invalid/", out _), "same-origin guard");
            var and = await CompoundDiagnostics.EvaluateAsync(client, origin, "/ready", new("AND", "/other"), CancellationToken.None);
            Check(!and.Passed && and.Checks.Count == 3 && and.Checks[0].Passed &&
                and.Checks[1].Passed && !and.Checks[2].Passed && and.Checks[2].HttpStatus == 503, "AND rejects failed check");
            var or = await CompoundDiagnostics.EvaluateAsync(client, origin, "/ready", new("OR", "/other"), CancellationToken.None);
            Check(or.Passed, "OR allows at least one passing check");
            var all = await CompoundDiagnostics.EvaluateAsync(client, origin, "/ready", new("AND", null), CancellationToken.None);
            Check(all.Passed && all.Checks.Count == 2, "AND succeeds on TCP and HTTP");
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            try
            {
                await CompoundDiagnostics.EvaluateAsync(client, origin, "/ready", new("AND", null), canceled.Token);
                throw new Exception("Expected cancellation");
            }
            catch (OperationCanceledException) { Check(true, "request cancellation propagated"); }
        }
        finally { listener.Stop(); }
    }

    private sealed class TestHandler(Uri origin) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var uri = request.RequestUri!;
            if (uri.Scheme != origin.Scheme || uri.Host != origin.Host || uri.Port != origin.Port)
                throw new Exception("Unexpected diagnostic target");
            return Task.FromResult(new HttpResponseMessage(uri.AbsolutePath == "/ready" ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable));
        }
    }
}
