using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Configuration;

internal static class ActiveCompoundHealthTests
{
    public static async Task RunAsync()
    {
        static void Check(bool ok, string name)
        {
            if (!ok) throw new Exception("Active compound health: " + name);
            Console.WriteLine("PASS: " + name);
        }
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddReverseProxy();
        CompoundProbingRequestFactory.Register(services);
        using var provider = services.BuildServiceProvider();
        Check(provider.GetRequiredService<IProbingRequestFactory>() is CompoundProbingRequestFactory, "native probe factory wrapped");
        var cluster = JsonNode.Parse("""
        {"Metadata":{"ADC.Health.CompoundMode":"AND","ADC.Health.SecondaryPath":"/other"},
         "HealthCheck":{"AvailableDestinationsPolicy":"HealthyAndUnknown","Active":{"Enabled":true,"Path":"/ready"}},
         "Destinations":{"d":{"Address":"http://127.0.0.1/"}}}
        """)!.AsObject();
        Check(ActiveCompoundSettings.ValidateDraft(cluster), "valid reviewed active configuration");
        cluster["HealthCheck"]!["AvailableDestinationsPolicy"] = "HealthyOrPanic";
        Check(!ActiveCompoundSettings.ValidateDraft(cluster), "panic fallback rejected");
        cluster["HealthCheck"]!["AvailableDestinationsPolicy"] = "HealthyAndUnknown";
        cluster["Destinations"]!["d"]!["Health"] = "http://other.invalid/";
        Check(!ActiveCompoundSettings.ValidateDraft(cluster), "alternate health origin rejected");
        using var evidenceClient = new HttpMessageInvoker(new OriginHandler());
        var generation = new ClusterModel(new ClusterConfig { ClusterId = "test" }, evidenceClient);
        var nextGeneration = new ClusterModel(new ClusterConfig { ClusterId = "test" }, evidenceClient);
        var destination = new DestinationModel(new DestinationConfig { Address = "http://127.0.0.1/" });
        var changedDestination = new DestinationModel(new DestinationConfig { Address = "http://127.0.0.1:81/" });
        Check(!CompoundReadinessEvidence.IsReady(generation, destination), "unknown evidence fails closed");
        var earlier = CompoundReadinessEvidence.Begin(generation, destination);
        var later = CompoundReadinessEvidence.Begin(generation, destination);
        later.Complete(false);
        earlier.Complete(true);
        Check(!CompoundReadinessEvidence.IsReady(generation, destination), "old success cannot override newer failure");
        CompoundReadinessEvidence.Begin(generation, destination).Complete(true);
        Check(CompoundReadinessEvidence.IsReady(generation, destination), "fresh successful evidence");
        Check(!CompoundReadinessEvidence.IsReady(nextGeneration, destination), "changed cluster generation invalidates evidence");
        Check(!CompoundReadinessEvidence.IsReady(generation, changedDestination), "changed destination generation invalidates evidence");
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var uri = new Uri("http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/ready");
            var handler = new OriginHandler();
            using var client = new HttpMessageInvoker(new CompoundProbeHandler(handler));
            async Task<HttpStatusCode> Probe(string mode)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Options.Set(ActiveCompoundSettings.ProbeKey, new(mode, "/other"));
                using var response = await client.SendAsync(request, CancellationToken.None);
                return response.StatusCode;
            }
            using (var ordinary = new HttpRequestMessage(HttpMethod.Post, uri))
            using (var response = await client.SendAsync(ordinary, CancellationToken.None))
                Check(response.StatusCode == HttpStatusCode.Accepted && handler.Count == 1, "ordinary POST forwarded once without compound evaluation");
            Check(await Probe("AND") == HttpStatusCode.ServiceUnavailable, "AND requires both HTTP checks");
            Check(await Probe("OR") == HttpStatusCode.OK, "OR requires at least one successful HTTP check and TCP");
            handler.PrimaryHealthy = false;
            Check(await Probe("OR") == HttpStatusCode.ServiceUnavailable, "TCP alone cannot satisfy OR");
            handler.PrimaryHealthy = true;
            handler.SecondaryHealthy = true;
            Check(await Probe("AND") == HttpStatusCode.OK, "AND success");
            listener.Stop();
            Check(await Probe("OR") == HttpStatusCode.ServiceUnavailable, "TCP failure always blocks readiness");
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            using var aborted = new HttpRequestMessage(HttpMethod.Get, uri);
            aborted.Options.Set(ActiveCompoundSettings.ProbeKey, new("OR", "/other"));
            try
            {
                using var response = await client.SendAsync(aborted, canceled.Token);
                throw new Exception("canceled probe returned a result");
            }
            catch (OperationCanceledException) { Check(true, "probe deadline cannot yield healthy result"); }
        }
        finally { listener.Stop(); }
    }

    private sealed class OriginHandler : HttpMessageHandler
    {
        private int count;
        public int Count => count;
        public bool PrimaryHealthy = true;
        public bool SecondaryHealthy;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Interlocked.Increment(ref count);
            token.ThrowIfCancellationRequested();
            var code = request.Method == HttpMethod.Post ? HttpStatusCode.Accepted :
                (request.RequestUri!.AbsolutePath == "/ready" ? PrimaryHealthy : SecondaryHealthy)
                ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable;
            return Task.FromResult(new HttpResponseMessage(code));
        }
    }
}
