using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.LoadBalancing;

var builder = WebApplication.CreateBuilder(args);
// Ephemeral loopback-only TLS identity. Never deploy this certificate for real clients.
using var tlsKey = RSA.Create(2048);
var certRequest = new CertificateRequest(new X500DistinguishedName("CN=localhost"),
    tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName("localhost");
san.AddIpAddress(IPAddress.Loopback);
certRequest.CertificateExtensions.Add(san.Build());
using var loopbackCert = certRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-10), DateTimeOffset.UtcNow.AddHours(6));
var httpPort = int.TryParse(Environment.GetEnvironmentVariable("YARP_LAB_HTTP_PORT"), out var h) ? h : 18080;
var tlsPort = int.TryParse(Environment.GetEnvironmentVariable("YARP_LAB_TLS_PORT"), out var t) ? t : 18443;
if (httpPort is < 1025 or > 65535 || tlsPort is < 1025 or > 65535 || httpPort == tlsPort)
    throw new ArgumentException("Lab listener ports invalid.");
builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenLocalhost(httpPort);
    k.ListenLocalhost(tlsPort, listen => listen.UseHttps(loopbackCert));
});

var configPath = Environment.GetEnvironmentVariable("YARP_LAB_CONFIG_FILE")
    ?? Path.Combine(AppContext.BaseDirectory, "lab.json");
builder.Configuration.AddJsonFile(configPath, optional: false, reloadOnChange: true);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>();

var app = builder.Build();
app.MapGet("/lab/ping", () => Results.Ok(new { lab = true }));
app.MapGet("/lab/stats", () => Results.Ok(new
{
    processWorkingSetBytes = Environment.WorkingSet,
    gcManagedHeapBytes = GC.GetTotalMemory(false),
    gc0Collections = GC.CollectionCount(0),
    gc1Collections = GC.CollectionCount(1),
    gc2Collections = GC.CollectionCount(2),
    timeUtc = DateTimeOffset.UtcNow
}));
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (ctx, next) =>
    {
        var proxy = ctx.GetReverseProxyFeature();
        TrafficLifecycle.Observe(proxy.AllDestinations, proxy.AvailableDestinations);
        if (proxy.AvailableDestinations.Any(TrafficLifecycle.IsDraining))
            proxy.AvailableDestinations = proxy.AvailableDestinations
                .Where(d => !TrafficLifecycle.IsDraining(d)).ToArray();
        await next();
    });
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
    proxyPipeline.UsePassiveHealthChecks();
});
app.Run();
