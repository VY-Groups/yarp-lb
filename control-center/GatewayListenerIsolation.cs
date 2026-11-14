using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Hosting;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Health;

/// <summary>Opt-in v0.1 independent data, admin and metrics sockets. Unconfigured legacy
/// loopback mode remains available for existing CI and migration only.</summary>
public sealed class GatewayListenerIsolation
{
    public sealed record Settings(
        string TrafficIp,
        int TrafficHttpPort,
        int TrafficHttpsPort,
        string ManagementIp,
        int AdminPort,
        int MetricsPort,
        string TrafficPfxPath,
        string TrafficPfxPasswordFile,
        string ManagementPfxPath,
        string ManagementPfxPasswordFile,
        string ClientCaPemPath,
        string[] ClientThumbprints,
        string[] AllowedAdminCidrs,
        long MaxConcurrentConnections,
        string HttpVersion);

    public readonly Settings Config;
    private readonly IPAddress _traffic, _management;
    private readonly IPNetwork[] _allowed;
    private readonly HashSet<string> _pins;
    private readonly X509Certificate2 _trafficCertificate, _managementCertificate, _clientCa;

    private GatewayListenerIsolation(Settings config)
    {
        Config = config;
        _traffic = ParseBoundIp(config.TrafficIp, "traffic");
        _management = ParseBoundIp(config.ManagementIp, "admin/metrics");
        if (_traffic.Equals(_management))
            throw new InvalidOperationException("Traffic and management IPs must differ for socket-level isolation");
        var ports = new[] {config.TrafficHttpPort, config.TrafficHttpsPort, config.AdminPort, config.MetricsPort};
        if (ports.Any(p => p is < 1 or > 65535) || ports.Distinct().Count() != ports.Length)
            throw new InvalidOperationException("Four listener ports must be unique and between 1 and 65535");
        if (config.MaxConcurrentConnections <= 0)
            throw new InvalidOperationException("REQUIRED_INPUT MaxConcurrentConnections must be derived from measured peak");
        if (config.HttpVersion is not ("1.1" or "2"))
            throw new InvalidOperationException("HttpVersion must be 1.1 or 2 and match the baseline ALPN");
        if (config.ClientThumbprints is null || config.ClientThumbprints.Length == 0)
            throw new InvalidOperationException("At least one pinned management client certificate is required");
        _pins = new HashSet<string>(config.ClientThumbprints.Select(NormalizeThumbprint), StringComparer.Ordinal);
        if (_pins.Any(x => x.Length != 40 || x.Any(c => !Uri.IsHexDigit(c))))
            throw new InvalidOperationException("Invalid pinned management client certificate SHA1 thumbprint");
        if (config.AllowedAdminCidrs is null || config.AllowedAdminCidrs.Length == 0)
            throw new InvalidOperationException("A nonempty management IP allowlist is required");
        _allowed = config.AllowedAdminCidrs.Select(s =>
            IPNetwork.TryParse(s, out var network) ? network :
            throw new InvalidOperationException("Invalid management CIDR: " + s)).ToArray();
        _trafficCertificate = LoadPfx(config.TrafficPfxPath, config.TrafficPfxPasswordFile);
        _managementCertificate = LoadPfx(config.ManagementPfxPath, config.ManagementPfxPasswordFile);
        CheckRegular(config.ClientCaPemPath, false);
        _clientCa = X509Certificate2.CreateFromPemFile(config.ClientCaPemPath);
        if (!_clientCa.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority))
            throw new InvalidOperationException("Management client trust anchor must be a CA certificate");
    }

    private static string NormalizeThumbprint(string value) => value.Replace(":", "", StringComparison.Ordinal)
        .Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
    private static IPAddress ParseBoundIp(string input, string role)
    {
        if (!IPAddress.TryParse(input, out var ip) ||
            ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) ||
            ip.IsIPv6Multicast || ip.IsIPv6LinkLocal)
            throw new InvalidOperationException(role + " listener may not bind wildcard/invalid IP");
        return ip;
    }
    private static void CheckRegular(string path, bool privateSecret)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            !File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Missing, symlinked, or relative listener certificate/secret file");
        if (privateSecret && OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(path);
            if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                          UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0 ||
                (mode & (UnixFileMode.UserRead | UnixFileMode.UserWrite)) !=
                (UnixFileMode.UserRead | UnixFileMode.UserWrite))
                throw new InvalidOperationException("Listener PFX/password must be mode 0600");
        }
    }
    private static X509Certificate2 LoadPfx(string file, string passFile)
    {
        CheckRegular(file, true);
        CheckRegular(passFile, true);
        var password = File.ReadAllText(passFile).TrimEnd('\r','\n');
        if (password.Length == 0)
            throw new InvalidOperationException("Listener PFX password cannot be empty");
        var cert = X509CertificateLoader.LoadPkcs12FromFile(file, password, X509KeyStorageFlags.EphemeralKeySet);
        if (!cert.HasPrivateKey || cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(1))
        {
            cert.Dispose();
            throw new InvalidOperationException("Listener certificate must have private key and >1 day validity");
        }
        return cert;
    }

    public static GatewayListenerIsolation? FromEnvironment()
    {
        var path = Environment.GetEnvironmentVariable("YARP_LISTENERS_CONFIG_FILE");
        if (string.IsNullOrEmpty(path)) return null;  // existing test-only legacy bootstrap
        CheckRegular(path, false);
        var opts = new JsonSerializerOptions(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
        var config = JsonSerializer.Deserialize<Settings>(File.ReadAllText(path), opts)
                     ?? throw new InvalidOperationException("Missing listener config");
        return new GatewayListenerIsolation(config);
    }

    private bool ClientAllowed(X509Certificate2? certificate)
    {
        if (certificate is null || !_pins.Contains(NormalizeThumbprint(certificate.Thumbprint)) ||
            certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() < DateTime.UtcNow)
            return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_clientCa);
        // Pinned leaf + private trusted CA. Revocation/CRL endpoints must be
        // separately validated during production PKI acceptance; do not treat CI as proof.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    }

    public void Configure(IWebHostBuilder web)
    {
        web.ConfigureKestrel(options =>
        {
            options.Limits.MaxConcurrentConnections = Config.MaxConcurrentConnections;
            options.Listen(_traffic, Config.TrafficHttpPort, listen => listen.Protocols = HttpProtocols.Http1);
            options.Listen(_traffic, Config.TrafficHttpsPort, listen =>
            {
                listen.Protocols = Config.HttpVersion == "2" ? HttpProtocols.Http2 : HttpProtocols.Http1;
                listen.UseHttps(_trafficCertificate);
            });
            void ConfigureManagement(ListenOptions listen)
            {
                listen.Protocols = HttpProtocols.Http1;
                listen.UseHttps(new HttpsConnectionAdapterOptions {
                    ServerCertificate = _managementCertificate,
                    ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                    ClientCertificateValidation = (cert, _, _) => ClientAllowed(cert)
                });
            }
            options.Listen(_management, Config.AdminPort, ConfigureManagement);
            options.Listen(_management, Config.MetricsPort, ConfigureManagement);
        });
    }

    private bool OnSocket(HttpContext ctx, IPAddress local, int port) =>
        ctx.Connection.LocalIpAddress?.Equals(local) == true && ctx.Connection.LocalPort == port;
    public bool OnData(HttpContext ctx) => OnSocket(ctx, _traffic, Config.TrafficHttpPort) ||
                                            OnSocket(ctx, _traffic, Config.TrafficHttpsPort);
    private bool HasApprovedClient(HttpContext ctx)
    {
        var remote = ctx.Connection.RemoteIpAddress;
        var cert = ctx.Connection.ClientCertificate;
        return remote is not null && _allowed.Any(n => n.Contains(remote)) && ClientAllowed(cert);
    }
    public bool OnAdmin(HttpContext ctx) => OnSocket(ctx, _management, Config.AdminPort) && HasApprovedClient(ctx);
    public bool OnMetrics(HttpContext ctx) => OnSocket(ctx, _management, Config.MetricsPort) && HasApprovedClient(ctx);

    public bool Permit(HttpContext ctx)
    {
        var path = ctx.Request.Path;
        if (path.StartsWithSegments("/admin") || path.StartsWithSegments("/dashboard") || path == "/")
            return OnAdmin(ctx);
        if (path == "/gateway/metrics") return OnMetrics(ctx);
        if (path == "/gateway/health/ready") return OnData(ctx);
        // Management port never forwards arbitrary user traffic, and data port
        // cannot reach administration or metrics even if middleware order changes.
        return OnData(ctx);
    }

    public static bool AnyDestinationHealthy(IProxyStateLookup proxy) =>
        proxy.GetClusters().Any(cluster =>
            cluster.Destinations.Values.Any(d => d.Health.Active == DestinationHealth.Healthy));
}
