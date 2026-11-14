using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

/// <summary>
/// Opt-in on-prem v1 endpoint isolation. No wildcard management/metrics binds,
/// no Host/X-Forwarded-For trust, TLS client certificate pin + OS chain validation.
/// Legacy mode remains available only for existing v0.1 CI compatibility.
/// Production service templates REQUIRE YARP_LISTENER_PROFILE=split-v1.
/// </summary>
internal sealed class ListenerIsolation
{
    private readonly HashSet<IPAddress> _allowlist;
    private readonly HashSet<string> _trustedClientPins;
    private readonly X509Certificate2? _trafficCert;
    private readonly X509Certificate2? _managementCert;
    public bool Enabled { get; }
    public IPAddress TrafficIp { get; }
    public IPAddress DataIp { get; }
    public IPAddress ManagementIp { get; }
    public int TrafficHttpPort { get; }
    public int TrafficHttpsPort { get; }
    public int ReadinessPort { get; }
    public int AdminPort { get; }
    public int MetricsPort { get; }
    private ListenerIsolation()
    {
        Enabled = false;
        TrafficIp = IPAddress.Loopback;
        DataIp = IPAddress.Loopback;
        ManagementIp = IPAddress.Loopback;
        _allowlist = new();
        _trustedClientPins = new(StringComparer.OrdinalIgnoreCase);
    }
    private ListenerIsolation(
        IPAddress traffic, IPAddress data, IPAddress management,
        int httpPort, int httpsPort, int readinessPort, int adminPort, int metricsPort,
        HashSet<IPAddress> allowlist, HashSet<string> pins,
        X509Certificate2 trafficCert, X509Certificate2 managementCert)
    {
        Enabled = true;
        TrafficIp = traffic; DataIp = data; ManagementIp = management;
        TrafficHttpPort = httpPort; TrafficHttpsPort = httpsPort;
        ReadinessPort = readinessPort; AdminPort = adminPort; MetricsPort = metricsPort;
        _allowlist = allowlist; _trustedClientPins = pins;
        _trafficCert = trafficCert; _managementCert = managementCert;
    }
    private static string Required(string name)
    {
        var value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException("Listener config REQUIRED: " + name);
        return value.Trim();
    }
    private static IPAddress RequiredAddress(string name)
    {
        var text = Required(name);
        if (!IPAddress.TryParse(text, out var ip) || IPAddress.Any.Equals(ip) ||
            IPAddress.IPv6Any.Equals(ip) || IPAddress.IPv6None.Equals(ip) ||
            ip.IsIPv4MappedToIPv6)
            throw new InvalidOperationException("INVALID_LISTENER_IP: " + name + " must be an explicit non-wildcard IP");
        return ip;
    }
    private static int Port(string key, int defaultPort)
    {
        var value = Environment.GetEnvironmentVariable(key);
        if (string.IsNullOrWhiteSpace(value)) return defaultPort;
        if (!int.TryParse(value, out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException("INVALID_LISTENER_PORT: " + key);
        return port;
    }
    private static X509Certificate2 LoadServerCertificate(string prefix)
    {
        var path = Required(prefix + "_PFX_PATH");
        var passwordFile = Required(prefix + "_PASSWORD_FILE");
        if (!Path.IsPathFullyQualified(path) || !Path.IsPathFullyQualified(passwordFile) ||
            !File.Exists(path) || !File.Exists(passwordFile))
            throw new InvalidOperationException("INVALID_TLS_SECRET_PATH for " + prefix);
        var cert = X509CertificateLoader.LoadPkcs12FromFile(path, File.ReadAllText(passwordFile).Trim());
        if (!cert.HasPrivateKey || cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
            throw new InvalidOperationException("INVALID_TLS_SERVER_CERTIFICATE for " + prefix);
        return cert;
    }
    private static string Pin(string s) => s.Trim().Replace(":", "").Replace(" ", "").ToUpperInvariant();
    public static ListenerIsolation FromEnvironment()
    {
        var profile = Environment.GetEnvironmentVariable("YARP_LISTENER_PROFILE");
        if (string.IsNullOrEmpty(profile)) return new ListenerIsolation(); // preexisting CI only
        if (!string.Equals(profile, "split-v1", StringComparison.Ordinal))
            throw new InvalidOperationException("UNSUPPORTED_LISTENER_PROFILE");
        var traffic = RequiredAddress("YARP_LISTENER_TRAFFIC_IP");
        var data = RequiredAddress("YARP_LISTENER_DATA_IP");
        var mgmt = RequiredAddress("YARP_LISTENER_MANAGEMENT_IP");
        if (traffic.Equals(mgmt) || data.Equals(mgmt))
            throw new InvalidOperationException("LISTENER_IP_COLLISION: management IP must be distinct");
        var http = Port("YARP_LISTENER_HTTP_PORT", 80);
        var https = Port("YARP_LISTENER_HTTPS_PORT", 443);
        var ready = Port("YARP_LISTENER_READINESS_PORT", 8081);
        var admin = Port("YARP_LISTENER_ADMIN_PORT", 9443);
        var metrics = Port("YARP_LISTENER_METRICS_PORT", 9100);
        var endpoints = new (string ip, int port)[] {
            (traffic.ToString(), http), (traffic.ToString(), https),
            (data.ToString(), ready), (mgmt.ToString(), admin), (mgmt.ToString(), metrics)
        };
        if (endpoints.Distinct().Count() != endpoints.Length)
            throw new InvalidOperationException("LISTENER_PORT_COLLISION");
        var allowlist = new HashSet<IPAddress>();
        foreach (var item in Required("YARP_LISTENER_ALLOWED_CLIENT_IPS").Split(',', StringSplitOptions.TrimEntries))
        {
            if (!IPAddress.TryParse(item, out var ip) ||
                ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                throw new InvalidOperationException("INVALID_MANAGEMENT_ALLOWLIST_IP");
            allowlist.Add(ip);
        }
        if (allowlist.Count == 0) throw new InvalidOperationException("MISSING_MANAGEMENT_ALLOWLIST");
        var pins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in Required("YARP_LISTENER_ALLOWED_CLIENT_SHA256").Split(',', StringSplitOptions.TrimEntries))
        {
            var normalized = Pin(item);
            if (normalized.Length != 64 || normalized.Any(c => !Uri.IsHexDigit(c)))
                throw new InvalidOperationException("INVALID_CLIENT_CERT_SHA256");
            pins.Add(normalized);
        }
        if (pins.Count == 0) throw new InvalidOperationException("CLIENT_CERT_PIN_REQUIRED");
        // A single approved leaf may serve both interfaces when its SAN covers
        // both names/IPs. Separate certificates are supported via different paths.
        var tc = LoadServerCertificate("YARP_LISTENER_TRAFFIC_TLS");
        var mc = LoadServerCertificate("YARP_LISTENER_MANAGEMENT_TLS");
        return new ListenerIsolation(traffic, data, mgmt, http, https, ready, admin,
                                     metrics, allowlist, pins, tc, mc);
    }
    private bool ValidClientCertificate(X509Certificate2 cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors != SslPolicyErrors.None ||
            cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow) return false;
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cert.RawData));
        return _trustedClientPins.Contains(hash);
    }
    public void Configure(WebApplicationBuilder builder)
    {
        if (!Enabled) return;
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.Listen(TrafficIp, TrafficHttpPort);
            k.Listen(TrafficIp, TrafficHttpsPort, listen =>
                listen.UseHttps(https => https.ServerCertificate = _trafficCert));
            k.Listen(DataIp, ReadinessPort);
            void RequireMutualTls(Microsoft.AspNetCore.Server.Kestrel.Https.HttpsConnectionAdapterOptions https)
            {
                https.ServerCertificate = _managementCert;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = ValidClientCertificate;
            }
            k.Listen(ManagementIp, AdminPort, listen => listen.UseHttps(RequireMutualTls));
            k.Listen(ManagementIp, MetricsPort, listen => listen.UseHttps(RequireMutualTls));
        });
    }
    private bool ManagementSource(HttpContext ctx) =>
        ctx.Connection.RemoteIpAddress is { } address && _allowlist.Contains(address.IsIPv4MappedToIPv6
            ? address.MapToIPv4() : address);
    private static bool IsAdmin(PathString path) =>
        path == "/" || path.StartsWithSegments("/admin") || path.StartsWithSegments("/dashboard");
    public bool IsMetricsListener(HttpContext ctx) =>
        Enabled && ctx.Connection.LocalIpAddress is { } ip &&
        ip.Equals(ManagementIp) && ctx.Connection.LocalPort == MetricsPort;
    public bool IsAdminListener(HttpContext ctx) =>
        Enabled && ctx.Connection.LocalIpAddress is { } ip &&
        ip.Equals(ManagementIp) && ctx.Connection.LocalPort == AdminPort;
    public async Task EnforceAsync(HttpContext ctx, RequestDelegate next)
    {
        if (!Enabled) { await next(ctx); return; }
        var ip = ctx.Connection.LocalIpAddress;
        var port = ctx.Connection.LocalPort;
        var path = ctx.Request.Path;
        if (ip is not null && ip.Equals(ManagementIp) && (port == AdminPort || port == MetricsPort))
        {
            if (!ManagementSource(ctx)) { ctx.Response.StatusCode = 403; return; }
            if (port == AdminPort && IsAdmin(path) || port == MetricsPort && path == "/gateway/metrics")
            { await next(ctx); return; }
            ctx.Response.StatusCode = 404; return;
        }
        if (ip is not null && ip.Equals(DataIp) && port == ReadinessPort)
        {
            if (ctx.Request.Method == "GET" && path == "/gateway/health/ready")
            { await next(ctx); return; }
            ctx.Response.StatusCode = 404; return;
        }
        if (ip is not null && ip.Equals(TrafficIp) && (port == TrafficHttpPort || port == TrafficHttpsPort))
        {
            if (IsAdmin(path) || path.StartsWithSegments("/gateway"))
            { ctx.Response.StatusCode = 404; return; }
            await next(ctx); return;
        }
        ctx.Response.StatusCode = 404;
    }
}
