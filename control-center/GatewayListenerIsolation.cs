using System.Net;
using System.Net.Quic;
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
public sealed class GatewayListenerIsolation : IDisposable
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
        string HttpVersion,
        string[]? TrafficCertificateDnsNames = null,
        VirtualSocket[]? VirtualServices = null);

    public sealed record VirtualSocket(string Id, string Ip, int Port, string Protocol, bool RequireLocalAddressPresence = false, string? VipFleetId = null, string? VipQuorumConfigPath = null, long? VipOwnershipEpoch = null, string? VipJournalDirectory = null, string? VipInterfaceId = null);
    private readonly (VirtualSocket Config, IPAddress Address)[] _virtualServices;

    public readonly Settings Config;
    private readonly IPAddress _traffic, _management;
    private readonly IPNetwork[] _allowed;
    private readonly HashSet<string> _pins;
    private readonly X509Certificate2? _trafficCertificate;
    private readonly TrafficCertificateRotation? _trafficCertificateRotation;
    private readonly X509Certificate2 _managementCertificate, _clientCa;

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
        var virtualServices = config.VirtualServices ?? [];
        if (virtualServices.Length > 32) throw new InvalidOperationException("At most 32 virtual service sockets are supported.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bindings = new HashSet<(IPAddress, int)>
        {
            (_traffic, config.TrafficHttpPort), (_traffic, config.TrafficHttpsPort),
            (_management, config.AdminPort), (_management, config.MetricsPort)
        };
        var validated = new List<(VirtualSocket, IPAddress)>();
        foreach (var service in virtualServices)
        {
            if (service is null || !VirtualServiceBinding.ValidId(service.Id) || !ids.Add(service.Id) ||
                service.Port is < 1 or > 65535 || service.Protocol is not ("HTTP" or "HTTPS"))
                throw new InvalidOperationException("Invalid or duplicate virtual service identifier, port or protocol.");
            var address = ParseBoundIp(service.Ip, "virtual service");
            if (address.Equals(_management) || address.IsIPv4MappedToIPv6 ||
                address.Equals(IPAddress.Broadcast) ||
                (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                    address.GetAddressBytes()[0] >= 224) || !bindings.Add((address, service.Port)))
                throw new InvalidOperationException("Virtual service socket overlaps another binding or management IP.");
            var journalBound=service.VipJournalDirectory is not null||service.VipInterfaceId is not null;
            var distributed = service.VipFleetId is not null || service.VipQuorumConfigPath is not null || service.VipOwnershipEpoch is not null||journalBound;
            bool validEpoch=journalBound
                ? service.VipOwnershipEpoch is null && !string.IsNullOrWhiteSpace(service.VipJournalDirectory) &&
                  Path.IsPathFullyQualified(service.VipJournalDirectory) && service.VipInterfaceId is {Length:>0 and <=256} &&
                  !service.VipInterfaceId.Any(char.IsControl)
                : service.VipOwnershipEpoch is >0;
            if (distributed && (!service.RequireLocalAddressPresence || string.IsNullOrWhiteSpace(service.VipQuorumConfigPath) ||
                !Path.IsPathFullyQualified(service.VipQuorumConfigPath) || !validEpoch ||
                address.Equals(_traffic) || address.Equals(_management)))
                throw new InvalidOperationException("Distributed VIP admission requires local guard, isolated address, private quorum config and exact ownership epoch.");
            if (distributed)
            {
                _ = FleetQuorum.VipScope(service.VipFleetId!, address.ToString());
                if(journalBound)_=VipHostAddressPlatform.Parse(service.Ip);
            }
            validated.Add((service, address));
        }
        foreach (var group in validated.GroupBy(x=>x.Item2))
        {
            var first=group.First().Item1;
            if(group.Any(x=>x.Item1.VipFleetId!=first.VipFleetId ||
                x.Item1.VipQuorumConfigPath!=first.VipQuorumConfigPath ||
                x.Item1.VipOwnershipEpoch!=first.VipOwnershipEpoch ||
                x.Item1.VipJournalDirectory!=first.VipJournalDirectory || x.Item1.VipInterfaceId!=first.VipInterfaceId))
                throw new InvalidOperationException("All sockets on a distributed VIP must share the exact same authority and epoch.");
        }
        _virtualServices = validated.ToArray();
        if (config.MaxConcurrentConnections <= 0)
            throw new InvalidOperationException("REQUIRED_INPUT MaxConcurrentConnections must be derived from measured peak");
        _ = TrafficHttpProtocols.Parse(config.HttpVersion);
        if (config.HttpVersion == "3" && !QuicConnection.IsSupported)
            throw new InvalidOperationException("HttpVersion 3 requires a .NET runtime with working MsQuic support");
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
        X509Certificate2? trafficCertificate = null;
        TrafficCertificateRotation? trafficRotation = null;
        X509Certificate2? managementCertificate = null;
        X509Certificate2? clientCa = null;
        try
        {
            managementCertificate = LoadPfx(config.ManagementPfxPath, config.ManagementPfxPasswordFile);
            CheckRegular(config.ClientCaPemPath, false);
            clientCa = X509CertificateLoader.LoadCertificateFromFile(config.ClientCaPemPath);
            if (!clientCa.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority))
                throw new InvalidOperationException("Management client trust anchor must be a CA certificate");
            if (config.TrafficCertificateDnsNames is { Length: > 0 })
                trafficRotation = new TrafficCertificateRotation(config.TrafficPfxPath,
                    config.TrafficPfxPasswordFile, config.TrafficCertificateDnsNames);
            else
                trafficCertificate = LoadPfx(config.TrafficPfxPath, config.TrafficPfxPasswordFile);
        }
        catch
        {
            trafficRotation?.Dispose();
            trafficCertificate?.Dispose();
            managementCertificate?.Dispose();
            clientCa?.Dispose();
            throw;
        }
        _trafficCertificate = trafficCertificate;
        _trafficCertificateRotation = trafficRotation;
        _managementCertificate = managementCertificate;
        _clientCa = clientCa;
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
        // Windows Schannel/MsQuic need an OS-backed private key handle.
        // UserKeySet avoids the machine-wide store; without PersistKeySet
        // the imported key is owned by the certificate lifetime.
        var keyFlags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet
            : X509KeyStorageFlags.EphemeralKeySet;
        var cert = X509CertificateLoader.LoadPkcs12FromFile(file, password, keyFlags);
        if (!cert.HasPrivateKey || cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
            cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(1))
        {
            cert.Dispose();
            throw new InvalidOperationException("Listener certificate must have private key and >1 day validity");
        }
        return cert;
    }

    // This is deliberately a local first-start wizard. It never issues a CA
    // certificate or imports a password over HTTP. The exact shipping listener
    // constructor validates the prepared inputs before a new file is written.
    internal static int RunBootstrapWizard(string[] args)
    {
        if (args.Length != 2 || !Path.IsPathFullyQualified(args[1]) || !Directory.Exists(args[1]) ||
            Console.IsInputRedirected)
        {
            Console.Error.WriteLine("Usage: --listener-bootstrap-wizard <existing absolute private directory> (interactive local console)");
            return 64;
        }
        try
        {
            var directory = Path.GetFullPath(args[1]);
            if (OperatingSystem.IsWindows()) WindowsStateProtection.ValidateOfflineKeyRingDirectory(directory);
            else GatewayCore.Gslb.Contracts.PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(directory, "Listener bootstrap");
            var output = Path.Combine(directory, "listeners.json");
            if (Path.Exists(output)) throw new InvalidOperationException("Existing listener configuration will not be overwritten.");
            Console.WriteLine("GatewayCore listener bootstrap — provision encrypted PFX files, password files and trust anchors with the host administrator first.");
            string Ask(string label)
            {
                Console.Write(label + ": ");
                var value = Console.ReadLine()?.Trim();
                return string.IsNullOrWhiteSpace(value) ? throw new InvalidDataException("Required input missing.") : value;
            }
            int Port(string label) => int.TryParse(Ask(label), out var port) && port is >= 1 and <= 65535
                ? port : throw new InvalidDataException("Invalid listener port.");
            string[] List(string label) => Ask(label).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            var trafficIp = Ask("Traffic IP (not wildcard)");
            var trafficHttp = Port("Traffic HTTP port");
            var trafficHttps = Port("Traffic HTTPS port");
            var managementIp = Ask("Management IP (different from traffic)");
            var adminPort = Port("Management HTTPS port");
            var metricsPort = Port("Metrics HTTPS port");
            var trafficPfx = Ask("Absolute encrypted traffic PFX path");
            var trafficPass = Ask("Absolute traffic password FILE path (not password)");
            var managementPfx = Ask("Absolute encrypted management PFX path");
            var managementPass = Ask("Absolute management password FILE path (not password)");
            var ca = Ask("Absolute management client CA public PEM path");
            var pins = List("Approved management client certificate thumbprints (comma separated)");
            var cidrs = List("Management CIDR allowlist (comma separated)");
            if (!long.TryParse(Ask("Measured maximum concurrent connections"), out var connections) || connections <= 0)
                throw new InvalidDataException("Measured positive connection limit required.");
            var protocol = Ask("Traffic HTTP version (1.1, 2 or 3)");
            var names = List("Explicit traffic certificate DNS names (comma separated)");
            if (names.Length == 0) throw new InvalidDataException("Explicit traffic DNS names required.");
            var managementName = Ask("Management TLS DNS name used by clients");
            var settings = new Settings(trafficIp, trafficHttp, trafficHttps, managementIp, adminPort, metricsPort,
                trafficPfx, trafficPass, managementPfx, managementPass, ca, pins, cidrs, connections, protocol, names);
            using var validated = new GatewayListenerIsolation(settings);
            var leaf = validated._managementCertificate;
            if (Uri.CheckHostName(managementName) != UriHostNameType.Dns ||
                !leaf.Extensions.Cast<X509Extension>().Any(x => x.Oid?.Value == "2.5.29.17") ||
                !leaf.MatchesHostname(managementName) ||
                !leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e =>
                    e.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1")))
                throw new InvalidOperationException("Management certificate must have matching SAN and server authentication EKU.");
            using var chain = new X509Chain();
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
            if (!chain.Build(leaf)) throw new CryptographicException("Management certificate trust verification failed.");
            Console.WriteLine("Traffic and management certificate checks passed locally; no port binding or live client handshake tested.");
            if (Ask("Type CREATE to write the new listener configuration") != "CREATE") return 2;
            var bytes = JsonSerializer.SerializeToUtf8Bytes(settings,
                new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true });
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var file = new FileStream(output, options))
            {
                file.Write(bytes);
                file.Flush(flushToDisk: true);
            }
            Console.WriteLine("LISTENER_BOOTSTRAP_CREATED. Configure YARP_LISTENERS_CONFIG_FILE under the service identity, then verify actual isolated TLS/mTLS.");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or
            InvalidDataException or CryptographicException or ArgumentException or PlatformNotSupportedException)
        {
            Console.Error.WriteLine("Listener bootstrap refused: " + ex.GetType().Name);
            return 78;
        }
    }

    internal static Settings? ReadSettingsFromEnvironment()
    {
        var path = Environment.GetEnvironmentVariable("YARP_LISTENERS_CONFIG_FILE");
        if (string.IsNullOrEmpty(path)) return null;
        CheckRegular(path, false);
        var opts = new JsonSerializerOptions(JsonSerializerDefaults.Web) { UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow };
        return JsonSerializer.Deserialize<Settings>(File.ReadAllText(path), opts)
                     ?? throw new InvalidOperationException("Missing listener config");
    }

    public static GatewayListenerIsolation? FromEnvironment()
    {
        var config = ReadSettingsFromEnvironment();
        return config is null ? null : new GatewayListenerIsolation(config);
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
                listen.Protocols = TrafficHttpProtocols.Parse(Config.HttpVersion);
                if (_trafficCertificateRotation is null)
                    listen.UseHttps(_trafficCertificate!);
                else
                    listen.UseHttps(new HttpsConnectionAdapterOptions
                    {
                        HandshakeTimeout = TimeSpan.FromSeconds(10),
                        ServerCertificateSelector = (_, serverName) => _trafficCertificateRotation.Select(serverName)
                    });
            });
            foreach (var service in _virtualServices)
            {
                options.Listen(service.Address, service.Config.Port, listen =>
                {
                    if (service.Config.Protocol == "HTTP") { listen.Protocols = HttpProtocols.Http1; return; }
                    listen.Protocols = TrafficHttpProtocols.Parse(Config.HttpVersion);
                    if (_trafficCertificateRotation is null)
                        listen.UseHttps(_trafficCertificate!);
                    else
                        listen.UseHttps(new HttpsConnectionAdapterOptions
                        {
                            HandshakeTimeout = TimeSpan.FromSeconds(10),
                            ServerCertificateSelector = (_, serverName) => _trafficCertificateRotation.Select(serverName)
                        });
                });
            }
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
    /// <summary>Returns true only after the live isolated listener has selected this certificate.</summary>
    public bool IsTrafficCertificateActive(string thumbprint) =>
        _trafficCertificateRotation is not null &&
        string.Equals(_trafficCertificateRotation.Current.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase);

    public bool OnData(HttpContext ctx) => OnSocket(ctx, _traffic, Config.TrafficHttpPort) ||
                                            OnSocket(ctx, _traffic, Config.TrafficHttpsPort) ||
                                            VirtualServiceId(ctx) is not null;
    public string? VirtualServiceId(HttpContext ctx)
    {
        foreach (var service in _virtualServices)
            if (OnSocket(ctx, service.Address, service.Config.Port)) return service.Config.Id;
        return null;
    }
    public bool HasVirtualService(string id) => _virtualServices.Any(service => service.Config.Id == id);
    public IReadOnlyList<VirtualSocket> VirtualServices => _virtualServices.Select(service => service.Config).ToArray();
    public bool OnTrafficHttp(HttpContext ctx) =>
        AcmeHttp01Endpoint.IsPublicTrafficHttpListener(ctx, _traffic, Config.TrafficHttpPort);
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

    public void Dispose()
    {
        _trafficCertificateRotation?.Dispose();
        _trafficCertificate?.Dispose();
        _managementCertificate.Dispose();
        _clientCa.Dispose();
    }
}
