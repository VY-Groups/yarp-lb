using System.Net;
using System.Text.RegularExpressions;
using System.Text.Json;

/// <summary>
/// Disposable GitHub Actions-only live Control Center lab support. Normal
/// deployment never enables these paths, nor trusts self-signed server certs.
/// </summary>
public static class Ec2WorkflowLab
{
    // Offline-only fixture names, never a runtime allowlist or live test target.
    public const string HostA = "ec2-54-10-20-30.ap-south-1.compute.amazonaws.com";
    public const string HostB = "ec2-52-20-30-40.ap-south-1.compute.amazonaws.com";
    private static readonly Regex Ec2Dns = new(
        @"\Aec2-(\d{1,3}-){3}\d{1,3}\.ap-south-1\.compute\.amazonaws\.com\z",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static bool IsApprovedEc2Host(string? host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 128 || !Ec2Dns.IsMatch(host))
            return false;
        var addressText = host[4..host.IndexOf('.')].Replace('-', '.');
        if (!IPAddress.TryParse(addressText, out var ip) ||
            ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            return false;
        var bytes = ip.GetAddressBytes();
        // No internal, loopback, link-local, carrier NAT or multicast targets.
        return bytes[0] is not (0 or 10 or 127 or >= 224) &&
            !(bytes[0] == 169 && bytes[1] == 254) &&
            !(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
            !(bytes[0] == 192 && bytes[1] == 168) &&
            !(bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
    }
    public static bool Enabled =>
        Environment.GetEnvironmentVariable("YARP_EC2_LAB_MODE") == "1";

    public static void RequireIsolatedRunner()
    {
        if (!Enabled || Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("CI") != "true")
            throw new InvalidOperationException("EC2 lab mode only works inside a disposable GitHub Actions runner.");
        var urls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS");
        if (string.IsNullOrEmpty(urls) || urls.Contains(';') ||
            !Uri.TryCreate(urls, UriKind.Absolute, out var uri) ||
            uri.Scheme != "http" || uri.Host != "127.0.0.1" ||
            uri.Port is < 1025 or > 65535 || uri.AbsolutePath != "/")
            throw new InvalidOperationException("EC2 lab gateway must bind HTTP to one explicit 127.0.0.1 port.");
        var a = Environment.GetEnvironmentVariable("BACKEND_A_HOST");
        var b = Environment.GetEnvironmentVariable("BACKEND_B_HOST");
        if (!IsApprovedEc2Host(a) || !IsApprovedEc2Host(b) ||
            string.Equals(a, b, StringComparison.Ordinal))
            throw new InvalidOperationException(
                "EC2 lab requires two distinct approved public Mumbai EC2 DNS names.");
    }

    public static string PrivateDirectory()
    {
        RequireIsolatedRunner();
        var path = Environment.GetEnvironmentVariable("YARP_EC2_LAB_PRIVATE_DIR");
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) == Path.GetPathRoot(path))
            throw new InvalidOperationException("EC2 lab requires an explicit absolute private workspace directory.");
        return path;
    }

    public static bool RelaxedBackendTls()
    {
        if (Environment.GetEnvironmentVariable("YARP_EC2_LAB_ALLOW_INSECURE_BACKEND_TLS") != "1")
            return false;
        RequireIsolatedRunner();
        if (Environment.GetEnvironmentVariable("YARP_EC2_LAB_TLS_RISK_ACK") != "1")
            throw new InvalidOperationException("Test-only TLS bypass additionally requires explicit risk acknowledgment.");
        // Check the actual current static YARP configuration EACH time a
        // handler is constructed, including following hot configuration reload.
        var configPath = Path.Combine(Directory.GetCurrentDirectory(), "appsettings.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(configPath));
        var clusters = doc.RootElement.GetProperty("ReverseProxy").GetProperty("Clusters");
        var approvedHosts = new HashSet<string>(StringComparer.Ordinal)
        {
            Environment.GetEnvironmentVariable("BACKEND_A_HOST")!,
            Environment.GetEnvironmentVariable("BACKEND_B_HOST")!
        };
        var seenHosts = new HashSet<string>(StringComparer.Ordinal);
        var seen = 0;
        foreach (var cluster in clusters.EnumerateObject())
        {
            foreach (var dest in cluster.Value.GetProperty("Destinations").EnumerateObject())
            {
                var address = dest.Value.GetProperty("Address").GetString();
                if (!Uri.TryCreate(address, UriKind.Absolute, out var url) ||
                    url.Scheme != Uri.UriSchemeHttps ||
                    !approvedHosts.Contains(url.Host) ||
                    url.Port != 443 || url.AbsolutePath != "/" ||
                    url.UserInfo.Length > 0 || url.Query.Length > 0 || url.Fragment.Length > 0)
                    throw new InvalidOperationException(
                        "Test-only TLS bypass is restricted to two exact approved EC2 HTTPS roots.");
                seenHosts.Add(url.Host);
                seen++;
            }
        }
        if (seen != 2 || seenHosts.Count != 2)
            throw new InvalidOperationException(
                "Test-only TLS bypass requires one HTTPS root for each distinct approved EC2 backend.");
        return true;
    }
}
