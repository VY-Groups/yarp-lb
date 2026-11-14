using System.Net;
using System.Text.Json;

/// <summary>
/// Disposable GitHub Actions-only live Control Center lab support. Normal
/// deployment never enables these paths, nor trusts self-signed server certs.
/// </summary>
public static class Ec2WorkflowLab
{
    public const string HostA = "ec2-3-108-65-15.ap-south-1.compute.amazonaws.com";
    public const string HostB = "ec2-65-0-11-186.ap-south-1.compute.amazonaws.com";
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
        if (Environment.GetEnvironmentVariable("BACKEND_A_HOST") != HostA ||
            Environment.GetEnvironmentVariable("BACKEND_B_HOST") != HostB)
            throw new InvalidOperationException("EC2 lab must use precisely the two allowlisted Mumbai backends.");
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
        var seen = 0;
        foreach (var cluster in clusters.EnumerateObject())
        {
            foreach (var dest in cluster.Value.GetProperty("Destinations").EnumerateObject())
            {
                var address = dest.Value.GetProperty("Address").GetString();
                if (!Uri.TryCreate(address, UriKind.Absolute, out var url) ||
                    url.Scheme != Uri.UriSchemeHttps ||
                    url.Host is not (HostA or HostB) ||
                    url.Port != 443 || url.AbsolutePath != "/" ||
                    url.UserInfo.Length > 0)
                    throw new InvalidOperationException(
                        "Test-only TLS bypass is restricted to the two allowlisted EC2 HTTPS roots.");
                seen++;
            }
        }
        if (seen != 2) throw new InvalidOperationException("Test-only TLS bypass requires exactly two EC2 HTTPS destinations.");
        return true;
    }
}
