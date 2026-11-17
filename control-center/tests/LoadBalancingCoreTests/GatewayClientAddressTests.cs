using System.Net;

internal static class GatewayClientAddressTests
{
    public static void Run()
    {
        var untrusted = GatewayClientAddress.ForAccessLog(
            IPAddress.Parse("198.51.100.8"), "203.0.113.4", new HashSet<string>());
        Check(untrusted.Address!.ToString() == "198.51.100.8" && untrusted.Source == "socket",
            "untrusted X-Forwarded-For is ignored");

        var trustedProxies = GatewayClientAddress.ParseTrustedProxyAddresses("10.0.0.5, 2001:db8::5");
        var trusted = GatewayClientAddress.ForAccessLog(
            IPAddress.Parse("10.0.0.5"), "203.0.113.4", trustedProxies);
        Check(trusted.Address!.ToString() == "203.0.113.4" && trusted.Source == "trusted-proxy",
            "single client address accepted from configured trusted proxy");

        var chain = GatewayClientAddress.ForAccessLog(
            IPAddress.Parse("10.0.0.5"), "203.0.113.4, 10.0.0.6", trustedProxies);
        Check(chain.Address!.ToString() == "10.0.0.5" &&
              chain.Source == "trusted-proxy-invalid-forwarded-for",
            "multi-hop forwarded chain fails closed");

        var mapped = GatewayClientAddress.ForAccessLog(
            IPAddress.Parse("::ffff:10.0.0.5"), "203.0.113.4", trustedProxies);
        Check(mapped.Address!.ToString() == "203.0.113.4" && mapped.Source == "trusted-proxy",
            "IPv4-mapped trusted proxy identity is normalized");

        foreach (var invalid in new[] { "0.0.0.0", "::", "10.0.0.0/8", "fe80::1%3", "not-an-ip" })
        {
            var rejected = false;
            try { _ = GatewayClientAddress.ParseTrustedProxyAddresses(invalid); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "invalid trusted proxy setting rejected: " + invalid);
        }
    }

    private static void Check(bool passed, string label)
    {
        if (!passed) throw new Exception("FAIL: " + label);
        Console.WriteLine("PASS: " + label);
    }
}
