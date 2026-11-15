using System.Diagnostics;
using System.Net;

public static class PeerRateTableTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("FAIL: " + label);
            Console.WriteLine("PASS: " + label);
        }
        Check(BoundedPeerRateTable.FromEnvironment(null, null) is null, "peer table disabled by default");
        foreach (var (rate, capacity) in new[] { ("0", (string?)null), ("-1", null), ("bad", null),
            ("2", "0"), ("2", "65537"), (null, "16") })
        {
            var rejected = false;
            try { BoundedPeerRateTable.FromEnvironment(rate, capacity); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "invalid table environment fails closed");
        }
        var table = new BoundedPeerRateTable(2, 1);
        var a = IPAddress.Parse("127.0.0.1");
        var b = IPAddress.Parse("127.0.0.2");
        const long t = 1;
        Check(table.TryAdmit(a, t), "first peer admitted");
        Check(table.TryAdmit(IPAddress.Parse("::ffff:127.0.0.1"), t), "mapped IPv4 shares quota");
        Check(!table.TryAdmit(a, t), "over-limit peer receives denial");
        Check(!table.TryAdmit(b, t), "table capacity rejects new peer");
        Check(!table.TryAdmit(null, t), "unknown identity rejected");
        var afterWindow = t + 61L * Stopwatch.Frequency;
        Check(table.TryAdmit(b, afterWindow), "expired entry evicted and new peer admitted");
        Check(!table.TryAdmit(a, afterWindow), "old peer cannot exceed maximum entries");
        Check(table.TryAdmit(b, afterWindow + 1), "existing peer retains second quota slot");
    }
}
