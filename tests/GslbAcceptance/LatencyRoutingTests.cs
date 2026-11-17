using System.Buffers.Binary;
using System.Net;
using System.Text;

// Characterization calls the shipping DNS assembly via a project reference.
// No copied selector and no wall-clock sleeps are involved in these cases.
internal static class LatencyRoutingTests
{
    public static void Run()
    {
        var now = Environment.TickCount64;
        var slow = Make("127.0.0.71", 2);
        var fast = Make("127.0.0.72", 1);
        WeightedFallback(Group(slow, fast), "missing measurements");
        Observe(slow, 100, now);
        WeightedFallback(Group(slow, fast), "one eligible measurement missing");
        fast.Latency.ObserveSuccess(TimeSpan.FromMilliseconds(10), now);
        WeightedFallback(Group(slow, fast), "insufficient sample floor");
        Observe(fast, 10, now - 15_001);
        WeightedFallback(Group(slow, fast), "one eligible measurement stale");

        slow = Make("127.0.0.71", 2);
        fast = Make("127.0.0.72", 1);
        Observe(slow, 114, now);
        Observe(fast, 100, now);
        WeightedFallback(Group(slow, fast), "under 15 percent uses weights");
        slow.Latency.ObserveFailure();
        Observe(slow, 115, now);
        var group = Group(slow, fast);
        for (var i = 0; i < 12; i++)
            Require(Address(Query(group)) == fast.Address.ToString(),
                "15 percent boundary chooses the measured faster site");

        fast.Healthy = 0;
        Require(Address(Query(group)) == slow.Address.ToString(),
            "unhealthy faster site cannot override health authority");
        slow.Healthy = 0;
        Require((Query(group)[3] & 15) == 2,
            "strict all-down policy still returns SERVFAIL");

        slow = Make("127.0.0.71", 2);
        fast = Make("127.0.0.72", 1);
        Observe(slow, 100, now);
        Observe(fast, 10, now);
        fast.Latency.ObserveFailure();
        fast.Latency.ObserveSuccess(TimeSpan.FromMilliseconds(10), now);
        WeightedFallback(Group(slow, fast), "recovery must rebuild its sample floor");

        var v6 = Make("2001:db8::71", 1);
        group = Group(slow, fast, v6);
        Observe(fast, 10, now);
        Require(Address(Query(group)) == fast.Address.ToString(),
            "missing IPv6 measurements do not poison the IPv4 pool");
        var packet = Query(group, 28);
        Require(BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6)) == 1 &&
            packet.AsSpan(packet.Length - 16).SequenceEqual(v6.Address.GetAddressBytes()),
            "AAAA uses its family-specific pool and weighted fallback");

        var estimator = new DnsProbeLatency();
        ObserveValue(estimator, 30, 1000);
        Require(estimator.TryRead(16_000, 3, 15_000, out _),
            "freshness limit is inclusive");
        estimator.ObserveSuccess(TimeSpan.FromMilliseconds(10), 999);
        Require(!estimator.TryRead(999, 3, 15_000, out _),
            "observed clock rollback resets the sample floor");
        ObserveValue(estimator, 20, 70_000);
        Require(estimator.TryRead(70_000, 3, 15_000, out var value) &&
            Math.Abs(value - 20) < 0.001,
            "long-gap reset discards the old EMA");
        Console.WriteLine("PASS: shipping DNS latency fallback, boundary, health, recovery and family characterization");
    }

    private static Site Make(string address, int weight) =>
        new(IPAddress.Parse(address), new Uri("http://127.0.0.1/unused"), weight,
            0, 1, 1, "Http", 0, null, null, []) { Healthy = 1 };
    private static SiteGroup Group(params Site[] sites) =>
        new(sites, 10, true, Array.Empty<DnsNameServer>(),
            "hostmaster.latency.unit.test", 1, "ObservedLatency", null);
    private static void Observe(Site site, double ms, long now) =>
        ObserveValue(site.Latency, ms, now);
    private static void ObserveValue(DnsProbeLatency latency, double ms, long now)
    {
        for (var i = 0; i < 3; i++)
            latency.ObserveSuccess(TimeSpan.FromMilliseconds(ms), now);
    }
    private static byte[] Query(SiteGroup group, ushort type = 1)
    {
        var packet = new List<byte> { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in "latency.unit.test".Split('.'))
        {
            packet.Add((byte)label.Length);
            packet.AddRange(Encoding.ASCII.GetBytes(label));
        }
        packet.AddRange(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        return DnsWireProtocol.Build(packet.ToArray(),
            new Dictionary<string, SiteGroup> { ["latency.unit.test"] = group },
            tcp: true) ?? throw new Exception("FAIL: DNS response missing");
    }
    private static string Address(byte[] packet)
    {
        Require((packet[3] & 15) == 0 &&
            BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6)) == 1,
            "one valid address answer required");
        return new IPAddress(packet.AsSpan(packet.Length - 4)).ToString();
    }
    private static void WeightedFallback(SiteGroup group, string scenario)
    {
        var first = 0; var second = 0;
        for (var i = 0; i < 90; i++)
        {
            var address = Address(Query(group));
            if (address == "127.0.0.71") first++;
            else if (address == "127.0.0.72") second++;
            else throw new Exception("FAIL: unexpected fallback site: " + address);
        }
        Require(first == 60 && second == 30, scenario + ": exact 2:1 fallback");
    }
    private static void Require(bool ok, string message)
    {
        if (!ok) throw new Exception("FAIL: " + message);
    }
}
