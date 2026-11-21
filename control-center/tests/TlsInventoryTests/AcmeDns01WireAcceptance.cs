using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal static class AcmeDns01WireAcceptance
{
    private const string Owner = "_acme-challenge.api.example.com";
    private const string Txt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private sealed class Lease(Action published, Action disposed) : IAcmeDns01PublicationLease
    {
        public Task PublishAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            published();
            return Task.CompletedTask;
        }
        public ValueTask DisposeAsync() { disposed(); return ValueTask.CompletedTask; }
    }

    private sealed class SelfReportingWriter : IAcmeDns01Publisher
    {
        public int Published;
        public int Disposed;
        public Task<IAcmeDns01PublicationLease> AcquirePublicationLeaseAsync(
            string fqdn, string value, TimeSpan lifetime, CancellationToken cancellationToken)
        {
            if (fqdn != Owner || value != Txt)
                throw new InvalidOperationException("Wrong DNS-01 owner/value");
            return Task.FromResult<IAcmeDns01PublicationLease>(
                new Lease(() => Published++, () => Disposed++));
        }

        public Task<IReadOnlyList<AcmeDns01AuthorityObservation>> ProbeAuthoritativeAsync(
            string fqdn, string txt, CancellationToken cancellationToken)
        {
            // This is deliberately false self-reported readiness. The
            // wire-verified publisher must never call this provider method.
            throw new InvalidOperationException("Untrusted DNS publisher must not fabricate authority evidence");
        }
    }

    public static async Task RunAsync()
    {
        static void Must(bool value, string message)
        {
            if (!value) throw new Exception("FAIL: " + message);
        }
        static void MustReject(Action action, string message)
        {
            try { action(); }
            catch (InvalidDataException) { return; }
            throw new Exception("FAIL: " + message);
        }

        var question = AcmeDns01WireVerifiedPublisher.BuildTxtQuestion(Owner, 0x1234);
        byte[] Response(byte[] input, string value = Txt, bool authoritative = true)
        {
            var response = new List<byte>(input);
            response[2] = authoritative ? (byte)0x84 : (byte)0x80; // QR, optional AA
            response[3] = 0; // NOERROR
            response[6] = 0;
            response[7] = 1; // 1 answer
            response.AddRange([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 5,
                0, 44, 43]); // pointer, TXT, IN, TTL=5, RDLENGTH=44
            response.AddRange(Encoding.ASCII.GetBytes(value));
            return response.ToArray();
        }
        var good = Response(question);
        var decoded = AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(
            good, 0x1234, Owner);
        Must(decoded.SequenceEqual(new[] { Txt }),
            "DNS-01 parser accepts exact authoritative TCP TXT RDATA with compressed owner");

        var noAa = Response(question, authoritative: false);
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(noAa, 0x1234, Owner),
            "non-authoritative or recursive DNS answer refused");
        var wrongId = good.ToArray();
        wrongId[0] ^= 0x1;
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(wrongId, 0x1234, Owner),
            "transaction ID mismatch refused");
        var truncated = good.ToArray();
        truncated[2] |= 0x02;
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(truncated, 0x1234, Owner),
            "truncated answer cannot prove a full RRset");
        var nxdomain = good.ToArray();
        nxdomain[3] = 3;
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(nxdomain, 0x1234, Owner),
            "NXDOMAIN never proves DNS-01 TXT publication");
        var badQuestion = good.ToArray();
        badQuestion[13] = (byte)'z';
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(badQuestion, 0x1234, Owner),
            "wrong question name cannot be used as a readiness vote");
        var invalidRdata = good[..^1];
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(invalidRdata, 0x1234, Owner),
            "truncated TXT value fails closed");
        var pointerLoop = good.ToArray();
        pointerLoop[question.Length] = 0xC0;
        pointerLoop[question.Length + 1] = checked((byte)question.Length);
        MustReject(() => AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(pointerLoop, 0x1234, Owner),
            "forward compression pointer cannot bypass parser");
        var otherValue = Response(question, new string('B', 43));
        Must(!AcmeDns01WireVerifiedPublisher.ParseAuthoritativeTxt(otherValue, 0x1234, Owner)
                .Contains(Txt),
            "plausible but wrong digest never proves expected TXT");

        var fakeWriter = new SelfReportingWriter();
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("192.0.2.1")),
            new("NS1.EXAMPLE.COM", IPAddress.Parse("192.0.2.2"))
        ], "duplicate logical authorities");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("192.0.2.1")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.1"))
        ], "two authority names sharing a single IP");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Loopback),
            new("ns2.example.com", IPAddress.IPv6Loopback)
        ], "loopback endpoints in production");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("fe80::1%2")),
            new("ns2.example.com", IPAddress.Parse("fe80::1%3"))
        ], "scoped IPv6 aliases of one link-local host counted as separate authorities");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("fe80::1234")),
            new("ns2.example.com", IPAddress.Parse("2001:db8::2"))
        ], "IPv6 link-local authority without a scope");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("224.0.0.1")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "IPv4 multicast authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("169.254.1.1")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "IPv4 link-local authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("0.1.2.3")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "reserved 0/8 authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("240.0.0.1")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "reserved IPv4 240/4 authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("ff02::1")),
            new("ns2.example.com", IPAddress.Parse("2001:db8::2"))
        ], "IPv6 multicast authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("fec0::1")),
            new("ns2.example.com", IPAddress.Parse("2001:db8::2"))
        ], "deprecated IPv6 site-local authority");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("::ffff:192.0.2.1")),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "IPv4-mapped IPv6 authority alias");
        MustRejectConfiguration([
            new("ns1.example.com", IPAddress.Parse("192.0.2.1"), 5053),
            new("ns2.example.com", IPAddress.Parse("192.0.2.2"))
        ], "non-port-53 production authority");
        _ = new AcmeDns01WireVerifiedPublisher(fakeWriter, [
            new("ns1.example.com", IPAddress.Parse("10.1.2.3")),
            new("ns2.example.com", IPAddress.Parse("fd00::2"))
        ]); // Private unicast DNS must remain eligible on premises.

        void MustRejectConfiguration(AcmeDns01AuthorityServer[] authorities, string message)
        {
            try { _ = new AcmeDns01WireVerifiedPublisher(fakeWriter, authorities); }
            catch (InvalidOperationException) { return; }
            throw new Exception("FAIL: accepted " + message);
        }

        // The two loopback address families represent distinct simulated
        // authorities. The production constructor cannot use these addresses.
        // Each test sends actual framed DNS over independent TCP sockets.
        async Task<(TcpListener V4, TcpListener V6, Task[] Servers, AcmeDns01WireVerifiedPublisher Publisher)>
            StartServers(bool secondAuthorityEligible)
        {
            var first = new TcpListener(IPAddress.Loopback, 0);
            var second = new TcpListener(IPAddress.IPv6Loopback, 0);
            first.Start(); second.Start();
            var firstPort = ((IPEndPoint)first.LocalEndpoint).Port;
            var secondPort = ((IPEndPoint)second.LocalEndpoint).Port;

            async Task Serve(TcpListener listener, bool aa)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                using var connection = await listener.AcceptTcpClientAsync(deadline.Token);
                await using var stream = connection.GetStream();
                var len = new byte[2];
                await stream.ReadExactlyAsync(len, deadline.Token);
                var count = BinaryPrimitives.ReadUInt16BigEndian(len);
                if (count is < 17 or > 512)
                    throw new Exception("Invalid DNS TXT query length");
                var incoming = new byte[count];
                await stream.ReadExactlyAsync(incoming, deadline.Token);
                var reply = Response(incoming, authoritative: aa);
                var frame = new byte[reply.Length + 2];
                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), checked((ushort)reply.Length));
                reply.CopyTo(frame, 2);
                await stream.WriteAsync(frame, deadline.Token);
            }

            var tasks = new[] { Serve(first, true), Serve(second, secondAuthorityEligible) };
            var verified = new AcmeDns01WireVerifiedPublisher(fakeWriter,
                [
                    new("ns1.example.com", IPAddress.Loopback, firstPort),
                    new("ns2.example.com", IPAddress.IPv6Loopback, secondPort)
                ], allowLocalTestEndpoints: true);
            return (first, second, tasks, verified);
        }

        var success = await StartServers(secondAuthorityEligible: true);
        try
        {
            await using (var lease = await AcmeDns01Publication.PublishAndVerifyAsync(
                "api.example.com", Txt, success.Publisher, CancellationToken.None,
                maximumProbes: 1, probeInterval: TimeSpan.Zero))
                Must(fakeWriter.Published == 1 && fakeWriter.Disposed == 0,
                    "both independent authoritative TCP answers gate ACME validation");
            Must(fakeWriter.Disposed == 1, "published DNS-01 TXT cleanup lease released on success");
            await Task.WhenAll(success.Servers);
        }
        finally { success.V4.Stop(); success.V6.Stop(); }

        var failed = await StartServers(secondAuthorityEligible: false);
        try
        {
            var blocked = false;
            try
            {
                await using var unused = await AcmeDns01Publication.PublishAndVerifyAsync(
                    "api.example.com", Txt, failed.Publisher, CancellationToken.None,
                    maximumProbes: 1, probeInterval: TimeSpan.Zero);
            }
            catch (InvalidOperationException) { blocked = true; }
            Must(blocked && fakeWriter.Published == 2 && fakeWriter.Disposed == 2,
                "one non-authoritative TCP answer blocks issuance and cleans up TXT");
            await Task.WhenAll(failed.Servers);
        }
        finally { failed.V4.Stop(); failed.V6.Stop(); }

        Console.WriteLine("PASS: independent real TCP authoritative DNS-01 evidence and malformed-frame rejection");
    }
}
