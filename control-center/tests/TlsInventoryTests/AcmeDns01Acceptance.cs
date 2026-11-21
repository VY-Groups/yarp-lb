internal static class AcmeDns01Acceptance
{
    private sealed class FakePublisher : IAcmeDns01Publisher
    {
        public int Published;
        public int Probed;
        public int Cleaned;
        public string? PublishedName;
        public string? PublishedValue;
        public bool Active;
        public bool ThrowAfterPublish;
        public readonly Queue<IReadOnlyList<AcmeDns01AuthorityObservation>> Responses = new();
        public bool ThrowOnProbe;

        private sealed class Lease(FakePublisher owner, string fqdn, string value)
            : IAcmeDns01PublicationLease
        {
            private bool disposed;
            public Task PublishAsync(CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                owner.Published++;
                owner.PublishedName = fqdn;
                owner.PublishedValue = value;
                owner.Active = true; // Simulate provider mutation before a timeout/error.
                if (owner.ThrowAfterPublish)
                    throw new InvalidOperationException("simulated provider timeout after TXT write");
                return Task.CompletedTask;
            }
            public ValueTask DisposeAsync()
            {
                if (!disposed)
                {
                    disposed = true;
                    if (owner.Active) owner.Cleaned++;
                    owner.Active = false;
                }
                return ValueTask.CompletedTask;
            }
        }

        public Task<IAcmeDns01PublicationLease> AcquirePublicationLeaseAsync(string fqdn,
            string txtValue, TimeSpan lifetime, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (lifetime is not { TotalMinutes: >= 1 and <= 10 })
                throw new Exception("FAIL: DNS-01 publication was not time bounded");
            return Task.FromResult<IAcmeDns01PublicationLease>(new Lease(this, fqdn, txtValue));
        }

        public Task<IReadOnlyList<AcmeDns01AuthorityObservation>> ProbeAuthoritativeAsync(
            string fqdn, string txtValue, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Probed++;
            if (ThrowOnProbe) throw new InvalidOperationException("simulated DNS authority failure");
            if (fqdn != PublishedName || txtValue != PublishedValue)
                throw new Exception("FAIL: DNS-01 probe used another TXT identity");
            return Task.FromResult(Responses.Count > 0
                ? Responses.Dequeue()
                : (IReadOnlyList<AcmeDns01AuthorityObservation>)Array.Empty<AcmeDns01AuthorityObservation>());
        }
    }

    public static async Task RunAsync()
    {
        static void Check(bool condition, string detail)
        {
            if (!condition) throw new Exception("FAIL: " + detail);
        }
        const string name = "api.example.com";
        var txt = new string('A', 43);
        Check(AcmeDns01Publication.IsDns01Value(txt), "canonical SHA-256 TXT accepted");
        foreach (var invalid in new[] { "", new string('A', 42), new string('A', 44),
            new string('A', 42) + "=", new string('A', 42) + "*",
            new string('A', 42) + "B" })
            Check(!AcmeDns01Publication.IsDns01Value(invalid),
                "invalid or noncanonical TXT rejected before publishing");
        Check(AcmeDns01Publication.ChallengeOwner("API.EXAMPLE.COM") ==
              "_acme-challenge.api.example.com", "DNS-01 target name canonicalized");
        foreach (var invalidName in new[] { "127.0.0.1", "*.example.com",
            "service.internal", "service.local", "localhost" })
        {
            var rejected = false;
            try { _ = AcmeDns01Publication.ChallengeOwner(invalidName); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "unsafe DNS-01 public owner rejected");
        }

        AcmeDns01AuthorityObservation Answer(string authority, params string[] rrset) =>
            new(authority, rrset);
        var good = new AcmeDns01AuthorityObservation[]
        {
            Answer("ns1.example.com", txt, "unrelated-existing-challenge"),
            Answer("ns2.example.com", txt)
        };
        Check(AcmeDns01Publication.HasVerifiedAuthorities(good, txt),
            "two independent authoritative RRsets containing the exact TXT are ready");
        foreach (var bad in new IReadOnlyList<AcmeDns01AuthorityObservation>[]
        {
            [Answer("ns1.example.com", txt)],
            [Answer("ns1.example.com", txt), Answer("NS1.EXAMPLE.COM", txt)],
            [Answer("ns1.example.com", txt), Answer("ns2.example.com", "stale")],
            [Answer("ns1.example.com", txt), Answer("", txt)],
            [Answer("ns1.example.com", txt), Answer("ns2.example.com", txt),
                Answer("ns3.example.com", "stale")],
            Enumerable.Range(1, 17).Select(i => Answer("ns" + i + ".example.com", txt)).ToArray()
        })
            Check(!AcmeDns01Publication.HasVerifiedAuthorities(bad, txt),
                "missing, duplicate, stale or oversized authoritative results fail closed");

        var publisher = new FakePublisher();
        publisher.Responses.Enqueue(good);
        await using (var lease = await AcmeDns01Publication.PublishAndVerifyAsync(
            name, txt, publisher, CancellationToken.None,
            maximumProbes: 1, probeInterval: TimeSpan.Zero))
        {
            Check(publisher.Published == 1 && publisher.Probed == 1 &&
                publisher.Cleaned == 0 &&
                publisher.PublishedName == "_acme-challenge.api.example.com" &&
                publisher.PublishedValue == txt,
                "publication precedes authoritative probe and remains live until release");
        }
        Check(publisher.Cleaned == 1,
            "successful DNS-01 authorization cleanup lease removes the TXT");

        var partialWrite = new FakePublisher { ThrowAfterPublish = true };
        var partialWriteFailed = false;
        try
        {
            await using var unused = await AcmeDns01Publication.PublishAndVerifyAsync(
                name, txt, partialWrite, CancellationToken.None,
                maximumProbes: 1, probeInterval: TimeSpan.Zero);
        }
        catch (InvalidOperationException) { partialWriteFailed = true; }
        Check(partialWriteFailed && partialWrite.Published == 1 &&
              partialWrite.Cleaned == 1 && !partialWrite.Active,
            "partial provider TXT write is compensated when publication throws before returning");

        var initiallyStale = new FakePublisher();
        initiallyStale.Responses.Enqueue([Answer("ns1.example.com", txt)]);
        initiallyStale.Responses.Enqueue(good);
        await using (var lease = await AcmeDns01Publication.PublishAndVerifyAsync(
            name, txt, initiallyStale, CancellationToken.None,
            maximumProbes: 2, probeInterval: TimeSpan.Zero))
            Check(initiallyStale.Probed == 2,
                "bounded DNS-01 authoritative visibility retries until quorum");
        Check(initiallyStale.Cleaned == 1, "retry success cleans up its lease");

        var failed = new FakePublisher();
        failed.Responses.Enqueue([Answer("ns1.example.com", txt)]);
        var noQuorum = false;
        try
        {
            await using var unused = await AcmeDns01Publication.PublishAndVerifyAsync(
                name, txt, failed, CancellationToken.None,
                maximumProbes: 1, probeInterval: TimeSpan.Zero);
        }
        catch (InvalidOperationException) { noQuorum = true; }
        Check(noQuorum && failed.Published == 1 && failed.Cleaned == 1,
            "DNS-01 never requests ACME validation after one-authority response and cleans up");

        var throwing = new FakePublisher { ThrowOnProbe = true };
        var aborted = false;
        try
        {
            await using var unused = await AcmeDns01Publication.PublishAndVerifyAsync(
                name, txt, throwing, CancellationToken.None,
                maximumProbes: 1, probeInterval: TimeSpan.Zero);
        }
        catch (InvalidOperationException) { aborted = true; }
        Check(aborted && throwing.Cleaned == 1,
            "DNS-01 authority probe errors always remove the published TXT");

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var notPublished = new FakePublisher();
        var wasCancelled = false;
        try
        {
            await using var unused = await AcmeDns01Publication.PublishAndVerifyAsync(
                name, txt, notPublished, cancelled.Token,
                maximumProbes: 1, probeInterval: TimeSpan.Zero);
        }
        catch (OperationCanceledException) { wasCancelled = true; }
        Check(wasCancelled && notPublished.Published == 0,
            "cancelled DNS-01 issuance cannot publish challenge material");

        Console.WriteLine("PASS: DNS-01 exact TXT, independent authority quorum, timeout, cancellation and cleanup");
    }
}
