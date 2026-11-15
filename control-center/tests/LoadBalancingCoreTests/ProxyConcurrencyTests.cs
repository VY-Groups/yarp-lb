using System.Threading.RateLimiting;

public static class ProxyConcurrencyTests
{
    public static async Task RunAsync()
    {
        static void Check(bool ok, string name)
        {
            if (!ok) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }
        var defaultSettings = ProxyConcurrencySettings.FromEnvironment(null, null);
        Check(defaultSettings.PermitLimit == 128 && defaultSettings.QueueLimit == 0, "conservative defaults");
        var limits = ProxyConcurrencySettings.FromEnvironment("1", "1");
        Check(limits.PermitLimit == 1 && limits.QueueLimit == 1, "explicit bounded limits");
        foreach (var invalid in new [] { "0", "-1", "abc", "100001", " 1" })
        {
            var rejected = false;
            try { ProxyConcurrencySettings.FromEnvironment(invalid, null); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "fail closed invalid permits " + invalid);
        }
        foreach (var invalid in new [] { "-1", "4097", "1.5" })
        {
            var rejected = false;
            try { ProxyConcurrencySettings.FromEnvironment(null, invalid); }
            catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "fail closed invalid queue " + invalid);
        }
        using var limiter = new ConcurrencyLimiter(limits.ToLimiterOptions());
        using var first = limiter.AttemptAcquire();
        Check(first.IsAcquired, "first request admitted");
        var queued = limiter.AcquireAsync().AsTask();
        Check(!queued.IsCompleted, "second request waits");
        using var denied = limiter.AttemptAcquire();
        Check(!denied.IsAcquired, "overload rejected at queue cap");
        first.Dispose();
        using var admitted = await queued.WaitAsync(TimeSpan.FromSeconds(2));
        Check(admitted.IsAcquired, "queued request admitted on release");
        using var noQueue = new ConcurrencyLimiter(defaultSettings.ToLimiterOptions());
        var held = new List<RateLimitLease>();
        for (var i = 0; i < defaultSettings.PermitLimit; i++)
        {
            var lease = noQueue.AttemptAcquire();
            Check(lease.IsAcquired, "permit " + i);
            held.Add(lease);
        }
        using var rejection = noQueue.AttemptAcquire();
        Check(!rejection.IsAcquired, "no queue default overload immediately rejects");
        foreach (var lease in held) lease.Dispose();
    }
}
