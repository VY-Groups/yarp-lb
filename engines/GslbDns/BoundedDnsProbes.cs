// Independent bounded scheduler for local GSLB health checks.
// A finished batch must complete before the next probe cycle: no overlapping
// cycles or unconstrained Task.Run per backend in the DNS dataplane.
internal static class BoundedDnsProbes
{
    public static Task RunAsync<T>(IEnumerable<T> sites, int parallelism,
        Func<T, CancellationToken, ValueTask> check, CancellationToken ct)
    {
        if (sites is null) throw new ArgumentNullException(nameof(sites));
        if (check is null) throw new ArgumentNullException(nameof(check));
        if (parallelism is < 1 or > 128)
            throw new ArgumentOutOfRangeException(nameof(parallelism),
                "Concurrent DNS health probes must be 1..128");
        return Parallel.ForEachAsync(sites,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = parallelism,
                CancellationToken = ct
            }, check);
    }
}
