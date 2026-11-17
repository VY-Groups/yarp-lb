using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;

/// <summary>Low-cardinality in-process DNS and agent evidence counters.</summary>
internal sealed class DnsRuntimeMetrics
{
    private readonly long[] queries = new long[2];
    private readonly long[] dropped = new long[2];
    private readonly long[][] responsesByRcode = [new long[16], new long[16]];
    private readonly long[] reports = new long[3]; // accepted, rejected, storage error

    public void QueryReceived(bool tcp) => Interlocked.Increment(ref queries[Transport(tcp)]);
    public void RequestDropped(bool tcp) => Interlocked.Increment(ref dropped[Transport(tcp)]);

    public void ResponseSent(bool tcp, ReadOnlySpan<byte> response)
    {
        if (response.Length < 4) return;
        var code = response[3] & 0x0f;
        Interlocked.Increment(ref responsesByRcode[Transport(tcp)][code]);
    }

    public void AgentReportAccepted() => Interlocked.Increment(ref reports[0]);
    public void AgentReportRejected() => Interlocked.Increment(ref reports[1]);
    public void AgentReportStorageError() => Interlocked.Increment(ref reports[2]);

    public string Render(IReadOnlyCollection<SiteGroup> groups, AgentHealthReportStore? reportStore,
        IReadOnlyCollection<AgentReportTarget> reportTargets, long nowTick)
    {
        var output = new StringBuilder(2048);
        WriteCounter(output, "gatewaycore_gslb_dns_queries_total",
            "DNS queries received by transport", "transport", ["udp", "tcp"], queries);
        WriteCounter(output, "gatewaycore_gslb_dns_dropped_total",
            "DNS queries that produced no response", "transport", ["udp", "tcp"], dropped);
        output.AppendLine("# HELP gatewaycore_gslb_dns_responses_total DNS responses sent by transport and response code");
        output.AppendLine("# TYPE gatewaycore_gslb_dns_responses_total counter");
        var codeNames = new[] { "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "RCODE6", "RCODE7", "RCODE8", "RCODE9", "RCODE10", "RCODE11", "RCODE12", "RCODE13", "RCODE14", "RCODE15" };
        for (var transport = 0; transport < responsesByRcode.Length; transport++)
        for (var code = 0; code < codeNames.Length; code++)
            output.Append("gatewaycore_gslb_dns_responses_total{transport=\"")
                .Append(transport == 0 ? "udp" : "tcp").Append("\",rcode=\"")
                .Append(codeNames[code]).Append("\"} ")
                .Append(Interlocked.Read(ref responsesByRcode[transport][code])).Append('\n');

        WriteCounter(output, "gatewaycore_gslb_agent_reports_total",
            "Authenticated agent report outcomes", "result", ["accepted", "rejected", "storage_error"], reports);

        var sites = groups.SelectMany(group => group.Sites).ToArray();
        output.AppendLine("# HELP gatewaycore_gslb_configured_zones Configured GSLB zones");
        output.AppendLine("# TYPE gatewaycore_gslb_configured_zones gauge");
        output.Append("gatewaycore_gslb_configured_zones ").Append(groups.Count).Append('\n');
        output.AppendLine("# HELP gatewaycore_gslb_configured_sites Configured GSLB backend sites");
        output.AppendLine("# TYPE gatewaycore_gslb_configured_sites gauge");
        output.Append("gatewaycore_gslb_configured_sites ").Append(sites.Length).Append('\n');
        output.AppendLine("# HELP gatewaycore_gslb_locally_healthy_sites Backend sites passing local probe hysteresis");
        output.AppendLine("# TYPE gatewaycore_gslb_locally_healthy_sites gauge");
        output.Append("gatewaycore_gslb_locally_healthy_sites ").Append(sites.Count(site => Volatile.Read(ref site.Healthy) == 1)).Append('\n');
        output.AppendLine("# HELP gatewaycore_gslb_administratively_quarantined_sites Sites explicitly quarantined by operator configuration");
        output.AppendLine("# TYPE gatewaycore_gslb_administratively_quarantined_sites gauge");
        output.Append("gatewaycore_gslb_administratively_quarantined_sites ")
            .Append(sites.Count(site => site.AdministrativelyQuarantined)).Append('\n');

        if (reportStore is not null)
        {
            var inQuorum = reportTargets.Count(target => reportStore.IsHealthy(
                target.Zone, target.SiteId, nowTick));
            var evidence = reportStore.EvidenceCounts(nowTick);
            output.AppendLine("# HELP gatewaycore_gslb_report_gated_sites Configured sites requiring signed-agent quorum");
            output.AppendLine("# TYPE gatewaycore_gslb_report_gated_sites gauge");
            output.Append("gatewaycore_gslb_report_gated_sites ").Append(reportTargets.Count).Append('\n');
            output.AppendLine("# HELP gatewaycore_gslb_agent_quorum_targets Report-gated sites currently meeting configured quorum");
            output.AppendLine("# TYPE gatewaycore_gslb_agent_quorum_targets gauge");
            output.Append("gatewaycore_gslb_agent_quorum_targets{state=\"quorum\"} ").Append(inQuorum).Append('\n');
            output.Append("gatewaycore_gslb_agent_quorum_targets{state=\"below_quorum\"} ")
                .Append(reportTargets.Count - inQuorum).Append('\n');
            output.AppendLine("# HELP gatewaycore_gslb_agent_evidence_reports Current signed observer reports by freshness and verdict");
            output.AppendLine("# TYPE gatewaycore_gslb_agent_evidence_reports gauge");
            AppendEvidence(output, "healthy", evidence.Healthy);
            AppendEvidence(output, "unhealthy", evidence.Unhealthy);
            AppendEvidence(output, "unknown", evidence.Unknown);
            AppendEvidence(output, "stale_or_missing", evidence.StaleOrMissing);
        }
        return output.ToString();
    }

    private static int Transport(bool tcp) => tcp ? 1 : 0;

    private static void AppendEvidence(StringBuilder output, string state, int count) =>
        output.Append("gatewaycore_gslb_agent_evidence_reports{state=\"").Append(state).Append("\"} ")
            .Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');

    private static void WriteCounter(StringBuilder output, string name, string help,
        string labelName, string[] labels, long[] values)
    {
        output.Append("# HELP ").Append(name).Append(' ').AppendLine(help);
        output.Append("# TYPE ").Append(name).AppendLine(" counter");
        for (var i = 0; i < labels.Length; i++)
            output.Append(name).Append('{').Append(labelName).Append("=\"").Append(labels[i]).Append("\"} ")
                .Append(Interlocked.Read(ref values[i]).ToString(CultureInfo.InvariantCulture)).Append('\n');
    }
}

/// <summary>Optional loopback-only Prometheus scrape endpoint for the DNS process.</summary>
internal sealed class DnsMetricsServer : IAsyncDisposable
{
    private readonly string listenAddress;
    private readonly int listenPort;
    private readonly DnsRuntimeMetrics metrics;
    private readonly IReadOnlyCollection<SiteGroup> groups;
    private readonly AgentHealthReportStore? reportStore;
    private readonly IReadOnlyCollection<AgentReportTarget> reportTargets;
    private WebApplication? app;

    public DnsMetricsServer(string listenAddress, int listenPort, DnsRuntimeMetrics metrics,
        IReadOnlyCollection<SiteGroup> groups, AgentHealthReportStore? reportStore,
        IReadOnlyCollection<AgentReportTarget> reportTargets)
    {
        if (!IPAddress.TryParse(listenAddress, out var address) || !IPAddress.IsLoopback(address) ||
            address.IsIPv4MappedToIPv6 || listenPort is < 1025 or > 65535)
            throw new InvalidDataException("GSLB metrics must use a dedicated loopback listener and port 1025..65535");
        this.listenAddress = address.ToString();
        this.listenPort = listenPort;
        this.metrics = metrics;
        this.groups = groups;
        this.reportStore = reportStore;
        this.reportTargets = reportTargets;
    }

    public async Task StartAsync(CancellationToken token)
    {
        if (app is not null) throw new InvalidOperationException("GSLB metrics listener already started");
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxConcurrentConnections = 8;
            kestrel.Limits.MaxRequestHeadersTotalSize = 4096;
            kestrel.Listen(IPAddress.Parse(listenAddress), listenPort);
        });
        var web = builder.Build();
        web.MapGet("/metrics", (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Results.Text(metrics.Render(groups, reportStore, reportTargets, Environment.TickCount64),
                "text/plain; version=0.0.4; charset=utf-8");
        });
        app = web;
        try { await web.StartAsync(token); }
        catch
        {
            app = null;
            await web.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        var running = app;
        app = null;
        if (running is null) return;
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await running.StopAsync(stop.Token); }
        catch (OperationCanceledException) { }
        await running.DisposeAsync();
    }
}
