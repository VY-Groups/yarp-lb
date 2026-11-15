using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

/// <summary>
/// A strict opt-in, one-peer HTTPS signed transport for eventually consistent
/// counters. Not a quota/lease/leader or config-replication protocol.
/// </summary>
public sealed record PeerSyncSettings(string NodeId, string RemoteId, Uri RemoteUrl,
    byte[] Secret, int Capacity, int IntervalSeconds)
{
    public static PeerSyncSettings? FromEnvironment(
        string? nodeId,string? remoteId,string? remoteUrl,string? secret,
        string? capacity,string? interval)
    {
        if (nodeId is null && remoteId is null && remoteUrl is null && secret is null &&
            capacity is null && interval is null) return null;
        static bool ValidId(string? id) =>
            !string.IsNullOrEmpty(id) && id.Length <= 48 &&
            id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
        if (!ValidId(nodeId) || !ValidId(remoteId) || nodeId == remoteId)
            throw new InvalidOperationException("Peer sync requires distinct ASCII node IDs");
        if (!Uri.TryCreate(remoteUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.AbsolutePath != "/gateway/internal/peer-sync" ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new InvalidOperationException("Peer sync requires exact HTTPS peer endpoint");
        if (string.IsNullOrEmpty(secret) || Encoding.UTF8.GetByteCount(secret) < 32)
            throw new InvalidOperationException("Peer sync requires a 32+ byte shared secret");
        static int Read(string? raw,int fallback,int max,string name)
        {
            if (raw is null) return fallback;
            if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ||
                n < 1 || n > max) throw new InvalidOperationException("Invalid " + name);
            return n;
        }
        return new PeerSyncSettings(nodeId!,remoteId!,uri!,Encoding.UTF8.GetBytes(secret),
            Read(capacity,2048,2048,"peer capacity"),
            Read(interval,2,30,"peer interval"));
    }
}

public sealed class PeerSyncPublisher : BackgroundService
{
    private readonly PeerSyncSettings settings;
    private readonly PeerStateJournal journal;
    private readonly PeerSignedMessages signing;
    private readonly IHttpClientFactory factory;
    private readonly ILogger<PeerSyncPublisher> logger;

    public PeerSyncPublisher(PeerSyncSettings settings, PeerStateJournal journal,
        PeerSignedMessages signing,IHttpClientFactory factory,ILogger<PeerSyncPublisher> logger)
    {
        this.settings=settings;
        this.journal=journal;
        this.signing=signing;
        this.factory=factory;
        this.logger=logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(settings.IntervalSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var snapshot=journal.Snapshot(now / 60);
                var payload=JsonSerializer.SerializeToUtf8Bytes(snapshot);
                if (payload.Length > 262144)
                    throw new InvalidOperationException("Peer frame exceeds 256 KiB limit");
                var (nonce, signature)=signing.Sign(settings.NodeId,now,payload);
                using var req=new HttpRequestMessage(HttpMethod.Post,settings.RemoteUrl);
                req.Headers.TryAddWithoutValidation("X-GC-Peer-Id",settings.NodeId);
                req.Headers.TryAddWithoutValidation("X-GC-Peer-Ts",now.ToString(CultureInfo.InvariantCulture));
                req.Headers.TryAddWithoutValidation("X-GC-Peer-Nonce",nonce);
                req.Headers.TryAddWithoutValidation("X-GC-Peer-Sig",signature);
                req.Content=new ByteArrayContent(payload);
                req.Content.Headers.ContentType=new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                using var result=await factory.CreateClient("peer-sync")
                    .SendAsync(req,HttpCompletionOption.ResponseHeadersRead,stoppingToken);
                if (!result.IsSuccessStatusCode)
                    logger.LogWarning("Peer counter sync rejected with HTTP {Status}",(int)result.StatusCode);
            }
            catch (OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning("Peer sync unavailable: {ErrorType}",ex.GetType().Name);
            }
            try
            {
                if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
            }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
