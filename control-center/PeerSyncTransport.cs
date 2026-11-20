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
    // The identity secret stays stable across transport-key rotation.
    public byte[]? SigningSecret { get; init; }
    public byte[]? PreviousSigningSecret { get; init; }

    public static PeerSyncSettings? FromEnvironment(
        string? nodeId,string? remoteId,string? remoteUrl,string? secret,
        string? capacity,string? interval,string? signingSecret = null,string? previousSigningSecret = null)
    {
        if (nodeId is null && remoteId is null && remoteUrl is null && secret is null &&
            capacity is null && interval is null && signingSecret is null && previousSigningSecret is null) return null;
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
        static byte[]? ReadKey(string? raw)
        {
            if (raw is null) return null;
            var length = Encoding.UTF8.GetByteCount(raw);
            if (length is < 32 or > 4096)
                throw new InvalidOperationException("Peer signing key must contain 32..4096 UTF-8 bytes");
            return Encoding.UTF8.GetBytes(raw);
        }
        var active = ReadKey(signingSecret);
        var previous = ReadKey(previousSigningSecret);
        if (previous is not null && (active is null ||
            System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(active,previous)))
            throw new InvalidOperationException("Peer previous signing key requires a distinct explicit active key");
        return new PeerSyncSettings(nodeId!,remoteId!,uri!,Encoding.UTF8.GetBytes(secret),
            Read(capacity,2048,2048,"peer capacity"),
            Read(interval,2,30,"peer interval"))
            { SigningSecret = active, PreviousSigningSecret = previous };
    }
}

/// <summary>
/// Fixed-cardinality publisher-side diagnostics. This reports delivery
/// attempts only; it does not imply durable queuing or remote persistence.
/// </summary>
public sealed record PeerSyncPublisherStatus(long AttemptsTotal, long AcknowledgementsTotal,
    long HttpFailuresTotal, long TransportFailuresTotal, long ResynchronizationsTotal,
    long? LastAcknowledgedAgeSeconds, DateTimeOffset? LastAcknowledgedUtc,
    int InFlightRequests);

public sealed class PeerSyncPublisherDiagnostics
{
    private sealed record AcknowledgementMark(long Timestamp, long UtcTicks);

    private readonly TimeProvider timeProvider;
    private long attempts, acknowledgements, httpFailures, transportFailures, resynchronizations;
    private AcknowledgementMark? lastAcknowledgement;
    private int inFlight;

    public PeerSyncPublisherDiagnostics(TimeProvider? timeProvider = null) =>
        this.timeProvider = timeProvider ?? TimeProvider.System;

    public void BeginAttempt()
    {
        Interlocked.Increment(ref attempts);
        Interlocked.Increment(ref inFlight);
    }

    public void EndAttempt() => Interlocked.Decrement(ref inFlight);

    public void RecordResponse(bool acknowledged, bool expectedChallenge = false)
    {
        if (!acknowledged)
        {
            if (!expectedChallenge) Interlocked.Increment(ref httpFailures);
            return;
        }

        var acknowledgedUtcTicks = timeProvider.GetUtcNow().UtcDateTime.Ticks;
        var acknowledgedTimestamp = timeProvider.GetTimestamp();
        var acknowledgement = new AcknowledgementMark(acknowledgedTimestamp, acknowledgedUtcTicks);
        Interlocked.Exchange(ref lastAcknowledgement, acknowledgement);
        Interlocked.Increment(ref acknowledgements);
    }

    public void RecordTransportFailure() => Interlocked.Increment(ref transportFailures);
    public void RecordResynchronization() => Interlocked.Increment(ref resynchronizations);

    public PeerSyncPublisherStatus Snapshot()
    {
        var acknowledgedAt = Volatile.Read(ref lastAcknowledgement);
        long? ageSeconds = null;
        if (acknowledgedAt is not null)
        {
            var elapsed = timeProvider.GetElapsedTime(acknowledgedAt.Timestamp);
            if (elapsed >= TimeSpan.Zero)
                ageSeconds = (long)Math.Floor(elapsed.TotalSeconds);
        }

        DateTimeOffset? acknowledgedUtc = acknowledgedAt is null
            ? null
            : new DateTimeOffset(acknowledgedAt.UtcTicks, TimeSpan.Zero);
        return new PeerSyncPublisherStatus(
            Interlocked.Read(ref attempts), Interlocked.Read(ref acknowledgements),
            Interlocked.Read(ref httpFailures), Interlocked.Read(ref transportFailures),
            Interlocked.Read(ref resynchronizations), ageSeconds, acknowledgedUtc,
            Math.Max(0, Volatile.Read(ref inFlight)));
    }
}

public sealed class PeerSyncPublisher : BackgroundService
{
    private readonly PeerSyncSettings settings;
    private readonly PeerStateJournal journal;
    private readonly PeerSignedMessages signing;
    private readonly IHttpClientFactory factory;
    private readonly ILogger<PeerSyncPublisher> logger;
    private readonly PeerSyncPublisherDiagnostics diagnostics;

    public PeerSyncPublisher(PeerSyncSettings settings, PeerStateJournal journal,
        PeerSignedMessages signing,IHttpClientFactory factory,ILogger<PeerSyncPublisher> logger,
        PeerSyncPublisherDiagnostics diagnostics)
    {
        this.settings=settings;
        this.journal=journal;
        this.signing=signing;
        this.factory=factory;
        this.logger=logger;
        this.diagnostics=diagnostics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(settings.IntervalSeconds));
        // No persisted challenge: learn the current receiver boot from an
        // authenticated HTTPS response, then send a new snapshot next tick.
        var receiverEpoch = "";
        PeerStateFrame? acknowledged = null;
        while (!stoppingToken.IsCancellationRequested)
        {
            var attemptStarted = false;
            try
            {
                var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var snapshot=journal.Snapshot(now / 60) with { ReceiverEpoch = receiverEpoch };
                var frame = PeerDelta.Select(snapshot, acknowledged);
                var payload=JsonSerializer.SerializeToUtf8Bytes(frame);
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
                diagnostics.BeginAttempt();
                attemptStarted = true;
                using var result=await factory.CreateClient("peer-sync")
                    .SendAsync(req,HttpCompletionOption.ResponseHeadersRead,stoppingToken);
                // Only a successful HTTPS response confirms this exact outbound baseline.
                // No chain of queued deltas: one previous full image is retained, bounded.
                acknowledged = result.IsSuccessStatusCode ? snapshot : null;
                var expectedChallenge = false;
                if (result.StatusCode == System.Net.HttpStatusCode.Conflict &&
                    result.Headers.TryGetValues(PeerStateJournal.ReceiverEpochHeader, out var values))
                {
                    var candidates = values.Take(2).ToArray();
                    if (candidates.Length == 1 && PeerStateJournal.IsReceiverEpoch(candidates[0]))
                    {
                        if (receiverEpoch.Length > 0 && receiverEpoch != candidates[0])
                            diagnostics.RecordResynchronization();
                        receiverEpoch = candidates[0];
                        expectedChallenge = true;
                        // Never replay the previous POST or reset local counters.
                        // The next periodic iteration sends a fresh signed snapshot.
                        logger.LogDebug("Peer receiver epoch learned; next periodic snapshot will resynchronize");
                    }
                    else
                        logger.LogWarning("Peer receiver challenge response invalid");
                }
                else if (!result.IsSuccessStatusCode)
                    logger.LogWarning("Peer counter sync rejected with HTTP {Status}",(int)result.StatusCode);
                diagnostics.RecordResponse(result.IsSuccessStatusCode, expectedChallenge);
            }
            catch (OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                diagnostics.RecordTransportFailure();
                acknowledged = null;
                logger.LogWarning("Peer sync unavailable: {ErrorType}",ex.GetType().Name);
            }
            finally
            {
                if (attemptStarted) diagnostics.EndAttempt();
            }
            try
            {
                if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
            }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
