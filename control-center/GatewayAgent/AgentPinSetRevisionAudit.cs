using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

/// <summary>
/// Emits bounded local audit records when the configured controller pin set
/// changes. This logger is not an immutable or centralized audit sink.
/// </summary>
public sealed class AgentPinSetRevisionAudit(ILogger logger)
{
    private string? currentRevision;

    public static string Fingerprint(IReadOnlySet<string> pins)
    {
        var canonical = string.Join("\n", pins.OrderBy(pin => pin, StringComparer.Ordinal));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    public void RecordRevision(string revision)
    {
        while (true)
        {
            var previous = Volatile.Read(ref currentRevision);
            if (StringComparer.Ordinal.Equals(previous, revision)) return;
            if (Interlocked.CompareExchange(ref currentRevision, revision, previous) != previous) continue;

            if (previous is null)
                logger.LogInformation("Controller mTLS pin-set revision loaded: {RevisionSha256}", revision);
            else
                logger.LogWarning(
                    "Controller mTLS pin-set revision changed: {PreviousRevisionSha256} -> {RevisionSha256}",
                    previous, revision);
            return;
        }
    }
}
