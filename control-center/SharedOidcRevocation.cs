using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;

/// <summary>Optional single-writer TLS authority for provider logout cutoffs.
/// Missing, malformed or unavailable state denies federated sessions.</summary>
internal sealed class SharedOidcRevocation : IDisposable
{
    private const long MaxCutoff = 253402300799;
    private readonly ConnectionMultiplexer connection;
    private readonly string issuer;
    private readonly string clientId;
    // Fixed population from the validated OIDC mapping (at most 512 subjects).
    private readonly ConcurrentDictionary<string, long> observed;

    private const string CutoffScript = """
        if redis.call('PTTL', KEYS[1]) ~= -1 then return -1 end
        local raw = redis.call('GET', KEYS[1])
        if not raw or #raw > 12 or not string.match(raw, '^%d+$') then return -1 end
        if #raw > 1 and string.sub(raw, 1, 1) == '0' then return -1 end
        local current = tonumber(raw)
        if not current or current < 0 or current > 253402300799 then return -1 end
        local floor = tonumber(ARGV[2])
        if not floor or current < floor then return -1 end
        if ARGV[1] ~= '' then
            local proposed = tonumber(ARGV[1])
            if not proposed or proposed <= 0 or proposed > 253402300799 then return -1 end
            if proposed > current then
                redis.call('SET', KEYS[1], ARGV[1])
                return proposed
            end
        end
        return current
        """;

    private SharedOidcRevocation(ConnectionMultiplexer connection, OidcSettings settings)
    {
        this.connection = connection; issuer = settings.Issuer; clientId = settings.ClientId;
        observed = new ConcurrentDictionary<string, long>(
            settings.Accounts.Select(a => new KeyValuePair<string, long>(a.Subject, 0L)),
            StringComparer.Ordinal);
    }

    internal static SharedOidcRevocation? FromFile(string? path, EnterpriseOidcPolicy? policy)
    {
        if (path is null) return null;
        if (policy is null) throw new InvalidOperationException("Shared OIDC revocation requires enterprise OIDC");
        ConfigurationOptions config;
        try
        {
            var bytes = EnterpriseOidcPolicy.ReadPrivate(path, 4096);
            try { config = ConfigurationOptions.Parse(Encoding.UTF8.GetString(bytes).TrimEnd('\r', '\n')); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidDataException)
        { throw new InvalidOperationException("Invalid private OIDC revocation Redis configuration"); }
        if (!config.Ssl || config.EndPoints.Count != 1 || !string.IsNullOrEmpty(config.ServiceName) ||
            string.IsNullOrEmpty(config.Password))
            throw new InvalidOperationException("OIDC revocation requires one authenticated TLS Redis primary");
        config.AbortOnConnectFail = true;
        config.ConnectTimeout = config.SyncTimeout = config.AsyncTimeout = 3000;
        config.BacklogPolicy = BacklogPolicy.FailFast;
        ConnectionMultiplexer? redis = null;
        try
        {
            redis = ConnectionMultiplexer.Connect(config);
            var server = redis.GetServer(config.EndPoints[0]);
            if (server.ServerType != ServerType.Standalone || server.IsReplica)
                throw new InvalidOperationException("OIDC revocation requires a standalone primary");
            return new SharedOidcRevocation(redis, policy.Settings);
        }
        catch (Exception ex) when (ex is RedisException or InvalidOperationException or TimeoutException)
        {
            redis?.Dispose();
            throw new InvalidOperationException("OIDC revocation authority unavailable or invalid");
        }
    }

    private RedisKey Key(string subject) => "gatewaycore:oidc:cutoff:v1:" +
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(issuer + "\n" + clientId + "\n" + subject)));

    internal async Task<long?> ReadOrAdvanceAsync(string subject, long? cutoff = null)
    {
        if (cutoff is <= 0 or > MaxCutoff || !observed.TryGetValue(subject, out var floor)) return null;
        try
        {
            // EVAL uses the primary; no cached or replica authorization read.
            var value = (long)await connection.GetDatabase().ScriptEvaluateAsync(CutoffScript,
                new RedisKey[] { Key(subject) },
                new RedisValue[] {
                    cutoff?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "",
                    floor.ToString(System.Globalization.CultureInfo.InvariantCulture) });
            if (value is < 0 or > MaxCutoff) return null;
            // A concurrent newer observation must not be overwritten by this
            // response. Reject an older reply conservatively.
            var latest = observed.AddOrUpdate(subject, value, (_, previous) => Math.Max(previous, value));
            return value == latest ? value : null;
        }
        catch (Exception ex) when (ex is RedisException or InvalidOperationException or TimeoutException)
        { return null; }
    }

    internal async Task<bool> AllowsAsync(string subject, long authenticationTime, long localCutoff)
    {
        var shared = await ReadOrAdvanceAsync(subject);
        return shared is long current && current >= localCutoff && authenticationTime > current;
    }

    public void Dispose() => connection.Dispose();
}
