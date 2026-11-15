using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;

/// <summary>
/// Optional standalone Redis-backed atomic request budget shared by multiple
/// gateways. NOT HAProxy's gossip/peers protocol or distributed consensus.
/// Redis unavailability rejects requests instead of falling back to local quotas.
/// </summary>
public sealed class SharedPeerRateLimiter : IDisposable
{
    // All commands run atomically in Redis, based on its server clock.
    // Hash-based identities avoid retaining plaintext client IP addresses.
    // Bound the number of distinct peer keys in each 60-second window.
    public const string AdmissionScript = """
        local tm = redis.call('TIME')
        local minute = math.floor(tonumber(tm[1]) / 60)
        local prefix = KEYS[1]
        local seen = prefix .. ':peers:' .. minute
        local client = prefix .. ':requests:' .. minute .. ':' .. ARGV[1]
        local already = redis.call('SISMEMBER', seen, ARGV[1])
        if already == 0 then
            if redis.call('SCARD', seen) >= tonumber(ARGV[3]) then return 0 end
            redis.call('SADD', seen, ARGV[1])
            redis.call('EXPIRE', seen, 120)
        end
        local n = redis.call('INCR', client)
        if n == 1 then redis.call('EXPIRE', client, 120) end
        if n > tonumber(ARGV[2]) then return 0 end
        return 1
        """;

    private readonly ConnectionMultiplexer redis;
    private readonly byte[] keySecret;
    private readonly string namespacePrefix;
    private readonly int perMinute;
    private readonly int maxPeers;
    private int disposed;

    private SharedPeerRateLimiter(ConnectionMultiplexer redis, byte[] secret,
        string namespacePrefix, int perMinute, int maxPeers)
    {
        this.redis = redis;
        keySecret = secret;
        this.namespacePrefix = namespacePrefix;
        this.perMinute = perMinute;
        this.maxPeers = maxPeers;
    }

    public static SharedPeerRateLimiter? FromEnvironment(string? endpoint,
        string? hmacSecret, string? rate, string? capacity, string? keyNamespace)
    {
        if (endpoint is null)
        {
            if (hmacSecret is not null || keyNamespace is not null) throw new InvalidOperationException(
                "Shared quota options require GATEWAY_PROXY_SHARED_REDIS");
            return null;
        }
        if (string.IsNullOrWhiteSpace(endpoint))
            throw new InvalidOperationException("GATEWAY_PROXY_SHARED_REDIS cannot be blank");
        if (string.IsNullOrEmpty(hmacSecret) || Encoding.UTF8.GetByteCount(hmacSecret) < 32)
            throw new InvalidOperationException("GATEWAY_PROXY_SHARED_HMAC_KEY requires >=32 UTF8 bytes");
        if (!int.TryParse(rate, NumberStyles.None, CultureInfo.InvariantCulture, out var permits) ||
            permits is < 1 or > 1_000_000)
            throw new InvalidOperationException("Shared Redis requires GATEWAY_PROXY_IP_RATE_PER_MINUTE in range 1..1000000");
        var cap = 4096;
        if (capacity is not null && (!int.TryParse(capacity, NumberStyles.None, CultureInfo.InvariantCulture, out cap)
            || cap is < 1 or > 65536))
            throw new InvalidOperationException("GATEWAY_PROXY_IP_TABLE_CAPACITY must be 1..65536");
        var ns = keyNamespace ?? "gatewaycore:quota:v1";
        if (ns.Length is < 1 or > 80 || ns.Any(c => !char.IsAsciiLetterOrDigit(c) && c != ':' && c != '-' && c != '_'))
            throw new InvalidOperationException("GATEWAY_PROXY_SHARED_NAMESPACE contains invalid characters");
        var config = ConfigurationOptions.Parse(endpoint);
        // Require verified TLS; do not accept self-signed or certificate bypass callbacks.
        if (!config.Ssl || config.EndPoints.Count != 1)
            // Only explicit single-server configuration is supported in this revision.
            throw new InvalidOperationException("Shared Redis requires a single TLS endpoint (ssl=true)");
        config.AbortOnConnectFail = true;
        config.ConnectTimeout = 3000;
        config.SyncTimeout = 3000;
        config.AsyncTimeout = 3000;
        var connection = ConnectionMultiplexer.Connect(config);
        return new SharedPeerRateLimiter(connection, Encoding.UTF8.GetBytes(hmacSecret), ns, permits, cap);
    }

    public async Task<bool> TryAdmitAsync(IPAddress? remoteIp)
    {
        if (Volatile.Read(ref disposed) != 0 || remoteIp is null) return false;
        var normalized = remoteIp.MapToIPv6().GetAddressBytes();
        var hash = HMACSHA256.HashData(keySecret, normalized);
        var peer = Convert.ToHexString(hash);
        var result = await redis.GetDatabase().ScriptEvaluateAsync(
            AdmissionScript,
            new RedisKey[] { namespacePrefix },
            new RedisValue[] { peer, perMinute, maxPeers }).ConfigureAwait(false);
        return (long)result == 1;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            redis.Dispose();
            CryptographicOperations.ZeroMemory(keySecret);
        }
    }
}
