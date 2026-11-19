using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Runtime;

internal interface IAuditRetention
{
    DateTime RequiredUntil(DateTime utcNow);
    Task<bool> ConfirmAsync(long sequence, byte[] exactRecord, DateTime retainUntilUtc, CancellationToken ct);
}

/// <summary>Independent versioned Object Lock backend. Never grants a receipt
/// based solely on an upload result: read back exact bytes and lock metadata.</summary>
internal sealed class ObjectLockRetention : IAuditRetention, IDisposable
{
    private readonly IAmazonS3 s3;
    private readonly string bucket, prefix;
    private readonly int days;
    internal ObjectLockRetention(IAmazonS3 s3, string bucket, string prefix, int days)
    {
        if (bucket.Length is < 3 or > 63 || !bucket.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')
            || prefix.Length is < 1 or > 64 || !prefix.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
            || days is < 1 or > 3650)
            throw new InvalidDataException("Invalid audit Object Lock bucket, namespace or retention days");
        this.s3 = s3; this.bucket = bucket; this.prefix = prefix; this.days = days;
    }

    internal static ObjectLockRetention Create(string endpoint, string region, string bucket, string prefix,
        int days, string access, string secret)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
            uri.AbsolutePath != "/" || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            region.Length is < 1 or > 64 || !region.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
            access.Length is < 1 or > 256 || secret.Length is < 1 or > 256 ||
            access.Any(char.IsControl) || secret.Any(char.IsControl))
            throw new InvalidDataException("Object Lock requires explicit HTTPS endpoint, signing region and dedicated credentials");
        var client = new AmazonS3Client(new BasicAWSCredentials(access, secret), new AmazonS3Config
        {
            ServiceURL = uri.GetLeftPart(UriPartial.Authority), AuthenticationRegion = region,
            ForcePathStyle = true, MaxErrorRetry = 0
        });
        try { return new ObjectLockRetention(client, bucket, prefix, days); }
        catch { client.Dispose(); throw; }
    }

    public DateTime RequiredUntil(DateTime utcNow) =>
        new DateTime((utcNow.AddDays(days).Ticks / TimeSpan.TicksPerSecond + 1) * TimeSpan.TicksPerSecond, DateTimeKind.Utc);

    public async Task<bool> ConfirmAsync(long sequence, byte[] exactRecord, DateTime retainUntilUtc, CancellationToken ct)
    {
        if (sequence < 1 || exactRecord.Length is < 1 or > 8192 || retainUntilUtc.Kind != DateTimeKind.Utc ||
            retainUntilUtc <= DateTime.UtcNow) return false;
        var key = prefix + "/" + sequence.ToString("D12", CultureInfo.InvariantCulture) + ".jsonl";
        string? version = null;
        try
        {
            try
            {
                using var body = new MemoryStream(exactRecord, writable: false);
                var result = await s3.PutObjectAsync(new PutObjectRequest
                {
                    BucketName = bucket, Key = key, InputStream = body,
                    ContentType = "application/json", IfNoneMatch = "*",
                    ChecksumSHA256 = Convert.ToBase64String(SHA256.HashData(exactRecord)),
                    ObjectLockMode = ObjectLockMode.FindValue("COMPLIANCE"), ObjectLockRetainUntilDate = retainUntilUtc
                }, ct);
                if (result.HttpStatusCode != HttpStatusCode.OK || !RealVersion(result.VersionId)) return false;
                version = result.VersionId;
            }
            catch (AmazonS3Exception ex) when (ex.StatusCode is HttpStatusCode.PreconditionFailed or HttpStatusCode.Conflict)
            {
                // A response may have been lost. Only an exact already-retained
                // record can recover the same pending sequence; never overwrite.
            }
            using var read = await s3.GetObjectAsync(new GetObjectRequest
            {
                BucketName = bucket, Key = key, VersionId = version
            }, ct);
            if (read.HttpStatusCode != HttpStatusCode.OK || !RealVersion(read.VersionId) ||
                (version is not null && version != read.VersionId) ||
                read.ObjectLockMode?.Value != "COMPLIANCE" ||
                read.ObjectLockRetainUntilDate is not DateTime until ||
                until.ToUniversalTime() < retainUntilUtc ||
                read.ContentLength != exactRecord.Length) return false;
            var received = new byte[exactRecord.Length];
            await read.ResponseStream.ReadExactlyAsync(received, ct);
            var extra = new byte[1];
            return await read.ResponseStream.ReadAsync(extra.AsMemory(), ct) == 0 &&
                CryptographicOperations.FixedTimeEquals(received, exactRecord);
        }
        catch (Exception ex) when (ex is AmazonServiceException or HttpRequestException or IOException or
                                   OperationCanceledException or InvalidOperationException)
        { return false; }
    }

    private static bool RealVersion(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value != "null" && value.Length <= 1024;

    public void Dispose() => s3.Dispose();
}
