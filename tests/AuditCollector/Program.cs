using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Amazon.S3;
using Amazon.S3.Model;
using Amazon.Runtime;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception("FAIL: " + message);
    Console.WriteLine("PASS: " + message);
}
static (string Id, byte[] Body) Intent()
{
    var eventId = Guid.NewGuid().ToString("N");
    return (eventId, JsonSerializer.SerializeToUtf8Bytes(new
    {
        schema = 1, eventId, node = "lab", utc = DateTimeOffset.UtcNow, actor = "operator",
        operation = "CONFIG_APPLY_INTENT", revision = new string('A',64), targetDigest = new string('B',64)
    }));
}
using var signer = RSA.Create(2048);
var root = Directory.CreateTempSubdirectory("audit-retention-");
try
{
    var path = Path.Combine(root.FullName, "ledger");
    var pending = Path.Combine(root.FullName, "pending");
    File.WriteAllBytes(path, []);
    File.WriteAllBytes(pending, []);
    var retention = new TestRetention();
    var first = Intent();
    var second = Intent();
    byte[] saved;
    using (var store = new AuditLedger(path, signer, retention, pending))
    {
        Check(store.Append(first.Id, first.Body).Status == 503 && store.Count == 0 &&
            new FileInfo(path).Length == 0 && new FileInfo(pending).Length > 0,
            "outage retains durable pending record and withholds receipt");
        saved = File.ReadAllBytes(pending);
        Check(store.Append(second.Id, second.Body).Status == 503 &&
            File.ReadAllBytes(pending).SequenceEqual(saved),
            "new intent cannot overtake or replace pending record");
    }
    retention.Available = true;
    using (var store = new AuditLedger(path, signer, retention, pending))
    {
        Check(store.RetryPending() && store.Count == 1 &&
            File.ReadAllBytes(path).SequenceEqual(saved) && new FileInfo(pending).Length == 0,
            "restart retries exactly the original signed record");
        Check(store.Append(first.Id, first.Body).Status == 409,
            "background persistence cannot retroactively authorize original request");
        var accepted = store.Append(second.Id, second.Body);
        Check(accepted.Status == 201 && accepted.Receipt is not null && store.Count == 2 &&
            retention.Objects.Count == 2 && signer.VerifyData(
                AuditContract.Input("GatewayCore-Audit-Receipt-v1", second.Id, second.Body),
                Convert.FromBase64String(accepted.Receipt!), HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            "new receipt only after retained record and durable local append");
    }
    var committed = File.ReadAllBytes(path);
    var last = committed.AsSpan(committed.AsSpan(0, committed.Length-1).LastIndexOf((byte)'\n')+1).ToArray();
    File.WriteAllBytes(pending, last);
    using (var store = new AuditLedger(path, signer, retention, pending))
        Check(store.RetryPending() && store.Count == 2 && new FileInfo(pending).Length == 0 &&
            File.ReadAllBytes(path).SequenceEqual(committed),
            "crash after local append but before journal clear does not append again");
    File.WriteAllBytes(pending, saved[..^1]);
    bool invalid = false;
    try { using var store = new AuditLedger(path, signer, retention, pending); }
    catch (InvalidDataException) { invalid = true; }
    Check(invalid, "partial pending record refuses startup rather than losing evidence");
}
finally { root.Delete(recursive: true); }

using var fake = new S3Fixture();
using var worm = new ObjectLockRetention(fake, "audit-bucket", "collector-a", 30);
var record = new byte[] { 1,2,3,4 };
var until = worm.RequiredUntil(DateTime.UtcNow);
Check(await worm.ConfirmAsync(1, record, until, CancellationToken.None) && fake.LastPut is
    { IfNoneMatch: "*", Key: "collector-a/000000000001.jsonl" } &&
    fake.LastPut.ObjectLockMode.Value == "COMPLIANCE" && fake.LastPut.ObjectLockRetainUntilDate == until &&
    fake.LastPut.ChecksumSHA256 == Convert.ToBase64String(SHA256.HashData(record)) &&
    fake.RequestedVersion == "locked-version",
    "real SDK adapter requires conditional write, checksum, COMPLIANCE retention and exact version");
fake.Conflict = true;
Check(await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "conditional conflict recovers only exact retained record");
fake.Stored = [4,3,2,1];
Check(!await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "same sequence with different content fails closed");
fake.Stored = record;
fake.Mode = "GOVERNANCE";
Check(!await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "governance mode is not accepted as compliance retention");
fake.Mode = "COMPLIANCE";
fake.Until = until.AddSeconds(-1);
Check(!await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "shortened retention rejected");
fake.Until = until;
fake.Version = "null";
Check(!await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "unversioned response rejected");
fake.Version = "locked-version";
fake.Conflict = false;
fake.ReadVersion = "different-version";
Check(!await worm.ConfirmAsync(1, record, until, CancellationToken.None),
    "read-back version must match upload version");
Console.WriteLine("AUDIT_RETENTION_CONTRACT_SUCCESS");

sealed class TestRetention : IAuditRetention
{
    public bool Available;
    public readonly Dictionary<long, byte[]> Objects = new();
    public DateTime RequiredUntil(DateTime now) => now.AddDays(30);
    public Task<bool> ConfirmAsync(long sequence, byte[] bytes, DateTime until, CancellationToken ct)
    {
        if (!Available) return Task.FromResult(false);
        if (Objects.TryGetValue(sequence, out var old)) return Task.FromResult(old.SequenceEqual(bytes));
        Objects.Add(sequence, bytes.ToArray());
        return Task.FromResult(true);
    }
}
sealed class S3Fixture() : AmazonS3Client(new BasicAWSCredentials("fixture", "fixture"), new AmazonS3Config
    { ServiceURL = "https://unused.example.invalid", AuthenticationRegion = "us-east-1", ForcePathStyle = true })
{
    public PutObjectRequest? LastPut;
    public string? RequestedVersion;
    public bool Conflict;
    public byte[] Stored = [];
    public string Mode = "COMPLIANCE", Version = "locked-version";
    public string? ReadVersion;
    public DateTime? Until;
    public override Task<PutObjectResponse> PutObjectAsync(PutObjectRequest request, CancellationToken cancellationToken = default)
    {
        LastPut = request;
        if (Conflict) throw new AmazonS3Exception("fixture conflict") { StatusCode = HttpStatusCode.PreconditionFailed };
        using var output = new MemoryStream();
        request.InputStream.CopyTo(output);
        Stored = output.ToArray();
        Until = request.ObjectLockRetainUntilDate;
        return Task.FromResult(new PutObjectResponse { HttpStatusCode = HttpStatusCode.OK, VersionId = Version });
    }
    public override Task<GetObjectResponse> GetObjectAsync(GetObjectRequest request, CancellationToken cancellationToken = default)
    {
        RequestedVersion = request.VersionId;
        return Task.FromResult(new GetObjectResponse
        {
            HttpStatusCode = HttpStatusCode.OK, VersionId = ReadVersion ?? Version,
            ObjectLockMode = ObjectLockMode.FindValue(Mode), ObjectLockRetainUntilDate = Until,
            ContentLength = Stored.Length, ResponseStream = new MemoryStream(Stored)
        });
    }
}
