using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using GatewayCore.Gslb.Contracts;

internal sealed record DnsResource(string Owner, ushort Type, uint Ttl, byte[] Rdata);

/// <summary>
/// Narrow RFC 4034/4035 signer for GatewayCore's deliberately small GSLB zone model.
/// Uses a pre-provisioned P-256 ECDSA private key in PEM form (algorithm 13).
/// It does not implement TSIG, NSEC3, automated rollover, or child-zone signing.
/// </summary>
internal sealed class DnssecZoneSigner : IDisposable
{
    internal const ushort RrsigType = 46;
    internal const ushort NsecType = 47;
    internal const ushort DnskeyType = 48;
    private const ushort DsType = 43;
    private readonly string apex;
    private readonly uint ttl;
    private readonly List<SigningKey> publishedKeys = [];
    private readonly List<SigningKey> signingKeys = [];
    private readonly List<DnsResource> staticRecords = [];
    private readonly Dictionary<(string Owner, ushort Type), List<DnsResource>> staticSignatures = [];
    private readonly Dictionary<string, DnsResource> nsecByOwner = new(StringComparer.Ordinal);
    private readonly List<string> owners;
    private readonly Dictionary<string, SortedSet<ushort>> types;
    private DateTime signedUntilUtc;
    private readonly object signingLock = new();

    public DnssecZoneSigner(string apex, uint ttl, string privateKeyPath,
        string soaContact, uint soaSerial, IReadOnlyList<DnsNameServer> nameServers,
        IReadOnlyList<DnsDelegation> delegations, bool hasA, bool hasAaaa,
        IReadOnlyList<string>? prepublishPublicKeyPaths = null,
        IReadOnlyList<string>? additionalSigningKeyPaths = null)
    {
        this.apex = Canonical(apex);
        this.ttl = ttl;
        try
        {
            var active = LoadPrivateKey(privateKeyPath, "active DNSSEC signing key", this.apex, isActive: true);
            publishedKeys.Add(active);
            signingKeys.Add(active);
            foreach (var path in additionalSigningKeyPaths ?? [])
            {
                var additional = LoadPrivateKey(path, "additional DNSSEC rollover signing key", this.apex, isActive: false);
                EnsureUniquePublicKey(additional);
                publishedKeys.Add(additional);
                signingKeys.Add(additional);
            }
            foreach (var path in prepublishPublicKeyPaths ?? [])
            {
                var prepublished = LoadPublicKey(path, this.apex);
                EnsureUniquePublicKey(prepublished);
                publishedKeys.Add(prepublished);
            }
        }
        catch
        {
            Dispose();
            throw;
        }

        types = new Dictionary<string, SortedSet<ushort>>(StringComparer.Ordinal);
        AddOwner(this.apex, 6, 2, DnskeyType);
        if (hasA) AddType(this.apex, 1);
        if (hasAaaa) AddType(this.apex, 28);
        foreach (var server in nameServers)
        {
            var host = Canonical(server.Host);
            if (!IsSubdomainOrEqual(host, this.apex)) continue;
            for (var current = host; current != this.apex; current = Parent(current))
                AddOwner(current);
            AddType(host, server.RecordType);
            staticRecords.Add(new DnsResource(host, server.RecordType, ttl, server.Address.GetAddressBytes()));
        }
        foreach (var delegation in delegations)
        {
            var cut = Canonical(delegation.Name);
            AddOwner(cut, 2);
            foreach (var server in delegation.NameServers)
            {
                var host = Canonical(server.Host);
                if (!IsSubdomainOrEqual(host, this.apex)) continue;
                // Data below a child cut is unsigned glue, not part of the parent zone.
                if (host.Equals(cut, StringComparison.Ordinal) || host.EndsWith("." + cut, StringComparison.Ordinal))
                    continue;
                for (var current = host; current != this.apex; current = Parent(current))
                    AddOwner(current);
                AddType(host, server.RecordType);
                staticRecords.Add(new DnsResource(host, server.RecordType, ttl, server.Address.GetAddressBytes()));
            }
        }
        owners = types.Keys.OrderBy(x => x, DnssecNameComparer.Instance).ToList();
        for (var i = 0; i < owners.Count; i++)
        {
            var owner = owners[i];
            var next = owners[(i + 1) % owners.Count];
            var bitmap = EncodeTypeBitmap(types[owner]);
            var rdata = WireName(next).Concat(bitmap).ToArray();
            nsecByOwner.Add(owner, new DnsResource(owner, NsecType, ttl, rdata));
        }

        var soaRdata = WireName(Canonical(nameServers[0].Host))
            .Concat(WireName(Canonical(soaContact))).ToList();
        Add32(soaRdata, soaSerial);
        Add32(soaRdata, 60);
        Add32(soaRdata, 30);
        Add32(soaRdata, 3600);
        Add32(soaRdata, ttl);
        staticRecords.Add(new DnsResource(this.apex, 6, ttl, soaRdata.ToArray()));
        foreach (var server in nameServers)
            staticRecords.Add(new DnsResource(this.apex, 2, ttl, WireName(Canonical(server.Host))));
        foreach (var publishedKey in publishedKeys)
            staticRecords.Add(new DnsResource(this.apex, DnskeyType, ttl, publishedKey.DnskeyRdata));
        staticRecords.AddRange(nsecByOwner.Values);
        ResignStatic(DateTime.UtcNow);
    }

    public DnsResource DnsKey => DnsKeys[0];
    public IReadOnlyList<DnsResource> DnsKeys => publishedKeys
        .Select(value => new DnsResource(apex, DnskeyType, ttl, value.DnskeyRdata)).ToArray();
    public DnsResource Ds => new(apex, DsType, ttl, publishedKeys.First(value => value.IsActive).DsRdata);
    public IReadOnlyList<DnsResource> DsRecords => publishedKeys
        .OrderBy(value => value.KeyTag)
        .ThenBy(value => Convert.ToHexString(value.DsRdata), StringComparer.Ordinal)
        .Select(value => new DnsResource(apex, DsType, ttl, value.DsRdata)).ToArray();
    public IReadOnlyList<(ushort KeyTag, DnsResource Ds, string Phase)> ParentDsMaterial => publishedKeys
        .OrderBy(value => value.IsActive ? 0 : value.IsSigning ? 1 : 2)
        .ThenBy(value => value.KeyTag)
        .ThenBy(value => Convert.ToHexString(value.DsRdata), StringComparer.Ordinal)
        .Select(value => (value.KeyTag, new DnsResource(apex, DsType, ttl, value.DsRdata),
            value.IsActive ? "active" : value.IsSigning ? "dual-sign" : "prepublish")).ToArray();
    public ushort KeyTag => publishedKeys[0].KeyTag;
    public IReadOnlyList<DnsResource> StaticRecords => staticRecords;
    public IReadOnlyList<string> Owners => owners;

    public DnsResource SignRrset(string owner, ushort type, uint originalTtl, IReadOnlyList<byte[]> rdata) =>
        SignRrsets(owner, type, originalTtl, rdata)[0];

    public IReadOnlyList<DnsResource> SignRrsets(string owner, ushort type, uint originalTtl, IReadOnlyList<byte[]> rdata)
    {
        if (rdata.Count == 0) throw new ArgumentException("DNSSEC cannot sign an empty RRset", nameof(rdata));
        lock (signingLock)
        {
            EnsureCurrentSignatures(DateTime.UtcNow);
            var canonicalOwner = Canonical(owner);
            var now = DateTime.UtcNow;
            var inception = ToSerialTime(now.AddMinutes(-5));
            var expiration = ToSerialTime(signedUntilUtc);
            var ownerLabels = checked((byte)canonicalOwner.Split('.').Length);
            var covered = new List<byte>();
            Add16(covered, type);
            covered.Add(13);
            covered.Add(ownerLabels);
            Add32(covered, originalTtl);
            Add32(covered, expiration);
            Add32(covered, inception);

            var result = new List<DnsResource>(signingKeys.Count);
            foreach (var signer in signingKeys)
            {
                var signedHeader = new List<byte>(covered);
                Add16(signedHeader, signer.KeyTag);
                signedHeader.AddRange(WireName(apex));
                var signedData = new List<byte>(signedHeader);
                foreach (var recordData in rdata.OrderBy(x => x, ByteArrayComparer.Instance))
                {
                    signedData.AddRange(WireName(canonicalOwner));
                    Add16(signedData, type);
                    Add16(signedData, 1);
                    Add32(signedData, originalTtl);
                    Add16(signedData, checked((ushort)recordData.Length));
                    signedData.AddRange(recordData);
                }
                var signature = signer.PrivateKey!.SignData(signedData.ToArray(), HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                result.Add(new DnsResource(canonicalOwner, RrsigType, originalTtl,
                    signedHeader.Concat(signature).ToArray()));
            }
            return result;
        }
    }

    public DnsResource? NsecAt(string owner) => nsecByOwner.GetValueOrDefault(Canonical(owner));

    public IReadOnlyList<DnsResource> DenialProof(string name, bool nxDomain)
    {
        lock (signingLock)
        {
            EnsureCurrentSignatures(DateTime.UtcNow);
            return BuildDenialProof(name, nxDomain);
        }
    }

    private IReadOnlyList<DnsResource> BuildDenialProof(string name, bool nxDomain)
    {
        var query = Canonical(name);
        if (!nxDomain && nsecByOwner.TryGetValue(query, out var exact))
            return new[] { exact }.Concat(SignaturesFor(exact)).ToArray();
        var proofs = new Dictionary<string, DnsResource>(StringComparer.Ordinal);
        if (!nxDomain)
        {
            var proof = Covering(query);
            proofs[proof.Owner] = proof;
        }
        else
        {
            var closest = query;
            while (!nsecByOwner.ContainsKey(closest) && closest != apex) closest = Parent(closest);
            var nextCloser = query;
            while (Parent(nextCloser) != closest && nextCloser != closest) nextCloser = Parent(nextCloser);
            var wildcard = "*." + closest;
            foreach (var candidate in new[] { nextCloser, wildcard })
            {
                if (nsecByOwner.ContainsKey(candidate)) continue;
                var proof = Covering(candidate);
                proofs[proof.Owner] = proof;
            }
        }
        return proofs.Values.SelectMany(record => new[] { record }.Concat(SignaturesFor(record))).ToArray();
    }

    public IReadOnlyList<DnsResource> SignaturesAt(string owner)
    {
        var canonical = Canonical(owner);
        lock (signingLock)
        {
            EnsureCurrentSignatures(DateTime.UtcNow);
            return staticSignatures.Where(x => x.Key.Owner == canonical).SelectMany(x => x.Value).ToArray();
        }
    }

    private DnsResource Covering(string name)
    {
        var candidate = Canonical(name);
        foreach (var owner in owners)
        {
            var next = nsecByOwner[owner].Rdata;
            var nextName = DecodeWireName(next, out _);
            if (InOpenInterval(candidate, owner, nextName)) return nsecByOwner[owner];
        }
        // A one-owner zone, or a canonical edge case, still uses its sole NSEC.
        return nsecByOwner[owners[0]];
    }

    private IReadOnlyList<DnsResource> SignaturesFor(DnsResource record)
    {
        if (staticSignatures.TryGetValue((record.Owner, record.Type), out var signature)) return signature;
        return SignRrsets(record.Owner, record.Type, record.Ttl, [record.Rdata]);
    }

    private void EnsureCurrentSignatures(DateTime now)
    {
        if (now < signedUntilUtc.AddDays(-1)) return;
        ResignStatic(now);
    }

    private void ResignStatic(DateTime now)
    {
        signedUntilUtc = now.AddDays(7);
        staticSignatures.Clear();
        foreach (var group in staticRecords.GroupBy(r => (r.Owner, r.Type)))
            staticSignatures[group.Key] = SignRrsets(group.Key.Owner, group.Key.Type,
                group.First().Ttl, group.Select(x => x.Rdata).ToArray()).ToList();
    }

    private void AddOwner(string owner, params ushort[] recordTypes)
    {
        owner = Canonical(owner);
        if (!types.TryGetValue(owner, out var set)) types.Add(owner, set = new SortedSet<ushort>());
        foreach (var type in recordTypes) set.Add(type);
        set.Add(NsecType);
        set.Add(RrsigType);
    }

    private void AddType(string owner, ushort type) => AddOwner(owner, type);

    private static bool IsSubdomainOrEqual(string name, string zone) =>
        name.Equals(zone, StringComparison.Ordinal) || name.EndsWith("." + zone, StringComparison.Ordinal);

    private static string Parent(string name)
    {
        var dot = name.IndexOf('.');
        return dot < 0 ? "." : name[(dot + 1)..];
    }

    private static bool InOpenInterval(string value, string start, string end)
    {
        var comparer = DnssecNameComparer.Instance;
        var startEnd = comparer.Compare(start, end);
        return startEnd < 0
            ? comparer.Compare(value, start) > 0 && comparer.Compare(value, end) < 0
            : comparer.Compare(value, start) > 0 || comparer.Compare(value, end) < 0;
    }

    private static string Canonical(string name) => name.TrimEnd('.').ToLowerInvariant();

    private static byte[] EncodeTypeBitmap(IEnumerable<ushort> values)
    {
        var output = new List<byte>();
        foreach (var group in values.Distinct().Order().GroupBy(type => type / 256))
        {
            var window = new byte[32];
            foreach (var type in group)
            {
                var offset = type % 256;
                window[offset / 8] |= (byte)(1 << (7 - (offset % 8)));
            }
            var length = Array.FindLastIndex(window, b => b != 0) + 1;
            output.Add((byte)group.Key);
            output.Add((byte)length);
            output.AddRange(window.Take(length));
        }
        return output.ToArray();
    }

    private static byte[] CreateDsRdata(string owner, byte[] dnskey, ushort tag)
    {
        var input = WireName(owner).Concat(dnskey).ToArray();
        var digest = SHA256.HashData(input);
        var output = new byte[4 + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, tag);
        output[2] = 13;
        output[3] = 2;
        digest.CopyTo(output, 4);
        return output;
    }

    private static ushort CalculateKeyTag(byte[] rdata)
    {
        uint accumulator = 0;
        for (var i = 0; i < rdata.Length; i++) accumulator += (uint)((i & 1) == 0 ? rdata[i] << 8 : rdata[i]);
        accumulator += (accumulator >> 16) & 0xffff;
        return (ushort)(accumulator & 0xffff);
    }

    private static uint ToSerialTime(DateTime value) => unchecked((uint)(new DateTimeOffset(value.ToUniversalTime()).ToUnixTimeSeconds()));

    private static string DecodeWireName(byte[] data, out int consumed)
    {
        var labels = new List<string>();
        var position = 0;
        while (position < data.Length && data[position] != 0)
        {
            var length = data[position++];
            if (length > 63 || position + length > data.Length) throw new InvalidDataException("Invalid internal NSEC name");
            labels.Add(Encoding.ASCII.GetString(data, position, length));
            position += length;
        }
        if (position >= data.Length) throw new InvalidDataException("Invalid internal NSEC terminator");
        consumed = position + 1;
        return string.Join('.', labels);
    }

    internal static byte[] WireName(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in Canonical(name).Split('.'))
        {
            bytes.Add(checked((byte)label.Length));
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private static void Add16(List<byte> bytes, ushort value) { bytes.Add((byte)(value >> 8)); bytes.Add((byte)value); }
    private static void Add32(List<byte> bytes, uint value)
    {
        bytes.Add((byte)(value >> 24)); bytes.Add((byte)(value >> 16)); bytes.Add((byte)(value >> 8)); bytes.Add((byte)value);
    }

    public void Dispose()
    {
        foreach (var privateKey in publishedKeys.Select(item => item.PrivateKey).OfType<ECDsa>())
            privateKey.Dispose();
    }

    private static SigningKey LoadPrivateKey(string path, string purpose, string apex, bool isActive)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(PrivateKeyFileSecurity.ReadPrivateKeyPem(path, purpose));
            var parameters = key.ExportParameters(true);
            if (parameters.D is null)
                throw new InvalidDataException("DNSSEC signing key must contain a private key");
            return CreateKeyMaterial(apex, parameters, key, isActive, isSigning: true);
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static SigningKey LoadPublicKey(string path, string apex)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new InvalidDataException("DNSSEC prepublish public-key paths must be absolute");
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists || fileInfo.Length is < 1 or > 16_384)
            throw new InvalidDataException("DNSSEC prepublish public key must be a bounded PEM file");
        var pem = File.ReadAllText(path);
        if (pem.Length is < 1 or > 16_384 ||
            !pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
            pem.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("DNSSEC prepublish key must be a bounded public SubjectPublicKeyInfo PEM");
        using var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return CreateKeyMaterial(apex, key.ExportParameters(false), null,
            isActive: false, isSigning: false);
    }

    private static SigningKey CreateKeyMaterial(string apex, ECParameters parameters, ECDsa? privateKey,
        bool isActive, bool isSigning)
    {
        if (parameters.Q.X is not { Length: 32 } x || parameters.Q.Y is not { Length: 32 } y ||
            privateKey is not null && privateKey.KeySize != 256 ||
            !string.Equals(parameters.Curve.Oid.Value,
                ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
            throw new InvalidDataException("DNSSEC rollover keys must use ECDSA P-256/SHA-256");
        var dnskey = new byte[68];
        BinaryPrimitives.WriteUInt16BigEndian(dnskey, 257); // KSK/CSK, Zone Key, Secure Entry Point
        dnskey[2] = 3; // DNSSEC protocol
        dnskey[3] = 13; // ECDSA P-256 with SHA-256
        x.CopyTo(dnskey, 4);
        y.CopyTo(dnskey, 36);
        var tag = CalculateKeyTag(dnskey);
        return new SigningKey(privateKey, dnskey, CreateDsRdata(apex, dnskey, tag), tag,
            isActive, isSigning);
    }

    private void EnsureUniquePublicKey(SigningKey candidate)
    {
        if (publishedKeys.Any(existing => existing.DnskeyRdata.AsSpan().SequenceEqual(candidate.DnskeyRdata)))
        {
            candidate.PrivateKey?.Dispose();
            throw new InvalidDataException("DNSSEC active, rollover and prepublish key material must be unique");
        }
    }

    private sealed record SigningKey(ECDsa? PrivateKey, byte[] DnskeyRdata,
        byte[] DsRdata, ushort KeyTag, bool IsActive, bool IsSigning);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
    }

    private sealed class DnssecNameComparer : IComparer<string>
    {
        public static readonly DnssecNameComparer Instance = new();
        public int Compare(string? x, string? y)
        {
            var left = (x ?? "").Split('.');
            var right = (y ?? "").Split('.');
            for (var offset = 1; offset <= Math.Min(left.Length, right.Length); offset++)
            {
                var comparison = StringComparer.Ordinal.Compare(left[^offset], right[^offset]);
                if (comparison != 0) return comparison;
            }
            return left.Length.CompareTo(right.Length);
        }
    }
}
