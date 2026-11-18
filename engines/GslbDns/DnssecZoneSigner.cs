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
    private readonly ECDsa key;
    private readonly string apex;
    private readonly uint ttl;
    private readonly ushort keyTag;
    private readonly byte[] dnskeyRdata;
    private readonly byte[] dsRdata;
    private readonly List<DnsResource> staticRecords = [];
    private readonly Dictionary<(string Owner, ushort Type), DnsResource> staticSignatures = [];
    private readonly Dictionary<string, DnsResource> nsecByOwner = new(StringComparer.Ordinal);
    private readonly List<string> owners;
    private readonly Dictionary<string, SortedSet<ushort>> types;
    private DateTime signedUntilUtc;
    private readonly object signingLock = new();

    public DnssecZoneSigner(string apex, uint ttl, string privateKeyPath,
        string soaContact, uint soaSerial, IReadOnlyList<DnsNameServer> nameServers,
        IReadOnlyList<DnsDelegation> delegations, bool hasA, bool hasAaaa)
    {
        this.apex = Canonical(apex);
        this.ttl = ttl;
        key = ECDsa.Create();
        try
        {
            key.ImportFromPem(PrivateKeyFileSecurity.ReadPrivateKeyPem(
                privateKeyPath, "DNSSEC signing private key"));
            var parameters = key.ExportParameters(true);
            if (key.KeySize != 256 || parameters.Q.X is not { Length: 32 } x ||
                parameters.Q.Y is not { Length: 32 } y)
                throw new InvalidDataException("DNSSEC signing key must be an ECDSA P-256 private key");
            dnskeyRdata = new byte[68];
            BinaryPrimitives.WriteUInt16BigEndian(dnskeyRdata, 257); // KSK/CSK, Zone Key, Secure Entry Point
            dnskeyRdata[2] = 3; // DNSSEC protocol
            dnskeyRdata[3] = 13; // ECDSA P-256 with SHA-256
            x.CopyTo(dnskeyRdata, 4);
            y.CopyTo(dnskeyRdata, 36);
            keyTag = CalculateKeyTag(dnskeyRdata);
            dsRdata = CreateDsRdata(this.apex, dnskeyRdata, keyTag);
        }
        catch
        {
            key.Dispose();
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
        staticRecords.Add(new DnsResource(this.apex, DnskeyType, ttl, dnskeyRdata));
        staticRecords.AddRange(nsecByOwner.Values);
        ResignStatic(DateTime.UtcNow);
    }

    public DnsResource DnsKey => new(apex, DnskeyType, ttl, dnskeyRdata);
    public DnsResource Ds => new(apex, DsType, ttl, dsRdata);
    public ushort KeyTag => keyTag;
    public IReadOnlyList<DnsResource> StaticRecords => staticRecords;
    public IReadOnlyList<string> Owners => owners;

    public DnsResource SignRrset(string owner, ushort type, uint originalTtl, IReadOnlyList<byte[]> rdata)
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
            Add16(covered, keyTag);
            covered.AddRange(WireName(apex));

            var signedData = new List<byte>(covered);
            foreach (var recordData in rdata.OrderBy(x => x, ByteArrayComparer.Instance))
            {
                signedData.AddRange(WireName(canonicalOwner));
                Add16(signedData, type);
                Add16(signedData, 1);
                Add32(signedData, originalTtl);
                Add16(signedData, checked((ushort)recordData.Length));
                signedData.AddRange(recordData);
            }
            var signature = key.SignData(signedData.ToArray(), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new DnsResource(canonicalOwner, RrsigType, originalTtl, covered.Concat(signature).ToArray());
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
        if (!nxDomain && nsecByOwner.TryGetValue(query, out var exact)) return [exact, SignatureFor(exact)];
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
        return proofs.Values.SelectMany(record => new[] { record, SignatureFor(record) }).ToArray();
    }

    public IReadOnlyList<DnsResource> SignaturesAt(string owner)
    {
        var canonical = Canonical(owner);
        lock (signingLock)
        {
            EnsureCurrentSignatures(DateTime.UtcNow);
            return staticSignatures.Where(x => x.Key.Owner == canonical).Select(x => x.Value).ToArray();
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

    private DnsResource SignatureFor(DnsResource record)
    {
        if (staticSignatures.TryGetValue((record.Owner, record.Type), out var signature)) return signature;
        return SignRrset(record.Owner, record.Type, record.Ttl, [record.Rdata]);
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
            staticSignatures[group.Key] = SignRrset(group.Key.Owner, group.Key.Type,
                group.First().Ttl, group.Select(x => x.Rdata).ToArray());
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

    public void Dispose() => key.Dispose();

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
