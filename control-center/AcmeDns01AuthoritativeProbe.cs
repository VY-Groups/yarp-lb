using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// An operator-pinned authoritative DNS endpoint. No recursive DNS resolver
/// discovery, DNS hostname lookup, SRV discovery or user-supplied URL is used.
/// </summary>
public sealed record AcmeDns01AuthorityServer(string AuthorityId, IPAddress Address, int Port = 53);

/// <summary>
/// Publication is delegated to a separately authenticated DNS update provider.
/// Readiness is NEVER delegated to that provider's self-reported observations:
/// this adapter performs independent TCP/53 DNS TXT queries directly to each
/// preconfigured authority and requires AA, matching question, exact TXT and
/// independent destination IPs before ACME validation can be attempted.
/// This is DNS wire evidence, not a DNSSEC cryptographic validation claim.
/// </summary>
public sealed class AcmeDns01WireVerifiedPublisher : IAcmeDns01Publisher
{
    private readonly IAcmeDns01Publisher writer;
    private readonly AcmeDns01AuthorityServer[] authorities;
    private const int MaximumDnsPacketBytes = 8192;

    // Do not count scoped/link-local aliases or multicast destinations as
    // independent authoritative DNS servers. RFC1918 and IPv6 ULA unicast
    // addresses remain supported for operator-managed on-premises DNS.
    private static bool IsPinnedUnicastAddress(IPAddress? address, bool allowLocalTestEndpoints)
    {
        if (address is null || address.IsIPv4MappedToIPv6 ||
            address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast) || address.IsIPv6Multicast)
            return false;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // An IPv6 zone/scope identifier changes the interface, not the
            // authority's identity. Distinct %scope values cannot satisfy quorum.
            if (address.ScopeId != 0 || address.IsIPv6LinkLocal || address.IsIPv6SiteLocal)
                return false;
        }
        else
        {
            var octets = address.GetAddressBytes();
            // 0/8 is not a destination, 169.254/16 is link-local, and
            // 224/4 plus 240/4 are not ordinary unicast DNS endpoints.
            if (octets[0] == 0 || octets[0] >= 224 ||
                (octets[0] == 169 && octets[1] == 254))
                return false;
        }

        return allowLocalTestEndpoints || !IPAddress.IsLoopback(address);
    }

    public AcmeDns01WireVerifiedPublisher(IAcmeDns01Publisher writer,
        IEnumerable<AcmeDns01AuthorityServer> authorities)
        : this(writer, authorities, allowLocalTestEndpoints: false) { }

    // Isolated in-process socket tests need dynamic ports and loopback.
    // The production constructor always requires distinct non-loopback IPs
    // and the real authoritative DNS TCP port 53.
    internal AcmeDns01WireVerifiedPublisher(IAcmeDns01Publisher writer,
        IEnumerable<AcmeDns01AuthorityServer> authorities, bool allowLocalTestEndpoints)
    {
        this.writer = writer ?? throw new ArgumentNullException(nameof(writer));
        this.authorities = (authorities ??
            throw new ArgumentNullException(nameof(authorities))).ToArray();
        if (this.authorities.Length is < 2 or > 16)
            throw new InvalidOperationException("DNS-01 requires two to sixteen pinned authoritative DNS endpoints");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var addresses = new HashSet<IPAddress>();
        foreach (var server in this.authorities)
        {
            var address = server?.Address;
            if (server is null || string.IsNullOrWhiteSpace(server.AuthorityId) ||
                server.AuthorityId.Length > 128 ||
                server.AuthorityId.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                    c is '.' or '-' or '_' or ':')) ||
                !IsPinnedUnicastAddress(address, allowLocalTestEndpoints) ||
                !names.Add(server.AuthorityId) || !addresses.Add(address!) ||
                (allowLocalTestEndpoints
                    ? server.Port is < 1 or > 65535
                    : server.Port != 53))
                throw new InvalidOperationException("Invalid or duplicate pinned DNS-01 authority endpoint");
        }
    }

    public Task<IAcmeDns01PublicationLease> AcquirePublicationLeaseAsync(
        string fqdn, string txtValue, TimeSpan lifetime,
        CancellationToken cancellationToken) =>
        writer.AcquirePublicationLeaseAsync(fqdn, txtValue, lifetime, cancellationToken);

    public async Task<IReadOnlyList<AcmeDns01AuthorityObservation>> ProbeAuthoritativeAsync(
        string fqdn, string txtValue, CancellationToken cancellationToken)
    {
        const string prefix = "_acme-challenge.";
        if (string.IsNullOrEmpty(fqdn) || !fqdn.StartsWith(prefix, StringComparison.Ordinal) ||
            !string.Equals(AcmeDns01Publication.ChallengeOwner(fqdn[prefix.Length..]),
                fqdn, StringComparison.Ordinal) ||
            !AcmeDns01Publication.IsDns01Value(txtValue))
            throw new InvalidOperationException("Invalid DNS-01 authoritative probe owner or SHA-256 digest");
        cancellationToken.ThrowIfCancellationRequested();
        return await Task.WhenAll(authorities.Select(async authority =>
        {
            try
            {
                var answers = await QueryAuthoritativeTxtAsync(authority, fqdn, cancellationToken);
                return new AcmeDns01AuthorityObservation(authority.AuthorityId, answers);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is IOException or SocketException or
                InvalidDataException or OperationCanceledException)
            {
                // A failed, non-authoritative, timed-out or malformed endpoint
                // does not contribute a quorum vote. Never fall back to the
                // provider's claimed view of its own DNS update.
                return new AcmeDns01AuthorityObservation(authority.AuthorityId, []);
            }
        }));
    }

    private static async Task<IReadOnlyList<string>> QueryAuthoritativeTxtAsync(
        AcmeDns01AuthorityServer server, string fqdn, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(4));
        var operation = deadline.Token;
        var transactionId = (ushort)RandomNumberGenerator.GetInt32(0, 65536);
        var query = BuildTxtQuestion(fqdn, transactionId);
        using var socket = new TcpClient(server.Address.AddressFamily);
        await socket.ConnectAsync(server.Address, server.Port, operation);
        await using var stream = socket.GetStream();
        var frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), checked((ushort)query.Length));
        query.CopyTo(frame, 2);
        await stream.WriteAsync(frame, operation);
        var length = new byte[2];
        await stream.ReadExactlyAsync(length, operation);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(length);
        if (responseLength is < 17 or > MaximumDnsPacketBytes)
            throw new InvalidDataException("Authoritative DNS TXT response length outside bound");
        var response = new byte[responseLength];
        await stream.ReadExactlyAsync(response, operation);
        return ParseAuthoritativeTxt(response, transactionId, fqdn);
    }

    internal static byte[] BuildTxtQuestion(string owner, ushort transactionId)
    {
        var question = new List<byte>(300);
        question.AddRange(new byte[12]);
        BinaryPrimitives.WriteUInt16BigEndian(
            System.Runtime.InteropServices.CollectionsMarshal.AsSpan(question)[..2],
            transactionId);
        question[5] = 1; // QDCOUNT=1; RD=0; recursion is never requested
        foreach (var label in owner.Split('.'))
        {
            if (label.Length is < 1 or > 63 || label.Any(ch => !char.IsAsciiLetterOrDigit(ch) &&
                    ch is not ('_' or '-')))
                throw new InvalidDataException("Invalid authoritative TXT owner label");
            question.Add(checked((byte)label.Length));
            question.AddRange(Encoding.ASCII.GetBytes(label));
        }
        question.Add(0);
        question.AddRange([0, 16, 0, 1]); // QTYPE=TXT, QCLASS=IN
        if (question.Count > 267)
            throw new InvalidDataException("Authoritative TXT question exceeds DNS name length");
        return question.ToArray();
    }

    /// <summary>
    /// Strict RFC 1035 parser. Header must represent an authoritative,
    /// nontruncated, nonrecursive successful answer to our exact question.
    /// A compression pointer must point backward and cannot loop.
    /// </summary>
    internal static IReadOnlyList<string> ParseAuthoritativeTxt(
        ReadOnlySpan<byte> packet, ushort transactionId, string expectedOwner)
    {
        if (packet.Length is < 17 or > MaximumDnsPacketBytes ||
            Read16(packet, 0) != transactionId)
            throw new InvalidDataException("DNS transaction mismatch or malformed length");
        var flags = Read16(packet, 2);
        if ((flags & 0x8400) != 0x8400 || // QR and authoritative answer
            (flags & 0x0200) != 0 || // no truncated RRsets
            (flags & 0x780F) != 0 || // QUERY opcode and NOERROR only
            (flags & 0x0100) != 0 || // no recursion requested
            Read16(packet, 4) != 1 ||
            Read16(packet, 6) > 32 || Read16(packet, 8) > 32 ||
            Read16(packet, 10) > 32)
            throw new InvalidDataException("DNS reply is not a bounded authoritative TXT response");

        var cursor = 12;
        if (!string.Equals(ReadName(packet, ref cursor), expectedOwner,
                StringComparison.OrdinalIgnoreCase) ||
            cursor + 4 > packet.Length || Read16(packet, cursor) != 16 ||
            Read16(packet, cursor + 2) != 1)
            throw new InvalidDataException("Authoritative DNS TXT question not echoed exactly");
        cursor += 4;
        var values = new List<string>();
        for (var section = 0; section < 3; section++)
        {
            var count = Read16(packet, 6 + section * 2);
            for (var record = 0; record < count; record++)
            {
                var owner = ReadName(packet, ref cursor);
                if (cursor + 10 > packet.Length)
                    throw new InvalidDataException("Incomplete DNS resource record");
                var type = Read16(packet, cursor);
                var dnsClass = Read16(packet, cursor + 2);
                var rdlen = Read16(packet, cursor + 8);
                cursor += 10;
                if (cursor + rdlen > packet.Length)
                    throw new InvalidDataException("DNS RDATA overruns authoritative answer");
                if (section == 0 && string.Equals(owner, expectedOwner,
                        StringComparison.OrdinalIgnoreCase))
                {
                    if (type != 16 || dnsClass != 1)
                        throw new InvalidDataException("Unexpected alias or non-TXT authoritative record");
                    if (values.Count == 32)
                        throw new InvalidDataException("Too many authoritative TXT values");
                    // RFC 8555 DNS-01: a single 43-byte unpadded SHA-256
                    // base64url character-string. Ignore different values, but
                    // never concatenate unrelated TXT chunks into a fake match.
                    if (rdlen == 44 && packet[cursor] == 43)
                    {
                        var span = packet.Slice(cursor + 1, 43);
                        if (span.IndexOfAnyExceptInRange((byte)0x20, (byte)0x7E) < 0)
                            values.Add(Encoding.ASCII.GetString(span));
                    }
                }
                cursor += rdlen;
            }
        }
        if (cursor != packet.Length)
            throw new InvalidDataException("Trailing bytes after authoritative DNS answer");
        return values;
    }

    private static ushort Read16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16BigEndian(data.Slice(offset, 2));

    private static string ReadName(ReadOnlySpan<byte> packet, ref int cursor)
    {
        var labels = new List<string>(8);
        var pos = cursor;
        var jumped = false;
        var hops = 0;
        var length = 1; // terminal root label
        var offsets = new HashSet<int>();
        while (true)
        {
            if (pos >= packet.Length)
                throw new InvalidDataException("Truncated DNS name");
            var tokenAt = pos;
            var octet = packet[pos++];
            if (octet == 0)
            {
                if (!jumped) cursor = pos;
                return string.Join('.', labels);
            }
            if ((octet & 0xC0) == 0xC0)
            {
                if (pos >= packet.Length)
                    throw new InvalidDataException("Truncated DNS compression pointer");
                var pointer = ((octet & 0x3F) << 8) | packet[pos++];
                if (pointer >= tokenAt || !offsets.Add(pointer) || ++hops > 16)
                    throw new InvalidDataException("Forward or looping DNS compression pointer");
                if (!jumped) { jumped = true; cursor = pos; }
                pos = pointer;
                continue;
            }
            if ((octet & 0xC0) != 0 || octet > 63 ||
                pos + octet > packet.Length || (length += octet + 1) > 255)
                throw new InvalidDataException("Invalid DNS label length");
            for (var i = 0; i < octet; i++)
            {
                var ch = (char)packet[pos + i];
                if (!char.IsAsciiLetterOrDigit(ch) && ch is not ('-' or '_'))
                    throw new InvalidDataException("Invalid DNS response name octet");
            }
            labels.Add(Encoding.ASCII.GetString(packet.Slice(pos, octet)));
            pos += octet;
            if (!jumped) cursor = pos;
        }
    }
}
