using System.Buffers.Binary;
using GatewayCore.Gslb.Contracts;
using System.Net;
using System.Net.Sockets;
using System.Text;

// Independent DNS wire-format implementation. External GSLB references are reviewed
// only as architectural context; no AGPL source is included. No recursion,
// DNSSEC, EDNS Client Subnet routing by default, or zone transfer.
internal static class DnsWireProtocol
{
    private const ushort A = 1, Ns = 2, Soa = 6, Aaaa = 28, Ds = 43, Opt = 41, EcsOption = 8;
    private const ushort ClassIn = 1;
    private sealed record Resource(string Owner, ushort Type, uint Ttl, byte[] Rdata);
    private sealed record EcsInput(ushort Family, int SourcePrefix, IPAddress Address);

    public static bool ValidName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 253) return false;
        var labels = name.TrimEnd('.').Split('.');
        return labels.Length > 0 && labels.All(label =>
            label.Length is >= 1 and <= 63 &&
            label.All(ch => ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_') &&
            label[0] != '-' && label[^1] != '-');
    }

    public static byte[]? Build(ReadOnlySpan<byte> query, IReadOnlyDictionary<string, SiteGroup> zones,
        bool tcp, IPAddress? resolverIp = null, AgentHealthReportStore? agentReports = null)
    {
        if (query.Length is < 17 or > 4096) return null;
        var id = BinaryPrimitives.ReadUInt16BigEndian(query);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(query[2..]);
        if ((flags & 0xF800) != 0 || (flags & 0x7800) != 0) return null; // QR or opcode
        if (BinaryPrimitives.ReadUInt16BigEndian(query[4..]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(query[6..]) != 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(query[8..]) != 0) return null;

        var pos = 12;
        var labels = new List<string>(8);
        while (true)
        {
            if (pos >= query.Length) return null;
            var length = query[pos++];
            if (length == 0) break;
            if (length > 63 || labels.Count >= 32 || pos + length > query.Length) return null;
            var label = Encoding.ASCII.GetString(query.Slice(pos, length));
            if (label.Any(ch => ch < '!' || ch > '~' || ch == '.')) return null;
            labels.Add(label);
            pos += length;
        }
        if (pos + 4 > query.Length) return null;
        var qtype = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos, 2));
        var qclass = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 2, 2));
        pos += 4;
        var questionEnd = pos;
        var domain = string.Join('.', labels).ToLowerInvariant();

        // A single well-formed EDNS(0) OPT is allowed. Unknown options are deliberately ignored;
        // ECS influences selection only for explicitly enabled zones and trusted resolvers.
        var edns = false;
        var payload = 512;
        var unsupportedEdns = false;
        EcsInput? ecsInput = null;
        var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(query[10..]);
        if (additionalCount > 1) return null;
        if (additionalCount == 1)
        {
            if (pos + 11 > query.Length || query[pos++] != 0) return null;
            if (BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos, 2)) != Opt) return null;
            var advertised = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 2, 2));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(query.Slice(pos + 4, 4));
            var rdlen = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 8, 2));
            pos += 10;
            if (pos + rdlen != query.Length) return null;
            var optionEnd = pos + rdlen;
            while (pos < optionEnd)
            {
                if (pos + 4 > optionEnd) return null;
                var optionCode = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos, 2));
                var optionLength = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 2, 2));
                pos += 4;
                if (pos + optionLength > optionEnd) return null;
                if (optionCode == EcsOption)
                {
                    if (ecsInput is not null || !TryReadEcs(query.Slice(pos, optionLength), out ecsInput))
                        return null;
                }
                pos += optionLength;
            }
            edns = true;
            payload = Math.Clamp((int)advertised, 512, 1232);
            unsupportedEdns = ((ttl >> 16) & 0xFF) != 0;
        }
        if (pos != query.Length) return null;

        SiteGroup? zone = null;
        string? apex = null;
        foreach (var entry in zones)
        {
            if ((domain == entry.Key || domain.EndsWith("." + entry.Key, StringComparison.Ordinal)) &&
                (apex is null || entry.Key.Length > apex.Length))
            {
                apex = entry.Key;
                zone = entry.Value;
            }
        }

        var answers = new List<Resource>();
        var authority = new List<Resource>();
        var extra = new List<Resource>();
        var responseEcs = new List<byte>();
        var rcode = 0;
        var authoritativeAnswer = zone is not null;
        if (unsupportedEdns) rcode = 0; // extended RCODE BADVERS is carried in OPT
        else if (zone is null) rcode = 5; // REFUSED for names outside explicitly hosted zones
        else if (qclass != ClassIn) rcode = 5;
        else
        {
            var atApex = domain == apex;
            var delegation = zone.Delegations
                .Where(cut => domain.Equals(cut.Name, StringComparison.OrdinalIgnoreCase) ||
                    domain.EndsWith("." + cut.Name, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(cut => cut.Name.Length)
                .FirstOrDefault();
            var ns = zone.NameServers.FirstOrDefault(n =>
                n.Host.Equals(domain, StringComparison.OrdinalIgnoreCase));
            // A configured address below this name makes it an existing empty
            // non-terminal. NXDOMAIN would incorrectly deny its entire subtree
            // to caching resolvers (RFC 8020 section 3.1).
            var emptyNonTerminal = !atApex && ns is null &&
                zone.NameServers.Any(n =>
                    n.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
            if (delegation is not null && domain.Equals(delegation.Name, StringComparison.OrdinalIgnoreCase) && qtype == Ds)
            {
                // DNSSEC is not implemented: an unsigned parent has no DS RRset
                // at this cut, so return the parent's negative SOA, not a referral.
                AddNegativeSoa();
            }
            else if (delegation is not null)
            {
                authoritativeAnswer = false;
                foreach (var server in delegation.NameServers)
                {
                    authority.Add(new Resource(delegation.Name, Ns, (uint)zone.Ttl, WireName(server.Host)));
                    if (server.Host.Equals(delegation.Name, StringComparison.OrdinalIgnoreCase) ||
                        server.Host.EndsWith("." + delegation.Name, StringComparison.OrdinalIgnoreCase))
                        extra.Add(new Resource(server.Host, server.RecordType, (uint)zone.Ttl,
                            server.Address.GetAddressBytes()));
                }
            }
            else if (!atApex && ns is null)
            {
                rcode = emptyNonTerminal ? 0 : 3; // NODATA vs true NXDOMAIN
                AddNegativeSoa();
            }
            else if ((qtype == A || qtype == Aaaa) && atApex)
            {
                // A and AAAA have separate backend-eligibility pools. When a family
                // is not configured the authoritative answer is NODATA + negative
                // SOA, never SERVFAIL or a mismatched address family.
                var family = qtype == A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                var configured = zone.Sites.Where(s => s.Address.AddressFamily == family).ToArray();
                if (configured.Length == 0)
                {
                    AddNegativeSoa();
                }
                else
                {
                    var now = Environment.TickCount64;
                    var eligible = configured.Where(s => !s.AdministrativelyQuarantined &&
                        Volatile.Read(ref s.Healthy) == 1 &&
                        (s.Validators.Length == 0 || now < Volatile.Read(ref s.ValidatorDeadline)) &&
                        (s.RequiredAgentIds.Length == 0 ||
                         (agentReports?.IsHealthy(apex!, s.AgentSiteId!, now) ?? false))).ToArray();
                    if (eligible.Length == 0)
                    {
                        if (zone.FailClosedWhenAllSitesDown) rcode = 2; // SERVFAIL
                        else
                        {
                            // Availability-first fallback may include failed probes,
                            // but administrative quarantine always remains a veto.
                            eligible = configured.Where(s => !s.AdministrativelyQuarantined).ToArray();
                            if (eligible.Length == 0) rcode = 2;
                        }
                    }
                    if (eligible.Length > 0 && rcode == 0)
                    {
                        // CIDR mapping uses only the direct DNS resolver socket
                        // source, NOT forwarded headers or untrusted EDNS ECS.
                        // If this region has no healthy endpoint, fall back to the
                        // other healthy sites before applying the weighted policy.
                        if (zone.RoutingPolicy == "CidrRegion")
                        {
                            var region = zone.CidrTable?.RegionFor(resolverIp);
                            if (zone.EnableEcsGeoRouting && ecsInput is not null &&
                                zone.TrustedEcsResolvers?.RegionFor(resolverIp) == "trusted")
                            {
                                var scopedInput = ApplyEcsPrivacyLimit(ecsInput);
                                var ecsRegion = zone.CidrTable?.RegionForEcs(
                                    scopedInput.Address, scopedInput.SourcePrefix);
                                if (ecsRegion is { } match)
                                {
                                    region = match.Region;
                                    AddEcsResponse(scopedInput, match.PrefixLength, responseEcs);
                                }
                            }
                            if (region is not null)
                            {
                                var regional = eligible.Where(s =>
                                    string.Equals(s.Region,region,
                                        StringComparison.OrdinalIgnoreCase)).ToArray();
                                if (regional.Length > 0) eligible = regional;
                            }
                        }
                        Site? chosen = null;
                        if (zone.RoutingPolicy == "Failover")
                        {
                            var bestPriority = eligible.Min(s => s.Priority);
                            chosen = eligible.First(s => s.Priority == bestPriority);
                        }
                        else
                        {
                            if (zone.RoutingPolicy == "WeightedFailover")
                            {
                                // Group only the family-correct eligible pool. Never
                                // send overflow into lower-priority groups while a
                                // higher-priority member remains healthy.
                                var priority = eligible.Min(s => s.Priority);
                                eligible = eligible.Where(s => s.Priority == priority).ToArray();
                            }
                            if (zone.RoutingPolicy == "ObservedLatency")
                            {
                                // This is local DNS-node -> probe-endpoint latency,
                                // NOT client-perceived latency or cross-region RTT.
                                // A single missing/stale sample causes weighted fallback.
                                var latencyNow = Environment.TickCount64;
                                var measured = new List<(Site Site, double Ms)>();
                                foreach (var site in eligible)
                                {
                                    if (!site.Latency.TryRead(latencyNow,
                                            SiteGroup.LatencyMinimumSamples,
                                            SiteGroup.LatencyMaximumAgeMs, out var ms))
                                    {
                                        measured.Clear();
                                        break;
                                    }
                                    measured.Add((site, ms));
                                }
                                if (measured.Count == eligible.Length)
                                {
                                    var best = measured.OrderBy(x => x.Ms).First();
                                    // Avoid switching affinity on sub-15% probe jitter.
                                    var runnerUp = measured.OrderBy(x => x.Ms).Skip(1).FirstOrDefault();
                                    if (measured.Count == 1 ||
                                        runnerUp.Ms >= best.Ms * 1.15)
                                        chosen = best.Site;
                                }
                            }
                            if (chosen is null)
                            {
                                // Historic IPv4 weighted ordering/semantics remain unchanged.
                                var total = eligible.Sum(s => s.Weight);
                                var ticket = (int)((ulong)Interlocked.Increment(ref zone.Counter) % (ulong)total);
                                foreach (var site in eligible)
                                {
                                    ticket -= site.Weight;
                                    if (ticket < 0) { chosen = site; break; }
                                }
                            }
                        }
                        if (chosen is not null)
                            answers.Add(new Resource(domain, qtype, (uint)zone.Ttl, chosen.Address.GetAddressBytes()));
                    }
                }
            }
            else if (ns is not null && qtype == ns.RecordType)
                answers.Add(new Resource(domain, ns.RecordType, (uint)zone.Ttl, ns.Address.GetAddressBytes()));
            else if (qtype == Soa && atApex && zone.NameServers.Length != 0)
                answers.Add(SoaRecord(apex!, zone));
            else if (qtype == Ns && atApex && zone.NameServers.Length != 0)
            {
                foreach (var server in zone.NameServers)
                {
                    answers.Add(new Resource(apex!, Ns, (uint)zone.Ttl, WireName(server.Host)));
                    if (server.Host.EndsWith("." + apex!, StringComparison.OrdinalIgnoreCase))
                        extra.Add(new Resource(server.Host, server.RecordType, (uint)zone.Ttl, server.Address.GetAddressBytes()));
                }
            }
            else AddNegativeSoa(); // NODATA (including AAAA, ANY and unsupported QTYPE)
        }

        void AddNegativeSoa()
        {
            if (zone is not null && zone.NameServers.Length != 0 && apex is not null)
                authority.Add(SoaRecord(apex, zone));
        }

        // Do not send EDNS OPT with DO bit: this engine has no DNSSEC signatures.
        // Constrain untrusted UDP response amplification and use TC for complete TCP retry.
        var budget = tcp ? 65535 : Math.Min(payload, Math.Max(128, query.Length * 4));
        var reserve = edns ? 11 + responseEcs.Count : 0;
        var bytes = new List<byte>(Math.Min(512, budget));
        bytes.AddRange(new byte[12]);
        bytes.AddRange(query.Slice(12, questionEnd - 12).ToArray());
        var an = 0; var nsCount = 0; var ar = 0; var truncated = false;
        if (!unsupportedEdns)
        {
            foreach (var section in new[] { answers, authority, extra })
            {
                foreach (var record in section)
                {
                    var wire = WireRecord(record, domain);
                    if (bytes.Count + wire.Length + reserve > budget)
                    {
                        truncated = true;
                        break;
                    }
                    bytes.AddRange(wire);
                    if (ReferenceEquals(section, answers)) an++;
                    else if (ReferenceEquals(section, authority)) nsCount++;
                    else ar++;
                }
                if (truncated) break;
            }
        }
        if (edns)
        {
            bytes.Add(0); // root owner
            Write16(bytes, Opt);
            Write16(bytes, (ushort)payload);
            Write32(bytes, unsupportedEdns ? 0x01000000u : 0u); // BADVERS or no ext rcode
            Write16(bytes, checked((ushort)responseEcs.Count));
            bytes.AddRange(responseEcs); // unknown options and disabled/ambiguous ECS are never echoed
            ar++;
        }
        var reply = bytes.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(0, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2, 2),
            (ushort)(0x8000 | (authoritativeAnswer ? 0x0400 : 0) |
                (truncated ? 0x0200 : 0) | (flags & 0x0100) | rcode));
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(6, 2), (ushort)an);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(8, 2), (ushort)nsCount);
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(10, 2), (ushort)ar);
        return reply;
    }

    private static bool TryReadEcs(ReadOnlySpan<byte> data, out EcsInput? ecs)
    {
        ecs = null;
        if (data.Length < 4) return false;
        var family = BinaryPrimitives.ReadUInt16BigEndian(data);
        var sourcePrefix = data[2];
        var scopePrefix = data[3];
        var addressLength = family switch
        {
            1 when sourcePrefix <= 32 => 4,
            2 when sourcePrefix <= 128 => 16,
            _ => 0,
        };
        if (addressLength == 0 || scopePrefix != 0 ||
            data.Length != 4 + (sourcePrefix + 7) / 8)
            return false;

        var addressBytes = new byte[addressLength];
        data[4..].CopyTo(addressBytes);
        MaskNetwork(addressBytes, sourcePrefix);
        ecs = new EcsInput(family, sourcePrefix, new IPAddress(addressBytes));
        return true;
    }

    private static EcsInput ApplyEcsPrivacyLimit(EcsInput input)
    {
        // Do not use client subnets more precise than /24 IPv4 or /56 IPv6.
        var maxPrefix = input.Family == 1 ? 24 : 56;
        var prefix = Math.Min(input.SourcePrefix, maxPrefix);
        var bytes = input.Address.GetAddressBytes();
        MaskNetwork(bytes, prefix);
        return new EcsInput(input.Family, prefix, new IPAddress(bytes));
    }

    private static void AddEcsResponse(EcsInput input, int scopePrefix, List<byte> response)
    {
        var sourcePrefix = input.SourcePrefix;
        var addressLength = (sourcePrefix + 7) / 8;
        Write16(response, EcsOption);
        Write16(response, checked((ushort)(4 + addressLength)));
        Write16(response, input.Family);
        response.Add(checked((byte)sourcePrefix));
        response.Add(checked((byte)Math.Min(scopePrefix, sourcePrefix)));
        response.AddRange(input.Address.GetAddressBytes().Take(addressLength));
    }

    private static void MaskNetwork(byte[] address, int bits)
    {
        var full = bits / 8;
        var partial = bits % 8;
        if (partial != 0)
        {
            address[full] &= (byte)(0xFF << (8 - partial));
            full++;
        }
        Array.Clear(address, full, address.Length - full);
    }

    private static Resource SoaRecord(string apex, SiteGroup zone)
    {
        var bytes = new List<byte>();
        bytes.AddRange(WireName(zone.NameServers[0].Host));
        bytes.AddRange(WireName(zone.SoaContact));
        Write32(bytes, zone.SoaSerial);
        Write32(bytes, 60); // refresh
        Write32(bytes, 30); // retry
        Write32(bytes, 3600); // expire
        Write32(bytes, (uint)zone.Ttl); // negative-cache minimum
        return new Resource(apex, Soa, (uint)zone.Ttl, bytes.ToArray());
    }

    private static byte[] WireRecord(Resource value, string originalQuestion)
    {
        var bytes = new List<byte>();
        if (value.Owner == originalQuestion) { bytes.Add(0xC0); bytes.Add(0x0C); }
        else bytes.AddRange(WireName(value.Owner));
        Write16(bytes, value.Type);
        Write16(bytes, ClassIn);
        Write32(bytes, value.Ttl);
        Write16(bytes, checked((ushort)value.Rdata.Length));
        bytes.AddRange(value.Rdata);
        return bytes.ToArray();
    }

    private static byte[] WireName(string domain)
    {
        var bytes = new List<byte>();
        foreach (var label in domain.TrimEnd('.').Split('.'))
        {
            bytes.Add(checked((byte)label.Length));
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private static void Write16(List<byte> bytes, ushort value)
    {
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }
    private static void Write32(List<byte> bytes, uint value)
    {
        bytes.Add((byte)(value >> 24));
        bytes.Add((byte)(value >> 16));
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }
}
