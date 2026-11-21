using System.Buffers.Binary;
using GatewayCore.Gslb.Contracts;
using System.Net;
using System.Net.Sockets;
using System.Text;

// Independent DNS wire-format implementation. No recursion, zone transfer,
// or EDNS Client Subnet routing by default.
internal static class DnsWireProtocol
{
    private const ushort A = 1, Ns = 2, Soa = 6, Txt = 16, Aaaa = 28, Ds = 43, Opt = 41, EcsOption = 8;
    private const ushort Rrsig = 46, Nsec = 47, Dnskey = 48, Nsec3 = 50, Nsec3Param = 51;
    private const ushort ClassIn = 1;
    // RFC 6891 response OPT CLASS reports this server's receive capability,
    // while the request's advertised size separately limits UDP response data.
    private const ushort ServerUdpPayloadSize = 1232;
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
        bool tcp, IPAddress? resolverIp = null, AgentHealthReportStore? agentReports = null,
        AuthorityFenceStore? authorityFence = null)
    {
        if (query.Length is < 17 or > 4096) return null;
        var id = BinaryPrimitives.ReadUInt16BigEndian(query);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(query[2..]);
        // DNS queries may set RD, AD or CD, but response-only QR/AA/TC/RA,
        // reserved Z, a nonzero question RCODE and non-QUERY opcodes are not
        // valid requests for this strict authoritative UDP/TCP listener.
        // Drop them before name parsing, health lookups or allocations.
        if ((flags & 0xFECF) != 0) return null;
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
            // RFC 1035 limits the entire wire name (label length octets and
            // terminal root included) to 255 octets, not to 32 labels.
            if (length > 63 || pos + length > query.Length || pos + length - 12 >= 255)
                return null;
            var labelBytes = query.Slice(pos, length);
            // Keep the existing printable-ASCII owner policy; reject unsupported
            // octets before ASCII decoding can silently substitute '?'.
            foreach (var octet in labelBytes)
                if (octet < (byte)'!' || octet > (byte)'~' || octet == (byte)'.')
                    return null;
            var label = Encoding.ASCII.GetString(labelBytes);
            labels.Add(label);
            pos += length;
        }
        if (pos + 4 > query.Length) return null;
        var qtype = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos, 2));
        var qclass = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 2, 2));
        // RFC 6895 reserves QTYPE 0 and QCLASS 0. A zero question
        // is not an unsupported ordinary RR type: reject the malformed
        // frame before zone lookup, signing, or backend-health evaluation.
        if (qtype == 0 || qclass == 0) return null;
        pos += 4;
        var questionEnd = pos;
        var domain = string.Join('.', labels).ToLowerInvariant();

        // A single well-formed EDNS(0) OPT is allowed. Unknown options are deliberately ignored;
        // ECS influences selection only for explicitly enabled zones and trusted resolvers.
        var edns = false;
        var payload = 512;
        var unsupportedEdns = false;
        var dnssecOk = false;
        EcsInput? ecsInput = null;
        var ecsSeen = false;
        var ecsInvalid = false;
        var additionalCount = BinaryPrimitives.ReadUInt16BigEndian(query[10..]);
        if (additionalCount > 1) return null;
        if (additionalCount == 1)
        {
            if (pos + 11 > query.Length || query[pos++] != 0) return null;
            if (BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos, 2)) != Opt) return null;
            var advertised = BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos + 2, 2));
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(query.Slice(pos + 4, 4));
            // RFC 6891: the upper eight bits of OPT TTL carry the
            // extended response code and MUST be zero in a request.
            // Treat a nonzero client-supplied response code as malformed
            // instead of normalizing it into a valid authoritative answer.
            if ((ttl & 0xFF000000u) != 0) return null;
            dnssecOk = (ttl & 0x00008000u) != 0;
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
                    // Malformed or duplicate ECS must not influence routing. Keep
                    // answering the DNS question using resolver-source policy, but
                    // never reflect an invalid subnet back to the recursive resolver.
                    if (ecsSeen)
                    {
                        ecsInput = null;
                        ecsInvalid = true;
                    }
                    else
                    {
                        ecsSeen = true;
                        if (!TryReadEcs(query.Slice(pos, optionLength), out ecsInput))
                            ecsInvalid = true;
                    }
                    if (ecsInvalid) ecsInput = null;
                }
                pos += optionLength;
            }
            edns = true;
            payload = Math.Min(Math.Clamp((int)advertised, 512, ushort.MaxValue), ServerUdpPayloadSize);
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

        var answers = new List<DnsResource>();
        var authority = new List<DnsResource>();
        var extra = new List<DnsResource>();
        var responseEcs = new List<byte>();
        var rcode = 0;
        string? denialName = null;
        var denialIsNxDomain = false;
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
            var nsHostExists = zone.NameServers.Any(n =>
                n.Host.Equals(domain, StringComparison.OrdinalIgnoreCase));
            var ns = zone.NameServers.FirstOrDefault(n =>
                n.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) && n.RecordType == qtype);
            var txt = zone.AcmeTxtRecords.Where(record =>
                record.Host.Equals(domain, StringComparison.OrdinalIgnoreCase)).ToArray();
            var txtOwnerExists = txt.Length != 0;
            // A configured address below this name makes it an existing empty
            // non-terminal. NXDOMAIN would incorrectly deny its entire subtree
            // to caching resolvers (RFC 8020 section 3.1).
            var emptyNonTerminal = !atApex && !nsHostExists && !txtOwnerExists &&
                (zone.NameServers.Any(n =>
                    n.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)) ||
                 zone.Delegations.Any(cut =>
                    cut.Name.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)) ||
                 zone.AcmeTxtRecords.Any(record =>
                    record.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase)));
            if (delegation is not null && domain.Equals(delegation.Name, StringComparison.OrdinalIgnoreCase) && qtype == Ds)
            {
                if (delegation.DsRecords.Length > 0)
                    answers.AddRange(delegation.DsRecords.Select(ds => new DnsResource(
                        delegation.Name, Ds, (uint)zone.Ttl, ds.Rdata)));
                else
                {
                    // No child DS is configured. A signed parent proves DS absence
                    // with NSEC; unsigned parents retain the historical SOA-only response.
                    AddNegativeSoa();
                    denialName = delegation.Name;
                }
            }
            else if (delegation is not null)
            {
                authoritativeAnswer = false;
                var delegatedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var server in delegation.NameServers)
                {
                    // An NS RR is per hostname, but a single in-domain server
                    // can have both A and AAAA glue. Keep one NS value while
                    // returning every configured address RRset for that name.
                    if (delegatedNames.Add(server.Host))
                        authority.Add(new DnsResource(delegation.Name, Ns, (uint)zone.Ttl, WireName(server.Host)));
                    if (server.Host.Equals(delegation.Name, StringComparison.OrdinalIgnoreCase) ||
                        server.Host.EndsWith("." + delegation.Name, StringComparison.OrdinalIgnoreCase))
                        extra.Add(new DnsResource(server.Host, server.RecordType, (uint)zone.Ttl,
                            server.Address.GetAddressBytes()));
                }
                // DNSSEC referrals carry the parent-signed DS RRset (or signed
                // proof of its absence) in authority. Delegation NS itself is
                // intentionally unsigned by the parent.
                if (dnssecOk && zone.Dnssec is { } parentSigner)
                {
                    if (delegation.DsRecords.Length > 0)
                    {
                        var dsRrset = delegation.DsRecords.Select(ds => new DnsResource(
                            delegation.Name, Ds, (uint)zone.Ttl, ds.Rdata)).ToArray();
                        authority.AddRange(dsRrset);
                        authority.AddRange(parentSigner.SignRrsets(delegation.Name, Ds,
                            (uint)zone.Ttl, dsRrset.Select(r => r.Rdata).ToArray()));
                    }
                    else authority.AddRange(parentSigner.DenialProof(delegation.Name, nxDomain: false));
                }
            }
            else if (!atApex && !nsHostExists && !txtOwnerExists)
            {
                rcode = emptyNonTerminal ? 0 : 3; // NODATA vs true NXDOMAIN
                AddNegativeSoa();
                denialName = domain;
                denialIsNxDomain = !emptyNonTerminal;
            }
            else if (zone.Dnssec is { } signer && qtype == Dnskey && atApex)
            {
                answers.AddRange(signer.DnsKeys);
            }
            else if (zone.Dnssec is { } nsecSigner && qtype == Nsec && nsecSigner.NsecAt(domain) is { } nsec)
            {
                answers.Add(nsec);
            }
            else if (zone.Dnssec is { UsesNsec3: true } nsec3Signer &&
                qtype == Nsec3 && nsec3Signer.Nsec3At(domain) is { } nsec3)
            {
                answers.Add(nsec3);
            }
            else if (zone.Dnssec is { UsesNsec3: true, Nsec3Param: { } nsec3param } &&
                qtype == Nsec3Param && atApex)
            {
                answers.Add(nsec3param);
            }
            else if (zone.Dnssec is { } sigSigner && qtype == Rrsig)
            {
                answers.AddRange(sigSigner.SignaturesAt(domain));
                if (domain == apex)
                    foreach (var site in zone.Sites)
                        answers.AddRange(sigSigner.SignRrsets(domain,
                            site.Address.AddressFamily == AddressFamily.InterNetwork ? A : Aaaa,
                            (uint)zone.Ttl, [site.Address.GetAddressBytes()]));
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
                    denialName = apex;
                }
                else
                {
                    var now = Environment.TickCount64;
                    var eligible = configured.Where(s => !s.AdministrativelyQuarantined &&
                        Volatile.Read(ref s.Healthy) == 1 &&
                        (s.Validators.Length == 0 || now < Volatile.Read(ref s.ValidatorDeadline)) &&
                        (s.RequiredAgentIds.Length == 0 ||
                         (agentReports?.IsHealthy(apex!, s.AgentSiteId!, now) ?? false)) &&
                        (authorityFence is null || authorityFence.IsPeerEligible(
                            apex!, s.AuthorityFenceSiteId!, now))).ToArray();
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
                            EcsInput? selectedEcs = null;
                            var selectedEcsScope = 0;
                            if (zone.EnableEcsGeoRouting && ecsInput is not null &&
                                zone.TrustedEcsResolvers?.RegionFor(resolverIp) == "trusted")
                            {
                                var scopedInput = ApplyEcsPrivacyLimit(ecsInput);
                                var ecsRegion = zone.CidrTable?.RegionForEcs(
                                    scopedInput.Address, scopedInput.SourcePrefix);
                                if (ecsRegion is { } match)
                                {
                                    region = match.Region;
                                    selectedEcs = scopedInput;
                                    selectedEcsScope = match.PrefixLength;
                                }
                            }
                            if (region is not null)
                            {
                                var regional = eligible.Where(s =>
                                    string.Equals(s.Region,region,
                                        StringComparison.OrdinalIgnoreCase)).ToArray();
                                if (regional.Length > 0)
                                {
                                    eligible = regional;
                                    // The ECS region is not the selected backend
                                    // when all sites in it are unhealthy. Do not
                                    // advertise an inapplicable cache scope.
                                    if (selectedEcs is not null)
                                        AddEcsResponse(selectedEcs, selectedEcsScope, responseEcs);
                                }
                            }
                        }
                        else if (zone.RoutingPolicy == "GeoIpEcs" &&
                            zone.EnableEcsGeoRouting && ecsInput is not null &&
                            zone.TrustedEcsResolvers?.RegionFor(resolverIp) == "trusted")
                        {
                            var scopedInput = ApplyEcsPrivacyLimit(ecsInput);
                            var geoRegion = zone.GeoIpTable?.RegionForEcs(
                                scopedInput.Address, scopedInput.SourcePrefix);
                            if (geoRegion is { } match)
                            {
                                var regional = eligible.Where(s =>
                                    string.Equals(s.Region, match.Region,
                                        StringComparison.OrdinalIgnoreCase)).ToArray();
                                if (regional.Length > 0)
                                {
                                    eligible = regional;
                                    AddEcsResponse(scopedInput, match.PrefixLength, responseEcs);
                                }
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
                            answers.Add(new DnsResource(domain, qtype, (uint)zone.Ttl, chosen.Address.GetAddressBytes()));
                    }
                }
            }
            else if (qtype == Txt && txtOwnerExists)
                answers.AddRange(txt.Select(record =>
                    new DnsResource(domain, Txt, (uint)zone.Ttl, record.Rdata)));
            else if (ns is not null && qtype == ns.RecordType)
                answers.Add(new DnsResource(domain, ns.RecordType, (uint)zone.Ttl, ns.Address.GetAddressBytes()));
            else if (qtype == Soa && atApex && zone.NameServers.Length != 0)
                answers.Add(SoaRecord(apex!, zone));
            else if (qtype == Ns && atApex && zone.NameServers.Length != 0)
            {
                var uniqueServerHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var server in zone.NameServers)
                {
                    if (uniqueServerHosts.Add(server.Host))
                        answers.Add(new DnsResource(apex!, Ns, (uint)zone.Ttl, WireName(server.Host)));
                    if (server.Host.EndsWith("." + apex!, StringComparison.OrdinalIgnoreCase))
                        extra.Add(new DnsResource(server.Host, server.RecordType, (uint)zone.Ttl, server.Address.GetAddressBytes()));
                }
            }
            else
            {
                AddNegativeSoa(); // NODATA (including AAAA, ANY and unsupported QTYPE)
                denialName = domain;
            }
        }

        void AddNegativeSoa()
        {
            if (zone is not null && zone.NameServers.Length != 0 && apex is not null)
                authority.Add(SoaRecord(apex, zone));
        }

        if (!unsupportedEdns && zone?.Dnssec is { } dnssec && authoritativeAnswer)
        {
            if (dnssecOk)
            {
                AddRrsetSignatures(answers, dnssec);
                AddRrsetSignatures(authority, dnssec);
                if (denialName is not null)
                    authority.AddRange(dnssec.DenialProof(denialName, denialIsNxDomain));
            }
            else if (qtype is Nsec or Nsec3 or Nsec3Param && answers.Count > 0)
            {
                // Denial-chain records remain queryable without DO; RRSIGs are only
                // added when the client explicitly requests DNSSEC with DO.
            }
        }

        static void AddRrsetSignatures(List<DnsResource> section, DnssecZoneSigner signer)
        {
            var signatures = section.Where(r => r.Type != Rrsig)
                .GroupBy(r => (r.Owner, r.Type))
                .SelectMany(set => signer.SignRrsets(set.Key.Owner, set.Key.Type, set.First().Ttl,
                    set.Select(r => r.Rdata).ToArray())).ToArray();
            section.AddRange(signatures);
        }

        // Constrain untrusted UDP response amplification and use TC for complete TCP retry.
        var signedEdnsResponse = dnssecOk && zone?.Dnssec is not null && edns && !unsupportedEdns;
        var budget = tcp ? 65535 : signedEdnsResponse
            ? payload
            : Math.Min(payload, Math.Max(128, query.Length * 4));
        var reserve = edns ? 11 + responseEcs.Count : 0;
        var bytes = new List<byte>(Math.Min(512, budget));
        bytes.AddRange(new byte[12]);
        bytes.AddRange(query.Slice(12, questionEnd - 12).ToArray());
        var an = 0; var nsCount = 0; var ar = 0; var truncated = false;
        if (!unsupportedEdns)
        {
            foreach (var section in new[] { answers, authority, extra })
            {
                // RFC 2181: never emit a partial RRset. All records are IN
                // class; owner names are case-insensitive. Preserve first-set
                // order and member order, retaining the existing conservative
                // TC policy and OPT reservation (including for glue).
                foreach (var rrset in section.GroupBy(record =>
                    (record.Owner.ToLowerInvariant(), record.Type)))
                {
                    var wires = rrset.Select(record => WireRecord(record, domain)).ToArray();
                    if (bytes.Count + wires.Sum(wire => wire.Length) + reserve > budget)
                    {
                        truncated = true;
                        break;
                    }
                    foreach (var wire in wires) bytes.AddRange(wire);
                    if (ReferenceEquals(section, answers)) an += wires.Length;
                    else if (ReferenceEquals(section, authority)) nsCount += wires.Length;
                    else ar += wires.Length;
                }
                if (truncated) break;
            }
        }
        if (edns)
        {
            bytes.Add(0); // root owner
            Write16(bytes, Opt);
            Write16(bytes, ServerUdpPayloadSize);
            var optFlags = dnssecOk && zone?.Dnssec is not null ? 0x00008000u : 0u;
            Write32(bytes, unsupportedEdns ? 0x01000000u : optFlags); // BADVERS or DNSSEC OK
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

        // RFC 7871 encodes only the source-prefix bytes, with every unused bit
        // in the final byte set to zero. Reject noncanonical padding instead of
        // silently turning malformed ECS into a valid steering signal.
        var partialPrefix = sourcePrefix % 8;
        if (partialPrefix != 0)
        {
            var unusedMask = (1 << (8 - partialPrefix)) - 1;
            if ((data[^1] & unusedMask) != 0) return false;
        }

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

    private static DnsResource SoaRecord(string apex, SiteGroup zone)
    {
        var bytes = new List<byte>();
        bytes.AddRange(WireName(zone.NameServers[0].Host));
        bytes.AddRange(WireName(zone.SoaContact));
        Write32(bytes, zone.SoaSerial);
        Write32(bytes, 60); // refresh
        Write32(bytes, 30); // retry
        Write32(bytes, 3600); // expire
        Write32(bytes, (uint)zone.Ttl); // negative-cache minimum
        return new DnsResource(apex, Soa, (uint)zone.Ttl, bytes.ToArray());
    }

    private static byte[] WireRecord(DnsResource value, string originalQuestion)
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
