using System.Security.Cryptography;
using System.Text.Json;

/// <summary>Canonical digest over routing, health and external-observer trust policy shared by both authorities.</summary>
internal static class AuthorityFenceFingerprint
{
    public static string Compute(DnsZone[] zones, AgentReportServerConfig? agentReports,
        int probeIntervalSeconds = 1, int maxConcurrentHealthProbes = 1,
        IReadOnlyDictionary<string, DnssecZoneSigner>? loadedSigners = null,
        GeoIpAuthorityIdentity? geoIpIdentity = null,
        AgentHealthReportStore? loadedAgentStore = null)
    {
        // Never claim equivalent observer trust based on rereading a PEM
        // after the running store has imported a different key.
        if ((agentReports is null) != (loadedAgentStore is null))
            throw new InvalidDataException("Authority fingerprint requires the loaded observer trust store");
        var geoRouting = zones.Any(zone => zone.RoutingPolicy == "GeoIpEcs");
        if (geoRouting && (geoIpIdentity is null ||
            zones.Any(zone => zone.RoutingPolicy == "GeoIpEcs" &&
                (zone.GeoCountryRoutes is { Length: > 0 } && geoIpIdentity.CountrySha256 is null ||
                 zone.GeoAsnRoutes is { Length: > 0 } && geoIpIdentity.AsnSha256 is null))))
            throw new InvalidDataException("GeoIP authority fingerprint requires loaded database identity");
        // Fingerprint the signer actually serving this zone, not a second
        // read of mutable PEM paths. DS material is public and binds keys
        // and rollover roles without exposing private key bytes.
        string[] DnssecKeys(DnsZone zone)
        {
            var name = zone.Name.TrimEnd('.').ToLowerInvariant();
            var enabled = !string.IsNullOrWhiteSpace(zone.DnssecPrivateKeyPath);
            if (loadedSigners is not null && loadedSigners.TryGetValue(name, out var signer))
            {
                if (!enabled) throw new InvalidDataException("Unexpected loaded DNSSEC signer");
                return signer.ParentDsMaterial.Select(key =>
                    key.Phase + ":" + Convert.ToHexString(key.Ds.Rdata))
                    .Order(StringComparer.Ordinal).ToArray();
            }
            if (enabled) throw new InvalidDataException("Authority fingerprint requires the loaded DNSSEC signer");
            return [];
        }
        var trustPolicy = agentReports is null ? null : new
        {
            agentReports.MaxTtlSeconds,
            agentReports.MaxAgeSeconds,
            agentReports.MaxClockSkewSeconds,
            agentReports.MaxReportsPerMinute,
            RevokedPins = (agentReports.RevokedCertificateSha256 ?? []).Select(pin => pin.ToUpperInvariant())
                .Order(StringComparer.Ordinal).ToArray(),
            Agents = loadedAgentStore!.GetLoadedTrustIdentity()
        };
        var canonical = zones.OrderBy(zone => zone.Name.TrimEnd('.'), StringComparer.OrdinalIgnoreCase)
            .Select(zone => new
            {
                Name = zone.Name.TrimEnd('.').ToLowerInvariant(),
                zone.TtlSeconds,
                zone.FailClosedWhenAllSitesDown,
                zone.FailureThreshold,
                zone.SuccessThreshold,
                zone.SoaSerial,
                SoaPrimary = zone.NameServers?.FirstOrDefault()?.Host.TrimEnd('.').ToLowerInvariant(),
                DnssecKeys = DnssecKeys(zone),
                DnssecDenialMode = (zone.DnssecDenialMode ?? "Nsec").ToUpperInvariant(),
                DnssecNsec3SaltHex = zone.DnssecNsec3SaltHex?.ToUpperInvariant(),
                DnssecNsec3Iterations = zone.DnssecNsec3Iterations ?? 0,
                SoaContact = (zone.SoaContact ?? ("hostmaster." + zone.Name.TrimEnd('.')))
                    .TrimEnd('.').ToLowerInvariant(),
                zone.RoutingPolicy,
                zone.EnableEcsGeoRouting,
                TrustedEcsResolverCidrs = (zone.TrustedEcsResolverCidrs ?? []).Order(StringComparer.Ordinal).ToArray(),
                CidrRoutes = (zone.CidrRoutes ?? []).OrderBy(row => row.Cidr, StringComparer.Ordinal)
                    .Select(row => new { row.Cidr, Region = row.Region.ToLowerInvariant() }).ToArray(),
                GeoCountryRoutes = (zone.GeoCountryRoutes ?? []).OrderBy(row => row.CountryCode, StringComparer.Ordinal)
                    .Select(row => new { Country = row.CountryCode.ToUpperInvariant(), Region = row.Region.ToLowerInvariant() }).ToArray(),
                GeoAsnRoutes = (zone.GeoAsnRoutes ?? []).OrderBy(row => row.Asn)
                    .Select(row => new { row.Asn, Region = row.Region.ToLowerInvariant() }).ToArray(),
                NameServers = (zone.NameServers ?? []).OrderBy(row => row.Host, StringComparer.OrdinalIgnoreCase)
                    .Select(row => new { Host = row.Host.TrimEnd('.').ToLowerInvariant(), row.Address }).ToArray(),
                Delegations = (zone.Delegations ?? []).OrderBy(cut => cut.Name.TrimEnd('.'),
                        StringComparer.OrdinalIgnoreCase)
                    .Select(cut => new
                    {
                        Name = cut.Name.TrimEnd('.').ToLowerInvariant(),
                        NameServers = cut.NameServers.OrderBy(ns => ns.Host.TrimEnd('.'),
                                StringComparer.OrdinalIgnoreCase).ThenBy(ns => ns.Address, StringComparer.Ordinal)
                            .Select(ns => new { Host = ns.Host.TrimEnd('.').ToLowerInvariant(), ns.Address })
                            .ToArray(),
                        DsRecords = (cut.DsRecords ?? []).OrderBy(ds => ds.KeyTag)
                            .ThenBy(ds => ds.Algorithm).ThenBy(ds => ds.DigestType)
                            .ThenBy(ds => ds.DigestHex.ToUpperInvariant(), StringComparer.Ordinal)
                            .Select(ds => new { ds.KeyTag, ds.Algorithm, ds.DigestType,
                                DigestHex = ds.DigestHex.ToUpperInvariant() }).ToArray()
                    }).ToArray(),
                Sites = zone.Sites.OrderBy(site => site.AuthorityFenceSiteId, StringComparer.Ordinal)
                    .Select(site => new
                    {
                        SiteId = site.AuthorityFenceSiteId,
                        site.Address,
                        site.HealthUrl,
                        site.Weight,
                        site.Priority,
                        site.HealthCheckType,
                        site.TcpPort,
                        Region = site.Region?.ToLowerInvariant(),
                        site.AgentSiteId,
                        RequiredAgentIds = (site.RequiredAgentIds ?? []).Order(StringComparer.Ordinal).ToArray(),
                        site.MinimumHealthyAgentReports,
                        ValidatorUrls = (site.ValidatorUrls ?? []).Order(StringComparer.Ordinal).ToArray(),
                        site.AdministrativelyQuarantined
                    }).ToArray()
            }).ToArray();
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            Zones = canonical,
            AgentTrustPolicy = trustPolicy,
            GeoIpDatabase = geoRouting ? geoIpIdentity : null,
            ProbeIntervalSeconds = probeIntervalSeconds,
            MaxConcurrentHealthProbes = maxConcurrentHealthProbes
        })));
    }
}
