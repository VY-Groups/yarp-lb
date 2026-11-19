using System.Security.Cryptography;
using System.Text.Json;

/// <summary>Canonical digest over routing, health and external-observer trust policy shared by both authorities.</summary>
internal static class AuthorityFenceFingerprint
{
    public static string Compute(DnsZone[] zones, AgentReportServerConfig? agentReports,
        int probeIntervalSeconds = 1, int maxConcurrentHealthProbes = 1)
    {
        var trustPolicy = agentReports is null ? null : new
        {
            agentReports.MaxTtlSeconds,
            agentReports.MaxAgeSeconds,
            agentReports.MaxClockSkewSeconds,
            agentReports.MaxReportsPerMinute,
            RevokedPins = (agentReports.RevokedCertificateSha256 ?? []).Select(pin => pin.ToUpperInvariant())
                .Order(StringComparer.Ordinal).ToArray(),
            Agents = (agentReports.Agents ?? []).OrderBy(agent => agent.AgentId, StringComparer.Ordinal)
                .Select(agent => new
                {
                    agent.AgentId,
                    agent.VantageGroup,
                    CertificatePins = (agent.CertificateSha256 ?? []).Select(pin => pin.ToUpperInvariant())
                        .Order(StringComparer.Ordinal).ToArray(),
                    SigningKeys = (agent.SigningPublicKeyPems ?? []).Select(path =>
                        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))))
                        .Order(StringComparer.Ordinal).ToArray()
                }).ToArray()
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
                            .ToArray()
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
            ProbeIntervalSeconds = probeIntervalSeconds,
            MaxConcurrentHealthProbes = maxConcurrentHealthProbes
        })));
    }
}
