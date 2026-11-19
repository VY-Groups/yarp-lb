using System.Net;

internal static class DnsListenerValidation
{
    public static void ValidateAuthoritativeZones(IPAddress listen, DnsZone[] zones)
    {
        // A listener exposed beyond loopback is an authoritative DNS service.
        // Refuse zones that cannot answer their apex NS query. Legacy A-only
        // zones remain available to isolated loopback tests and development.
        if (!IPAddress.IsLoopback(listen) &&
            zones.Any(zone => zone.NameServers is not { Length: > 0 }))
            throw new InvalidDataException(
                "Non-loopback authoritative DNS requires at least one explicit NameServers entry for every zone.");
    }
}
