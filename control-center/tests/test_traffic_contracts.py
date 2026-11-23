from pathlib import Path
root=Path(__file__).resolve().parents[1]
code=(root/'Program.cs').read_text()
engine=(root/'LoadBalancingExtensions.cs').read_text()
core=(root/'LoadBalancingCore.cs').read_text()
registry=(root/'CapabilityRegistry.cs').read_text()
front=(root/'wwwroot/app.ts').read_text()
inst=(root/'INSTALL.ps1').read_text()
assert 'AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>()' in code
assert 'AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>()' in code
assert 'MapCapabilityRegistry()' in code
assert 'AddSingleton<ILoadBalancingPolicy, PrimaryBackupPolicy>()' in code
assert '"PrimaryBackup"' in code
assert 'requires enabled active health checks for safe fallback' in code
assert 'PrimaryBackup' in front and 'TrafficRole' in front
assert '"PrimaryBackup"' in registry and 'backupMetadata' in registry
assert 'requiresActiveHealth = true' in registry
assert 'Sentinel quorum/fencing' in registry
assert 'physical HA' in registry

assert 'JsonNode weightValue' in code
assert 'SourceIpHash' in code and 'WeightedRandom' in code
assert 'LoadBalancingCore.TryWeight' in code
assert 'DangerousAcceptAnyServerCertificate' in code
assert 'GATEWAY_TRUSTED_PROXY_IPS' in code
# The shipping gateway uses a typed source-generated log method. Pin the
# exact structured schema and the actual call-site argument allowlist, not
# an obsolete inline message location. Existing real forwarding and OTLP
# acceptance also check the emitted access log and its privacy contract.
telemetry=(root/'GatewayOpenTelemetry.cs').read_text()
import re
template = (
    'GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} '
    'clientIpSource={ClientIpSource} method={Method} routeId={RouteId} '
    'statusCode={StatusCode} durationMs={DurationMs}'
)
declaration = re.search(
    r'\[LoggerMessage\(EventId\s*=\s*0,\s*Level\s*=\s*LogLevel\.Information,\s*'
    r'Message\s*=\s*"([^"]+)"\)\]\s*public static partial void LogAccess\(',
    telemetry)
assert declaration is not None and declaration.group(1) == template
call = re.search(
    r'GatewayOpenTelemetry\.LogAccess\(accessLogger,\s*'
    r'timestampUtc,\s*clientAddress\.Address\?\.ToString\(\)\s*\?\?\s*"unknown",\s*'
    r'clientAddress\.Source,\s*ctx\.Request\.Method,\s*routeId,\s*ctx\.Response\.StatusCode,\s*'
    r'durationMs\);', code)
assert call is not None, 'local typed access log must preserve its reviewed source and fields'
assert 'Request.Path' not in call.group(0) and 'Request.Query' not in call.group(0)
assert 'Request.Headers' not in call.group(0)

# Remote OTLP must use a different *strictly IP-free* log category. Neither
# a forwarded address nor an untrusted HTTP method can cross the exporter.
telemetry_template = (
    'GATEWAY_TELEMETRY_ACCESS timestampUtc={TimestampUtc:o} method={Method} '
    'routeId={RouteId} statusCode={StatusCode} durationMs={DurationMs}'
)
telemetry_decl = re.search(
    r'\[LoggerMessage\(EventId\s*=\s*1,\s*Level\s*=\s*LogLevel\.Information,\s*'
    r'Message\s*=\s*"([^"]+)"\)\]\s*public static partial void LogTelemetryAccess\(',
    telemetry)
assert telemetry_decl is not None and telemetry_decl.group(1) == telemetry_template
assert 'CreateLogger("GatewayCore.TelemetryAccess")' in code
export_call = re.search(
    r'GatewayOpenTelemetry\.LogTelemetryAccess\(telemetryAccessLogger,\s*'
    r'timestampUtc,\s*GatewayOpenTelemetry\.BoundedTelemetryMethod\(ctx\.Request\.Method\),\s*'
    r'GatewayOpenTelemetry\.IsSafeTelemetryId\(routeId\)\s*\?\s*routeId\s*:\s*"_other",\s*'
    r'ctx\.Response\.StatusCode,\s*durationMs\);', code)
assert export_call is not None, 'OTLP access summary must use bounded non-identifying fields'
for forbidden in ('clientAddress', 'RemoteIpAddress', 'X-Forwarded-For', 'Request.Path',
                  'Request.Query', 'Request.Headers', 'ClientIp'):
    assert forbidden not in export_call.group(0), 'untrusted data must not enter OTLP'
assert 'string.Equals(category, "GatewayCore.TelemetryAccess", StringComparison.Ordinal)' in telemetry
assert 'string.Equals(category, "GatewayCore.AccessLog", StringComparison.Ordinal)' not in telemetry

assert '/admin/api/reports/traffic.json' in code
assert '/admin/api/reports/traffic.csv' in code
assert 'duration_bucket_upper_seconds' in code
assert 'GatewayTrafficReportCsv.DurationBucketRows' in code
assert 'RequireRole("Administrator", "Operator")' in code
assert 'durationBuckets = requestHistogram.Snapshot()' in code
assert 'untrackedDestinationRequests = destinationTelemetry.UntrackedRequests' in code
assert 'Tracked destination limit:' in front and 'untrackedDestinationRequests' in front
assert 'Traffic JSON' in front and 'Traffic CSV' in front
assert 'Backend health JSON' in front and 'Backend health CSV' in front
assert '/admin/api/reports/health.json' in code and '/admin/api/reports/health.csv' in code
assert 'Request duration distribution' in front
assert 'DestinationConfig.Metadata' not in core
assert 'RandomNumberGenerator.GetInt32' in engine
assert 'RemoteIpAddress' in engine
assert 'Request.Headers["X-Forwarded-For"]' not in engine
assert 'SHA256.HashData' in core and 'PickRendezvousIndex' in core
assert 'CapabilityRegistry.cs' in inst and 'LoadBalancingExtensions.cs' in inst
assert 'Weight must be an integer from 1 to 100' in front
assert 'Traffic Engine & platform modules' in front
assert 'Feature' not in engine  # basic sanity
print('PASS: extension registration, validations, safe peer-IP source, UI wiring, packaging')
