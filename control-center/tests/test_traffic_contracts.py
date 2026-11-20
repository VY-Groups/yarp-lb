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
    r'Math\.Round\(elapsed\s*\*\s*1000\.0\s*/\s*System\.Diagnostics\.Stopwatch\.Frequency,\s*3\)\);',
    code)
assert call is not None, 'typed access log must use only the reviewed bounded fields'
assert 'Request.Path' not in call.group(0) and 'Request.Query' not in call.group(0)
assert 'Request.Headers' not in call.group(0)
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
