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
assert 'JsonNode weightValue' in code
assert 'SourceIpHash' in code and 'WeightedRandom' in code
assert 'LoadBalancingCore.TryWeight' in code
assert 'DangerousAcceptAnyServerCertificate' in code
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
