$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Native Windows runner required' }
$name = 'GatewayCoreGslb'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'Refuse to touch an existing DNS service' }
$exe = (Resolve-Path 'engines/GslbDns/bin/Release/net10.0/GslbDns.exe').Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('gc-gslb-scm-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$config = Join-Path $root 'dns.json'
function FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return $listener.LocalEndpoint.Port } finally { $listener.Stop() }
}
$dnsPort = FreePort
do { $metricsPort = FreePort } while ($metricsPort -eq $dnsPort)
$settings = @{
    ListenHost = '127.0.0.1'; ListenPort = $dnsPort
    MetricsListenHost = '127.0.0.1'; MetricsListenPort = $metricsPort
    AllowDocumentationAddressesForTesting = $true
    ProbeIntervalSeconds = 1
    Zones = @(@{
        Name = 'scm.integration.test'; TtlSeconds = 30; SoaSerial = 1
        SoaContact = 'hostmaster.scm.integration.test'; RoutingPolicy = 'Weighted'
        NameServers = @(@{Host='ns1.scm.integration.test';Address='192.0.2.53'})
        Sites = @(@{Address='192.0.2.80';HealthUrl='http://127.0.0.1:9/ready';Weight=1})
    })
}
function WriteConfig {
    $settings | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $config -Encoding utf8
}
function VerifyRevision([int]$serial) {
    $expected = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
    $until = [DateTime]::UtcNow.AddSeconds(25)
    do {
        try {
            $observed = Invoke-RestMethod -Uri "http://127.0.0.1:$metricsPort/config-revision" -TimeoutSec 2
            if ($observed.type -eq 'gslb-loaded-config-revision' -and $observed.revision -ceq $expected) {
                & python -c "import sys;sys.path.insert(0,'ops/acceptance');import dns_wire_probe as w,gslb_signed_rollout as g; name='scm.integration.test'; port=int(sys.argv[1]); serial=int(sys.argv[2]); [(lambda q,t: w.require(g.soa_serial(w.exchange('127.0.0.1',port,q[1],t,2),q[0],name)==serial,'SOA revision mismatch'))(w.question(name,6),tcp) for tcp in (False,True)]" $dnsPort $serial
                if ($LASTEXITCODE -eq 0) { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $until)
    throw 'SCM DNS service did not serve the expected configuration and authoritative SOA'
}
$created = $false
try {
    WriteConfig
    New-Service -Name $name -BinaryPathName ('"{0}" "{1}"' -f $exe,$config) -StartupType Manual | Out-Null
    $created = $true
    Start-Service -Name $name
    (Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
    VerifyRevision 1
    $settings.Zones[0].SoaSerial = 2
    WriteConfig
    $service = Get-Service -Name $name
    Stop-Service -Name $name -ErrorAction Stop
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
    Start-Service -Name $name -ErrorAction Stop
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(20))
    VerifyRevision 2
    Write-Host 'PASS: native Windows SCM DNS restart, loaded digest and UDP/TCP SOA'
} finally {
    if ($created) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $name -ErrorAction Stop
            $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(20))
        }
        & "$env:WINDIR\System32\sc.exe" delete $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SCM test cleanup refused' }
    }
    Remove-Item -LiteralPath $root -Recurse -Force
}
