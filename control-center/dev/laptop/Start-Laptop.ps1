# Requires Windows 10/11, .NET 10 SDK. Runs without administrator rights.
# NEVER writes production routes, ProgramData state, services, firewall or certificate stores.
[CmdletBinding()]
param(
    [switch]$SmokeTest,
    [switch]$SkipBuild,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$repositoryRoot = (Resolve-Path (Join-Path $root '..')).Path
$backendProject = Join-Path $repositoryRoot 'tests\L7\BackendLab\BackendLab.csproj'
$controlProject = Join-Path $root 'SpeedSignYarp.csproj'
$settings = Join-Path $root 'appsettings.json'
$template = Join-Path $PSScriptRoot 'appsettings.laptop.json'
$devHome = Join-Path $env:LOCALAPPDATA 'YarpControlCenterDev'
$devState = Join-Path $devHome 'state'
$logsDir = Join-Path $devHome 'logs'
$processes = New-Object System.Collections.Generic.List[System.Diagnostics.Process]
$oldAsp = $env:ASPNETCORE_ENVIRONMENT
$oldDotnet = $env:DOTNET_ENVIRONMENT
$oldState = $env:YARP_CC_DEV_STATE_DIR
function Log([string]$message) { Write-Host "[YARP 0.1 DEV] $message" -ForegroundColor Cyan }
function Require([bool]$ok, [string]$reason) { if (-not $ok) { throw $reason } }
function HttpCode([string]$url) {
    try { return [int](Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 4).StatusCode }
    catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}
function WaitHttp([string]$url, [string]$name) {
    $end = (Get-Date).AddSeconds(50)
    do {
        if ((HttpCode $url) -eq 200) { Log "READY: $name"; return }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $end)
    throw "Timeout waiting for $name at $url. Inspect the logs at $logsDir."
}
function StartDotnet([string]$name, [string]$dll, [string]$working, [string]$tailArgs) {
    $out = Join-Path $logsDir "$name.stdout.log"
    $err = Join-Path $logsDir "$name.stderr.log"
    $cmdArgs = '"' + $dll + '"'
    if ($tailArgs) { $cmdArgs += ' ' + $tailArgs }
    $p = Start-Process -FilePath (Get-Command dotnet).Source -ArgumentList $cmdArgs `
        -WorkingDirectory $working -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $processes.Add($p)
    Log "START $name (PID $($p.Id))"
}
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Laptop script supports Windows only.' }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Install the .NET 10 SDK first.' }
    $sdks = @(& dotnet --list-sdks)
    Require (@($sdks | Where-Object { $_ -match '^10\.' }).Count -gt 0) 'Expected .NET 10 SDK'
    foreach ($port in @(8080, 18081, 18082)) {
        $listener = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)
        Require ($listener.Count -eq 0) "Port $port is already in use. Stop the previous test process first."
    }
    New-Item -ItemType Directory -Path $devState, $logsDir -Force | Out-Null
    if (-not (Test-Path -LiteralPath $settings)) {
        Copy-Item -LiteralPath $template -Destination $settings
        Log 'Created appsettings.json from loopback-only demo template'
    } else {
        $json = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
        Require ($null -ne $json.DevelopmentLab -and $json.DevelopmentLab.LabOnly -eq $true) `
            'Existing appsettings.json is not tagged as a laptop lab. Refusing to launch it.'
        $url = [string]$json.Kestrel.Endpoints.LocalHttp.Url
        Require ($url -eq 'http://127.0.0.1:8080') 'Existing lab listener must remain http://127.0.0.1:8080'
    }
    $env:ASPNETCORE_ENVIRONMENT='Development'
    $env:DOTNET_ENVIRONMENT='Development'
    $env:YARP_CC_DEV_STATE_DIR=$devState
    if (-not $SkipBuild) {
        Log 'Building .NET 10 backend and application (NuGet connectivity needed on first run)'
        & dotnet build $backendProject --configuration Release
        if ($LASTEXITCODE -ne 0) { throw 'Mock backend build failed' }
        & dotnet build $controlProject --configuration Release
        if ($LASTEXITCODE -ne 0) { throw 'Control Center build failed' }
    }
    $backendDll = Join-Path $repositoryRoot 'tests\L7\BackendLab\bin\Release\net10.0\BackendLab.dll'
    $controlDll = Join-Path $root 'bin\Release\net10.0\SpeedSignYarp.dll'
    Require (Test-Path -LiteralPath $backendDll) 'Missing backend executable. Re-run without -SkipBuild.'
    Require (Test-Path -LiteralPath $controlDll) 'Missing control application. Re-run without -SkipBuild.'
    $backendWorkingDir = Split-Path -Parent $backendDll
    StartDotnet 'backend-A' $backendDll $backendWorkingDir '18081 A'
    StartDotnet 'backend-B' $backendDll $backendWorkingDir '18082 B'
    WaitHttp 'http://127.0.0.1:18081/health/ready' 'backend A'
    WaitHttp 'http://127.0.0.1:18082/health/ready' 'backend B'
    StartDotnet 'control-center' $controlDll $root ''
    WaitHttp 'http://127.0.0.1:8080/gateway/health' 'Control Center'
    WaitHttp 'http://127.0.0.1:8080/dashboard' 'Management dashboard'
    Log 'Dashboard: http://127.0.0.1:8080/dashboard'
    Log 'API demo:  http://127.0.0.1:8080/api/identity'
    Log 'Metrics:   http://127.0.0.1:8080/gateway/metrics'
    Log "Logs:      $logsDir"
    if ($SmokeTest) {
        $nodes = @{}
        for ($i=0; $i -lt 120; $i++) {
            $value = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/identity' -TimeoutSec 5
            $name = [string]$value.node
            Require ($name -in @('A','B')) "Invalid routed backend identity: $name"
            $nodes[$name] = 1 + [int]$nodes[$name]
        }
        Require ($nodes.ContainsKey('A') -and $nodes.ContainsKey('B')) 'Weighted routing did not reach both backends'
        Require ((HttpCode 'http://127.0.0.1:8080/admin/api/capabilities') -eq 401) 'Anonymous access to protected API was allowed'
        $metrics = (Invoke-WebRequest -Uri 'http://127.0.0.1:8080/gateway/metrics' -UseBasicParsing -TimeoutSec 6).Content
        Require ($metrics -match 'yarp_control_http_duration_seconds_bucket') 'Prometheus histogram missing'
        Log "PASS: 120 routed HTTP requests; backend distribution A=$($nodes['A']) B=$($nodes['B']); API protected; metrics valid"
    } else {
        if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:8080/dashboard' | Out-Null }
        Log 'Press Ctrl+C here to stop the three development processes.'
        while ($true) {
            foreach($p in $processes) {
                if ($p.HasExited) { throw "A development process exited unexpectedly (PID $($p.Id)); check logs." }
            }
            Start-Sleep -Seconds 2
        }
    }
}
finally {
    foreach ($p in $processes) {
        try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction Stop } } catch {}
    }
    $env:ASPNETCORE_ENVIRONMENT=$oldAsp
    $env:DOTNET_ENVIRONMENT=$oldDotnet
    $env:YARP_CC_DEV_STATE_DIR=$oldState
    Log 'Stopped owned development processes; preserved isolated laptop configuration/state.'
}
