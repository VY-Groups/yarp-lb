# Disposable GitHub-hosted Windows SCM integration only.
# Refuses real machines, existing services, and existing ProgramData state.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'REFUSED: Windows SCM smoke only runs on a disposable GitHub Actions Windows runner'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'REFUSED: disposable SCM smoke needs administrator rights on runner'
}
$name = 'GatewayCoreYarp'
$product = Join-Path $env:ProgramData $name
if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue) -or
    (Test-Path -LiteralPath $product)) {
    throw 'REFUSED: pre-existing service or gateway state may not be touched'
}
$root = Join-Path $env:RUNNER_TEMP ('gatewaycore-scm-' + [guid]::NewGuid().ToString('N'))
$published = Join-Path $root 'published'
$createdService = $false
$rootProject = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$project = Join-Path $rootProject 'control-center\GatewayCoreYarp.csproj'
$sample = Join-Path $rootProject 'control-center\appsettings.TEST.sample.json'
$port = Get-Random -Minimum 22500 -Maximum 32500
$baseUrl = 'http://127.0.0.1:' + $port
try {
    New-Item -ItemType Directory -Path $published -Force | Out-Null
    & dotnet publish $project --configuration Release --framework net10.0 -p:UseAppHost=true --output $published
    if ($LASTEXITCODE -ne 0) { throw 'Disposable .NET publish failed' }
    $exe = Join-Path $published 'GatewayCoreYarp.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw 'Published Windows SCM executable missing'
    }
    # The shipped test-only config is never copied into production state.
    $config = Get-Content -LiteralPath $sample -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.Kestrel.Endpoints.LocalHttp.Url = $baseUrl
    $encoded = $config | ConvertTo-Json -Depth 20
    [IO.File]::WriteAllText((Join-Path $published 'appsettings.json'), $encoded,
        (New-Object Text.UTF8Encoding($false)))
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
        throw 'Allocated disposable loopback port already in use'
    }
    # LocalSystem is the existing SCM/ACL baseline, NOT a customer account test.
    New-Service -Name $name -BinaryPathName ('"{0}"' -f $exe) -DisplayName 'GatewayCore Disposable SCM CI' -StartupType Manual | Out-Null
    $createdService = $true
    $service = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($null -eq $service -or $service.StartName -ne 'LocalSystem') {
        throw 'Disposable service must use expected LocalSystem identity'
    }
    function Wait-Health {
        for ($i = 0; $i -lt 100; $i++) {
            if ((Get-Service -Name $name).Status -eq 'Stopped') { break }
            try {
                $reply = Invoke-WebRequest -UseBasicParsing -Method Get -Uri ($baseUrl + '/gateway/health') -TimeoutSec 2
                if ($reply.StatusCode -eq 200) { return }
            } catch { }
            Start-Sleep -Milliseconds 300
        }
        throw 'Windows SCM process failed to reach healthy loopback endpoint'
    }
    Start-Service -Name $name
    Wait-Health
    if (-not (Test-Path -LiteralPath $product)) { throw 'SCM did not create state' }
    $stateRoot = Join-Path $product 'ControlPlane'
    if (-not (Get-Acl -LiteralPath $stateRoot).AreAccessRulesProtected) {
        throw 'SCM state directory inherited broad ACL permissions'
    }
    Write-Output 'PASS: real Windows SCM service reached loopback gateway health'
    $cookieSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $bootstrapBody = @{username='ci_scm_admin';password='Disposable-Windows-SCM-CI-Secret-4096!';email='scm-admin@example.invalid'} | ConvertTo-Json -Compress
    $bootstrap = Invoke-WebRequest -Uri ($baseUrl + '/admin/api/bootstrap') -UseBasicParsing -Method Post -WebSession $cookieSession -TimeoutSec 10 -ContentType 'application/json' -Body $bootstrapBody
    if ($bootstrap.StatusCode -ne 200 -or -not (($bootstrap.Content | ConvertFrom-Json).authenticated)) {
        throw 'Disposable SCM administrator bootstrap rejected'
    }
    $before = Invoke-WebRequest -Uri ($baseUrl + '/admin/api/session') -UseBasicParsing -Method Get -WebSession $cookieSession -TimeoutSec 10
    $whoBefore = $before.Content | ConvertFrom-Json
    if (-not $whoBefore.authenticated -or $whoBefore.username -ne 'ci_scm_admin') {
        throw 'SCM session cookie was not authenticated before restart'
    }
    $keyDirectory = Join-Path $stateRoot 'data-protection-keys'
    $xmlFiles = @(Get-ChildItem -LiteralPath $keyDirectory -Filter '*.xml' -File)
    if ($xmlFiles.Count -lt 1) { throw 'Windows persistent DPAPI key XML missing' }
    foreach ($entry in $xmlFiles) {
        $contents = [IO.File]::ReadAllText($entry.FullName)
        if ($contents -notmatch '<encryptedSecret\b' -or $contents -match '<masterKey\b') {
            throw 'Persistent Windows key XML is not DPAPI wrapped'
        }
    }
    Write-Output 'PASS: persisted Windows Data Protection XML remains encrypted'
    Stop-Service -Name $name
    (Get-Service -Name $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(30))
    Start-Service -Name $name
    Wait-Health
    $after = Invoke-WebRequest -Uri ($baseUrl + '/admin/api/session') -UseBasicParsing -Method Get -WebSession $cookieSession -TimeoutSec 10
    $whoAfter = $after.Content | ConvertFrom-Json
    if (-not $whoAfter.authenticated -or $whoAfter.username -ne 'ci_scm_admin') {
        throw 'SCM restart invalidated existing DPAPI-protected session'
    }
    Write-Output 'PASS: real Windows SCM stop/restart preserved authenticated cookie'
} finally {
    if ($createdService) {
        try {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
                Stop-Service -Name $name -ErrorAction Stop
                $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(30))
            }
        } catch {
            Write-Warning 'Disposable service shutdown requires runner cleanup'
        }
        & sc.exe delete $name | Out-Null
    }
    $remaining = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($null -eq $remaining -or $remaining.Status -eq 'Stopped') {
        if (Test-Path -LiteralPath $product) {
            Remove-Item -LiteralPath $product -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
