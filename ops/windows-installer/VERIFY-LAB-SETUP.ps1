[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$SetupPath,
    [Parameter(Mandatory)][string]$PayloadPath,
    [Parameter(Mandatory)][ValidateSet('Fresh','Upgrade','Rollback','IPv6Upgrade')][string]$Scenario
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Installer acceptance can only mutate a disposable GitHub-hosted Windows runner.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Acceptance requires the hosted runner administrator.' }

$serviceName = 'GatewayCoreYarp'
$productRoot = Join-Path $env:ProgramData 'GatewayCoreYarp'
$stateRoot = Join-Path $productRoot 'ControlPlane'
$configPath = Join-Path $stateRoot 'config\appsettings.json'
$target = Join-Path $env:ProgramFiles "GatewayCore\Lab\$SourceCommit"
$testFailureMarker = Join-Path $env:TEMP "GatewayCoreYarp-installer-fail-health-$SourceCommit"
$oldSha = '0000000000000000000000000000000000000000'
$oldRoot = Join-Path $env:ProgramFiles "GatewayCore\Lab\$oldSha"
$oldExe = Join-Path $oldRoot 'app\GatewayCoreYarp.exe'
$oldConfig = Join-Path $oldRoot 'app\appsettings.json'
$oldConfigUrl = if ($Scenario -eq 'IPv6Upgrade') { 'http://[::1]:8080' } else { 'http://127.0.0.1:8080' }
$adminFile = Join-Path $stateRoot 'admin-users.json'
$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$setupLog = Join-Path $env:TEMP "GatewayCore-Setup-$SourceCommit.log"
$stateBefore = @{}
$oldInstalled = $false
$setupArgs = @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',"/LOG=$setupLog")

function Invoke-Sc([string[]]$Arguments) {
    & "$env:WINDIR\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($Arguments -join ' ') failed with $LASTEXITCODE" }
}

function Wait-Healthy([int]$Seconds = 90) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri ($oldConfigUrl + '/gateway/health') -TimeoutSec 2
            if ($response.StatusCode -eq 200 -and ($response.Content | ConvertFrom-Json).status -eq 'healthy') { return }
        } catch { }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Loopback health endpoint did not become ready.'
}

function Invoke-Setup([switch]$ExpectFailure) {
    $process = Start-Process -FilePath $SetupPath -ArgumentList $setupArgs -Wait -PassThru
    $logText = if (Test-Path -LiteralPath $setupLog) { Get-Content -LiteralPath $setupLog -Raw } else { '' }
    $diagnostic = if ($logText) { ($logText -split "`r?`n" | Select-Object -Last 60) -join "`n" } else { 'Setup log was not created.' }
    if ($ExpectFailure) {
        # Inno Setup wraps long logged PowerShell lines at arbitrary columns.
        if ($process.ExitCode -eq 0) { throw "Failed Setup falsely reported success (exit 0).\n$diagnostic" }
        if (Test-Path -LiteralPath $target) { throw "Failed Setup left its candidate installation directory behind: $target\n$diagnostic" }
        if ($logText -notmatch '(?s)Disposable acceptance.{0,160}contro.{0,40}lled service health failure\.') {
            throw "The upgrade did not fail at the intended post-start health gate. Exit=$($process.ExitCode).`n$diagnostic"
        }
    } elseif ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $target '.dashboard-ready'))) {
        throw "Setup did not complete and mark the healthy service ready. Exit=$($process.ExitCode).`n$diagnostic"
    }
}

function Get-DirectoryAclSddl([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
}

function Test-LoopbackDashboardEndpoint([object]$Endpoint) {
    $urlProperty = if ($null -eq $Endpoint) { $null } else { $Endpoint.PSObject.Properties['Url'] }
    if ($null -eq $urlProperty -or -not $urlProperty.Value) { return $false }
    $uri = $null
    if (-not [Uri]::TryCreate([string]$urlProperty.Value,[UriKind]::Absolute,[ref]$uri)) { return $false }
    return $uri.Scheme -eq 'http' -and $uri.Port -eq 8080 -and $uri.IsLoopback
}

function Seed-PreviousInstall {
    if (Test-Path -LiteralPath $oldRoot) { throw 'Synthetic previous version path already exists.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $oldExe) -Force | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $PayloadPath 'app') -Force | Copy-Item -Destination (Split-Path -Parent $oldExe) -Recurse -Force
    if (-not (Test-Path -LiteralPath $oldExe -PathType Leaf)) { throw 'Synthetic previous executable is missing.' }
    $config = [ordered]@{
        AllowedHosts='localhost;127.0.0.1;[::1]'
        Kestrel=@{Endpoints=@{LocalHttp=@{Url=$oldConfigUrl}}}
        ReverseProxy=@{Routes=@{};Clusters=@{}}
        MigrationSentinel='preserve-this-value'
    }
    [IO.File]::WriteAllText($oldConfig, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Invoke-Sc @('create',$serviceName,'binPath=',('"{0}"' -f $oldExe),'start=','auto','obj=','NT AUTHORITY\LocalService','DisplayName=','GatewayCore Previous Lab')
    New-ItemProperty -LiteralPath $svcKey -Name Environment -PropertyType MultiString -Value @("YARP_RUNTIME_CONFIG_PATH=$oldConfig",'ASPNETCORE_ENVIRONMENT=Production') -Force | Out-Null
    Start-Service -Name $serviceName
    $script:oldInstalled = $true
    Wait-Healthy
    $web = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $body = @{username='installer_ci_admin';password='Disposable-Installer-CI-Password-Not-For-Use';email='installer@example.invalid'} | ConvertTo-Json -Compress
    $response = Invoke-WebRequest -UseBasicParsing -Uri ($oldConfigUrl + '/admin/api/bootstrap') -Method Post -WebSession $web -TimeoutSec 10 -ContentType 'application/json' -Body $body
    if ($response.StatusCode -ne 200 -or -not ($response.Content | ConvertFrom-Json).authenticated) { throw 'Previous installation did not create disposable administrator state.' }
    Set-Content -LiteralPath (Join-Path $stateRoot 'migration-sentinel.txt') -Value 'preserve-state' -Encoding ascii
    $keyDirectory = Join-Path $stateRoot 'data-protection-keys'
    $keys = @(Get-ChildItem -LiteralPath $keyDirectory -Filter '*.xml' -File)
    if ($keys.Count -eq 0) { throw 'Previous installation did not create persistent DPAPI key material.' }
    $script:stateBefore = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $stateRoot -File -Recurse -Force)) {
        $script:stateBefore[$file.FullName.Substring($stateRoot.Length + 1)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
}

function Assert-InstalledService([string]$ExpectedExe) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or $service.StartName -ne 'NT AUTHORITY\LocalService') {
        $actual = if ($null -eq $service) { 'missing' } else { "State='$($service.State)', StartMode='$($service.StartMode)', StartName='$($service.StartName)'" }
        $diagnostic = if (Test-Path -LiteralPath $setupLog) { (Get-Content -LiteralPath $setupLog -Tail 40 | Out-String) } else { 'Setup log was not created.' }
        throw "GatewayCore service is not running as LocalService with automatic startup. SCM reported: $actual`n$diagnostic"
    }
    if ($service.PathName.Trim('"') -cne $ExpectedExe) { throw "SCM binary path mismatch: $($service.PathName)" }
    Wait-Healthy
    $dashboard = Invoke-WebRequest -UseBasicParsing -Uri ($oldConfigUrl + '/dashboard') -TimeoutSec 10
    if ($dashboard.StatusCode -ne 200) { throw 'Dashboard did not return HTTP 200 after health became ready.' }
    $marker = Join-Path (Split-Path -Parent (Split-Path -Parent $ExpectedExe)) '.dashboard-ready'
    if ((Get-Content -LiteralPath $marker -Raw).Trim() -cne $SourceCommit) { throw 'Dashboard launch marker was written before/without the verified install commit.' }
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $installerMetadata = $config.PSObject.Properties['GatewayCoreInstaller']
    $schemaVersion = if ($null -eq $installerMetadata -or $null -eq $installerMetadata.Value) { $null } else { $installerMetadata.Value.PSObject.Properties['ConfigurationSchemaVersion'] }
    if ($null -eq $schemaVersion -or $schemaVersion.Value -ne 1) { throw 'Runtime config was not migrated to schema version 1.' }
    $dashboardEndpoint = @($config.Kestrel.Endpoints.PSObject.Properties | Where-Object { Test-LoopbackDashboardEndpoint $_.Value })
    if ($dashboardEndpoint.Count -eq 0) { throw 'Dashboard listener is not bound to loopback port 8080.' }
    $stateAcl = Get-Acl -LiteralPath $stateRoot
    if (-not $stateAcl.AreAccessRulesProtected -or -not (Get-Acl -LiteralPath $configPath).AreAccessRulesProtected) { throw 'Service config/state ACL is not protected.' }
    $binaryAcl = Get-Acl -LiteralPath $ExpectedExe
    $localSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid,$null)
    $danger = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $binaryAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Equals($localSid) -and ($rule.FileSystemRights -band $danger) -ne 0) {
            throw 'LocalService can modify its own executable.'
        }
    }
    $parentAcl = Get-Acl -LiteralPath $productRoot
    $parentDanger = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $parentAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Equals($localSid) -and ($rule.FileSystemRights -band $parentDanger) -ne 0) {
            throw 'LocalService can alter the ProgramData parent that contains protected rollback backups.'
        }
    }
}

function Assert-InstalledPayload {
    $appRoot = Join-Path $target 'app'
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $PayloadPath 'app') -File -Recurse -Force)) {
        $relative = $file.FullName.Substring((Join-Path $PayloadPath 'app').Length + 1)
        $installed = Join-Path $appRoot $relative
        if (-not (Test-Path -LiteralPath $installed -PathType Leaf) -or (Get-FileHash $file.FullName).Hash -ne (Get-FileHash $installed).Hash) {
            throw "Installed payload mismatch: $relative"
        }
    }
}

try {
    if ((Test-Path -LiteralPath $target) -or (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { throw 'Runner has pre-existing target or service state.' }
    if ($Scenario -eq 'Fresh') {
        if (Test-Path -LiteralPath $productRoot) { throw 'Fresh-install runner has pre-existing ProgramData state.' }
    } else {
        Seed-PreviousInstall
    }

    if ($Scenario -eq 'Rollback') {
        $stateAclBefore = Get-DirectoryAclSddl $stateRoot
        $configBefore = [IO.File]::ReadAllText($oldConfig)
        $serviceEnvironmentBefore = @((Get-ItemProperty -LiteralPath $svcKey).Environment)
        Set-Content -LiteralPath $testFailureMarker -Value 'CI-only controlled startup failure' -Encoding ascii
        Invoke-Setup -ExpectFailure
        Remove-Item -LiteralPath $testFailureMarker -Force -ErrorAction SilentlyContinue
        $restored = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($null -eq $restored -or $restored.PathName.Trim('"') -cne $oldExe -or $restored.State -ne 'Running' -or
            $restored.StartMode -ne 'Auto' -or $restored.StartName -ne 'NT AUTHORITY\LocalService') {
            throw 'Failed upgrade did not restore the prior service path, identity, startup mode and running state.'
        }
        $serviceEnvironmentAfter = @((Get-ItemProperty -LiteralPath $svcKey).Environment)
        if (($serviceEnvironmentAfter -join "`n") -cne ($serviceEnvironmentBefore -join "`n")) { throw 'Failed upgrade did not restore the prior service environment.' }
        if ((Get-DirectoryAclSddl $stateRoot) -cne $stateAclBefore) { throw 'Failed upgrade did not restore the original state ACL.' }
        if ([IO.File]::ReadAllText($oldConfig) -cne $configBefore) { throw 'Failed upgrade changed the old runtime config.' }
        if (Test-Path -LiteralPath $configPath) { throw 'Failed upgrade left a partial migrated runtime config.' }
        Wait-Healthy
        Write-Output 'PASS: injected startup failure rolled back the service path, config and ACL.'
    } else {
        Invoke-Setup
        Assert-InstalledPayload
        Assert-InstalledService (Join-Path $target 'app\GatewayCoreYarp.exe')
        if ($Scenario -in @('Upgrade','IPv6Upgrade')) {
            if (-not (Test-Path -LiteralPath $adminFile) -or (Get-Content (Join-Path $stateRoot 'migration-sentinel.txt') -Raw).Trim() -cne 'preserve-state') {
                throw 'Upgrade did not preserve administrator and application state.'
            }
            $after = @{}
            foreach ($file in @(Get-ChildItem -LiteralPath $stateRoot -File -Recurse -Force | Where-Object { $_.Name -notin @('appsettings.json') })) {
                $after[$file.FullName.Substring($stateRoot.Length + 1)] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            }
            foreach ($key in $stateBefore.Keys) {
                if ($key -notlike 'config\*' -and $after[$key] -cne $stateBefore[$key]) { throw "Upgrade modified pre-existing state: $key" }
            }
            $backups = @(Get-ChildItem -LiteralPath (Join-Path $productRoot 'InstallerBackups') -Directory)
            if ($backups.Count -eq 0 -or -not (Test-Path (Join-Path $backups[-1].FullName 'ControlPlane-sha256.json'))) { throw 'Upgrade did not retain a verified pre-migration backup.' }
            if (-not (Test-Path (Join-Path $backups[-1].FullName 'source-appsettings.json'))) { throw 'Upgrade did not back up the previous runtime configuration.' }
            if ((Get-Content $configPath -Raw | ConvertFrom-Json).MigrationSentinel -cne 'preserve-this-value') { throw 'Configuration migration discarded an existing setting.' }
            if ($Scenario -eq 'IPv6Upgrade') {
                $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
                $ipv6 = @($config.Kestrel.Endpoints.PSObject.Properties | Where-Object { $_.Value.Url -eq 'http://[::1]:8080' })
                $ipv4 = @($config.Kestrel.Endpoints.PSObject.Properties | Where-Object { $_.Value.Url -eq 'http://127.0.0.1:8080' })
                if ($ipv6.Count -ne 1 -or $ipv4.Count -ne 1) { throw 'IPv6-only upgrade did not preserve ::1 and provision the IPv4 management listener.' }
                $health4 = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8080/gateway/health' -TimeoutSec 10
                if ($health4.StatusCode -ne 200 -or ($health4.Content | ConvertFrom-Json).status -ne 'healthy') {
                    throw 'IPv4 management listener added for IPv6-only upgrade did not become healthy.'
                }
                Write-Output 'PASS: IPv6-only previous service migrated without losing ::1 and gained verified IPv4 loopback dashboard.'
            } else {
                Write-Output 'PASS: upgrade detected prior service, backed up protected state/config, migrated config and preserved DPAPI/admin data.'
            }
        } else {
            $shortcutCheck = Get-Content (Join-Path $PSScriptRoot 'GatewayCoreLab.iss') -Raw
            if ($shortcutCheck -notmatch 'Check:\s*DashboardReady' -or $shortcutCheck -notmatch 'shellexec\s+runasoriginaluser\s+skipifsilent') { throw 'Dashboard launch is not gated to verified service readiness and the interactive user.' }
            Write-Output 'PASS: fresh install, automatic service startup, health check, loopback dashboard and guarded launch.'
        }

        $second = Start-Process -FilePath $SetupPath -ArgumentList $setupArgs -Wait -PassThru
        if ($second.ExitCode -eq 0) { throw 'Setup permitted overwriting an already installed version.' }
        Write-Output 'PASS: same-version overwrite refused.'
        $uninstaller = Join-Path $target 'unins000.exe'
        $uninstall = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
        if ($uninstall.ExitCode -ne 0 -or (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { throw 'Uninstall did not remove the service cleanly.' }
        if (-not (Test-Path -LiteralPath (Join-Path $stateRoot 'data-protection-keys')) -or -not (Test-Path -LiteralPath $adminFile -ErrorAction SilentlyContinue)) {
            if ($Scenario -in @('Upgrade','IPv6Upgrade')) { throw 'Uninstall removed protected existing state.' }
            if (-not (Test-Path -LiteralPath $stateRoot)) { throw 'Uninstall removed protected ProgramData state.' }
        }
        Write-Output 'PASS: uninstall removes its service and binaries while retaining ProgramData state.'
    }
} finally {
    Remove-Item -LiteralPath $testFailureMarker -Force -ErrorAction SilentlyContinue
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -ErrorAction SilentlyContinue }
        & "$env:WINDIR\System32\sc.exe" delete $serviceName | Out-Null
    }
    if (Test-Path -LiteralPath $oldRoot) { Remove-Item -LiteralPath $oldRoot -Recurse -Force }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    if (Test-Path -LiteralPath $productRoot) { Remove-Item -LiteralPath $productRoot -Recurse -Force }
    Remove-Item -LiteralPath (Join-Path $env:ProgramData 'GatewayCoreYarp.install.lock') -Force -ErrorAction SilentlyContinue
}
