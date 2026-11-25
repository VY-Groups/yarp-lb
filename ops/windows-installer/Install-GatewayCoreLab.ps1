[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InstallRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [ValidateRange(10,300)][int]$HealthTimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'GatewayCoreYarp'
$productRoot = Join-Path $env:ProgramData 'GatewayCoreYarp'
$stateRoot = Join-Path $productRoot 'ControlPlane'
$configRoot = Join-Path $stateRoot 'config'
$configPath = Join-Path $configRoot 'appsettings.json'
$backupRoot = Join-Path $productRoot 'InstallerBackups'
$installRoot = [IO.Path]::GetFullPath($InstallRoot)
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles "GatewayCore\Lab\$SourceCommit"))
$exePath = Join-Path $installRoot 'app\GatewayCoreYarp.exe'
$readyMarker = Join-Path $installRoot '.dashboard-ready'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Setup must run elevated as a local administrator.'
    }
}

function Assert-Prerequisites {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'GatewayCore Lab requires 64-bit Windows.'
    }
    $os = Get-CimInstance Win32_OperatingSystem
    if ([int]$os.BuildNumber -lt 20348 -or [int]$os.ProductType -eq 1) {
        throw 'GatewayCore Lab Setup supports Windows Server 2022 or later only.'
    }
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($installRoot))
    if ($drive.AvailableFreeSpace -lt 1GB) { throw 'At least 1 GiB of free space is required for installation and rollback.' }
}

function Assert-NoReparsePoints([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop)
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installer state may not traverse a reparse point: $($item.FullName)"
        }
    }
}

function New-ProductAcl([string]$Path, [switch]$IncludeLocalService) {
    if (Test-Path -LiteralPath $Path) {
        $existing = Get-Acl -LiteralPath $Path
        if (-not $existing.AreAccessRulesProtected) { throw "Existing private installer directory has inherited permissions: $Path" }
        $allowed = @(
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null).Value,
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null).Value,
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        )
        $localServiceSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null).Value
        if ($IncludeLocalService) { $allowed += $localServiceSid }
        foreach ($rule in $existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -notin $allowed) {
                throw "Existing private installer directory grants access to an unapproved identity: $Path"
            }
            if (-not $IncludeLocalService -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -eq $localServiceSid) {
                throw "Installer backup directory must not be readable by the GatewayCore service account: $Path"
            }
        }
        if ($IncludeLocalService -and $existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]).IdentityReference.Value -notcontains $localServiceSid) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null),
                [Security.AccessControl.FileSystemRights]::FullControl,
                ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $existing.AddAccessRule($rule)
            Set-Acl -LiteralPath $Path -AclObject $existing
        }
        return
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $principals = @(
        [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null),
        [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    )
    if ($IncludeLocalService) {
        $principals += [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    }
    foreach ($sid in $principals) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    [IO.DirectoryInfo]::new($Path).SetAccessControl($acl)
}

function Set-StateAcl([string]$Path) {
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        New-ProductAcl -Path $Path -IncludeLocalService
        return
    }
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null),
        [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null),
        [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    )) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.FileInfo]::new($Path).SetAccessControl($acl)
}

function Set-ProductRootAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $systemSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $adminsSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $localServiceSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    foreach ($entry in @(
        @{ Sid=$systemSid; Rights=[Security.AccessControl.FileSystemRights]::FullControl },
        @{ Sid=$adminsSid; Rights=[Security.AccessControl.FileSystemRights]::FullControl },
        # The service must traverse this parent to reach ControlPlane, but must
        # not be able to replace or delete sibling InstallerBackups.
        @{ Sid=$localServiceSid; Rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute }
    )) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $entry.Sid, $entry.Rights,
            ([Security.AccessControl.InheritanceFlags]::None),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    [IO.DirectoryInfo]::new($Path).SetAccessControl($acl)
}

function Get-TreeAclManifest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $items = @((Get-Item -LiteralPath $Path -Force)) + @(Get-ChildItem -LiteralPath $Path -Force -Recurse)
    return @($items | ForEach-Object {
        $acl = Get-Acl -LiteralPath $_.FullName
        [pscustomobject]@{
            RelativePath = $_.FullName.Substring($Path.Length).TrimStart('\')
            IsDirectory = [bool]$_.PSIsContainer
            AccessSddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        }
    })
}

function Restore-TreeAclManifest([string]$Path, [object[]]$Manifest) {
    foreach ($entry in ($Manifest | Sort-Object { $_.RelativePath.Length })) {
        $target = if ($entry.RelativePath) { Join-Path $Path $entry.RelativePath } else { $Path }
        if (-not (Test-Path -LiteralPath $target)) { continue }
        if ($entry.IsDirectory) {
            $acl = [Security.AccessControl.DirectorySecurity]::new()
        } else {
            $acl = [Security.AccessControl.FileSecurity]::new()
        }
        $acl.SetSecurityDescriptorSddlForm($entry.AccessSddl, [Security.AccessControl.AccessControlSections]::Access)
        Set-Acl -LiteralPath $target -AclObject $acl
    }
}

function Get-FileManifest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @(Get-ChildItem -LiteralPath $Path -File -Force -Recurse | ForEach-Object {
        [pscustomobject]@{ Path=$_.FullName.Substring($Path.Length).TrimStart('\'); Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
    })
}

function Copy-VerifiedState([string]$Source, [string]$Destination, [object[]]$Manifest) {
    if (-not (Test-Path -LiteralPath $Source)) { return }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | Copy-Item -Destination $Destination -Recurse -Force
    foreach ($entry in $Manifest) {
        if (-not $entry.Path) { continue }
        $copy = Join-Path $Destination $entry.Path
        if (-not (Test-Path -LiteralPath $copy -PathType Leaf) -or
            (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -ne $entry.Sha256) {
            throw "Protected state backup verification failed: $($entry.Path)"
        }
    }
}

function Set-BackupAcl([string]$Path) {
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @(
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null),
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        )) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        [IO.DirectoryInfo]::new($Path).SetAccessControl($acl)
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @(
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null),
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        )) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                [Security.AccessControl.AccessControlType]::Allow))
        }
        [IO.FileInfo]::new($Path).SetAccessControl($acl)
    }
}

function Read-ServiceEnvironment([string]$Name) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $key)) { return @() }
    $properties = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    if ($null -eq $properties -or $null -eq $properties.PSObject.Properties['Environment']) { return @() }
    return @($properties.Environment)
}

function Get-ConfigSource([object]$Service, [string[]]$Environment) {
    foreach ($entry in $Environment) {
        if ($entry -match '^YARP_RUNTIME_CONFIG_PATH=(.+)$') {
            $path = $Matches[1]
            if (Test-Path -LiteralPath $path -PathType Leaf) { return [IO.Path]::GetFullPath($path) }
        }
    }
    if ($null -ne $Service) {
        $exe = [regex]::Match([string]$Service.PathName, '"(?<exe>[^"]+\.exe)"|(?<exe>.+?\.exe)(?:\s|$)', 'IgnoreCase')
        if ($exe.Success) {
            $path = Join-Path (Split-Path -Parent $exe.Groups['exe'].Value) 'appsettings.json'
            if (Test-Path -LiteralPath $path -PathType Leaf) { return [IO.Path]::GetFullPath($path) }
        }
    }
    return $null
}

function ConvertTo-ManagedConfig([string]$SourcePath) {
    if ($SourcePath) {
        $raw = [IO.File]::ReadAllText($SourcePath, [Text.Encoding]::UTF8)
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    } else {
        $config = [pscustomobject]@{
            AllowedHosts = 'localhost;127.0.0.1'
            Logging = [pscustomobject]@{ LogLevel = [pscustomobject]@{ Default='Warning'; 'Microsoft.AspNetCore'='Warning' } }
            Kestrel = [pscustomobject]@{ Endpoints = [pscustomobject]@{ GatewayCoreDashboard = [pscustomobject]@{ Url='http://127.0.0.1:8080' } } }
            ReverseProxy = [pscustomobject]@{ Routes=[pscustomobject]@{}; Clusters=[pscustomobject]@{} }
        }
    }
    if ($null -eq $config -or $config -isnot [pscustomobject]) { throw 'Runtime configuration must be a JSON object.' }
    if ($null -eq $config.ReverseProxy) { $config | Add-Member -NotePropertyName ReverseProxy -NotePropertyValue ([pscustomobject]@{ Routes=[pscustomobject]@{}; Clusters=[pscustomobject]@{} }) }
    if ($config.ReverseProxy -isnot [pscustomobject]) { throw 'ReverseProxy configuration must be an object; migration stopped without discarding it.' }
    foreach ($name in @('Routes','Clusters')) {
        if ($null -eq $config.ReverseProxy.$name) { $config.ReverseProxy | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{}) }
        if ($config.ReverseProxy.$name -isnot [pscustomobject]) { throw "ReverseProxy.$name must be an object; migration stopped without rewriting it." }
    }
    if ($null -eq $config.Kestrel) { $config | Add-Member -NotePropertyName Kestrel -NotePropertyValue ([pscustomobject]@{ Endpoints=[pscustomobject]@{} }) }
    if ($config.Kestrel -isnot [pscustomobject]) { throw 'Kestrel configuration must be an object.' }
    if ($null -eq $config.Kestrel.Endpoints) { $config.Kestrel | Add-Member -NotePropertyName Endpoints -NotePropertyValue ([pscustomobject]@{}) }
    if ($config.Kestrel.Endpoints -isnot [pscustomobject]) { throw 'Kestrel.Endpoints must be an object.' }
    $dashboard = $config.Kestrel.Endpoints.PSObject.Properties['GatewayCoreDashboard']
    if ($null -ne $dashboard) {
        if ($null -eq $dashboard.Value -or $dashboard.Value.Url -cne 'http://127.0.0.1:8080') { throw 'GatewayCoreDashboard must use the installer-owned loopback URL http://127.0.0.1:8080.' }
    } else {
        $reusableLoopbackEndpoint = $false
        foreach ($endpoint in $config.Kestrel.Endpoints.PSObject.Properties) {
            if ($null -ne $endpoint.Value -and $endpoint.Value.Url) {
                $uri = $null
                if ([Uri]::TryCreate([string]$endpoint.Value.Url, [UriKind]::Absolute, [ref]$uri) -and $uri.Port -eq 8080) {
                    $isLoopback = [Uri]::IsLoopback($uri)
                    if ($uri.Scheme -ne 'http' -or -not $isLoopback) {
                        throw 'Port 8080 is assigned to a non-loopback or non-HTTP endpoint; installer cannot safely expose the local dashboard.'
                    }
                    $reusableLoopbackEndpoint = $true
                }
            }
        }
        if (-not $reusableLoopbackEndpoint) {
            $config.Kestrel.Endpoints | Add-Member -NotePropertyName GatewayCoreDashboard -NotePropertyValue ([pscustomobject]@{ Url='http://127.0.0.1:8080' })
        }
    }
    if ($null -eq $config.AllowedHosts) { $config | Add-Member -NotePropertyName AllowedHosts -NotePropertyValue 'localhost;127.0.0.1' }
    if ($null -eq $config.GatewayCoreInstaller) { $config | Add-Member -NotePropertyName GatewayCoreInstaller -NotePropertyValue ([pscustomobject]@{}) }
    if ($config.GatewayCoreInstaller -isnot [pscustomobject]) { throw 'Installer configuration metadata must be an object.' }
    $version = 0
    if ($null -ne $config.GatewayCoreInstaller.ConfigurationSchemaVersion) {
        $version = [int]$config.GatewayCoreInstaller.ConfigurationSchemaVersion
    }
    if ($version -gt 1 -or $version -lt 0) { throw "Unsupported runtime configuration schema version: $version" }
    if ($version -lt 1) {
        $config.GatewayCoreInstaller | Add-Member -NotePropertyName ConfigurationSchemaVersion -NotePropertyValue 1 -Force
    }
    return $config
}

function Write-AtomicConfig([object]$Config, [string]$Path) {
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $json = ConvertTo-Json -InputObject $Config -Depth 100
    [IO.File]::WriteAllText($temp, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) {
        [IO.File]::Replace($temp, $Path, $null, $true)
    } else {
        [IO.File]::Move($temp, $Path)
    }
}

function Assert-OwnedService([object]$Service) {
    if ($null -eq $Service) { return $null }
    $match = [regex]::Match([string]$Service.PathName, '"(?<exe>[^"]+\\GatewayCoreYarp\.exe)"|(?<exe>.+?\\GatewayCoreYarp\.exe)(?:\s|$)', 'IgnoreCase')
    if (-not $match.Success) { throw 'A service with the GatewayCore service name exists but its executable cannot be verified. No changes were made.' }
    $exe = [IO.Path]::GetFullPath($match.Groups['exe'].Value)
    $labRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'GatewayCore\Lab')) + '\'
    if (-not $exe.StartsWith($labRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $exe -notmatch '\\Lab\\[0-9a-f]{40}\\app\\GatewayCoreYarp\.exe$') {
        throw 'Existing service is outside the supported GatewayCore Lab version layout. No changes were made.'
    }
    return $exe
}

function Wait-ServiceHealth([int]$TimeoutSeconds, [switch]$SkipTestInjection) {
    $testFailureMarker = Join-Path $env:TEMP "GatewayCoreYarp-installer-fail-health-$SourceCommit"
    if (-not $SkipTestInjection -and (Test-Path -LiteralPath $testFailureMarker) -and
        $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') {
        throw 'Disposable acceptance requested a controlled service health failure.'
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            try {
                $reply = Invoke-WebRequest -UseBasicParsing -Method Get -Uri 'http://127.0.0.1:8080/gateway/health' -TimeoutSec 3
                if ($reply.StatusCode -eq 200 -and (($reply.Content | ConvertFrom-Json).status -eq 'healthy')) { return }
            } catch { }
        }
        Start-Sleep -Milliseconds 400
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'GatewayCore service did not pass the loopback health check before the startup deadline.'
}

function Invoke-Sc([string[]]$Arguments) {
    & "$env:WINDIR\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Windows Service Control Manager operation failed (sc.exe $($Arguments -join ' '), exit $LASTEXITCODE)." }
}

Assert-Administrator
Assert-Prerequisites
if ($installRoot.TrimEnd('\') -ne $expectedRoot.TrimEnd('\')) { throw 'Installer path is not the unique versioned Program Files directory.' }
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) { throw 'The self-contained GatewayCore executable is missing.' }
if (Test-Path -LiteralPath $readyMarker) { Remove-Item -LiteralPath $readyMarker -Force }
Assert-NoReparsePoints $productRoot
Assert-NoReparsePoints $installRoot

$lockPath = Join-Path $env:ProgramData 'GatewayCoreYarp.install.lock'
$lock = $null
$backupPath = $null
$previousService = $null
$previousWasRunning = $false
$previousEnvironment = @()
$previousStart = $null
$previousImagePath = $null
    $previousProductRootSddl = $null
    $previousServiceIdentity = $null
    $previousFailureActions = $null
    $previousFailureActionsOnNonCrash = $null
    $previousDescription = $null
$stateExisted = Test-Path -LiteralPath $stateRoot
$configExisted = Test-Path -LiteralPath $configPath
$stateAclManifest = @()
$originalConfig = $null
$sourceConfig = $null
$serviceCreated = $false
$serviceChanged = $false
$migrationStarted = $false
$transactionSucceeded = $false

try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    if (Test-Path -LiteralPath $productRoot) {
        $rootAcl = Get-Acl -LiteralPath $productRoot
        if (-not $rootAcl.AreAccessRulesProtected) { throw 'Existing ProgramData root has inherited permissions; preserve it and perform a separately reviewed ACL migration.' }
        $allowedRootPrincipals = @(
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null).Value,
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null).Value,
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null).Value
        )
        foreach ($rule in $rootAcl.GetAcmˆ◊õhëÈÏ∂ªßq´^uöXŸRŸ^T]Sò[YH[ùö\õ€õY[ùQ\úõ‹êX›[€à⁄[[ùP€€ù[ùYBàBàYà
	ù[[ôH	ô]ö[›\—òZ[\ôPX›[€ú H¬àô]ÀR][Tõ‹\ùHS]\ò[]	Ÿ\ùöXŸRŸ^T]Sò[YHòZ[\ôPX›[€ú»Tõ‹\ùU\Hö[ò\ûHUò[YH	ô]ö[›\—òZ[\ôPX›[€ú»Qõ‹òŸH›]Sù[àH[ŸH»ô[[›ôKR][Tõ‹\ùHS]\ò[]	Ÿ\ùöXŸRŸ^T]Sò[YHòZ[\ôPX›[€ú»Q\úõ‹êX›[€à⁄[[ùP€€ù[ùYHBàYà
	ù[[ôH	ô]ö[›\—òZ[\ôPX›[€ú”€ìõ€ê‹ò\⁄
H¬àô]ÀR][Tõ‹\ùHS]\ò[]	Ÿ\ùöXŸRŸ^T]Sò[YHòZ[\ôPX›[€ú”€ìõ€ê‹ò\⁄òZ[\ô\»Tõ‹\ùU\H€‹ôUò[YH	ô]ö[›\—òZ[\ôPX›[€ú”€ìõ€ê‹ò\⁄Qõ‹òŸH›]Sù[àH[ŸH»ô[[›ôKR][Tõ‹\ùHS]\ò[]	Ÿ\ùöXŸRŸ^T]Sò[YHòZ[\ôPX›[€ú”€ìõ€ê‹ò\⁄òZ[\ô\»Q\úõ‹êX›[€à⁄[[ùP€€ù[ùYHBàYà
	ù[[ôH	ô]ö[›\—\ÿ‹ö\[€äH¬à[ùõ⁄ŸKTÿ»
	Ÿ\ÿ‹ö\[€âÀ	Ÿ\ùöXŸSò[YK‹›ö[ô◊Iô]ö[›\—\ÿ‹ö\[€äBàBàYà
	ô]ö[›\’ÿ\‘ù[õö[ô H¬à›\ùTŸ\ùöXŸHSò[YH	Ÿ\ùöXŸSò[YBàÿZ]TŸ\ùöXŸRX[åT⁄⁄\\›[öôX›[€ÇàBàBàHÿ]⁄»	õ€òX⁄—\úõ‹úÀêY
ê€›[õ›ô\›‹ôHö[‹àŸ\ùöXŸNà	
	Àë^Ÿ\[€ãìY\‹ÿYŸJHäHBàYà
\›T]S]\ò[]	ôXYSX\öŸ\äH»ô[[›ôKR][HS]\ò[]	ôXYSX\öŸ\àQõ‹òŸHBàYà
	õ€òX⁄—\úõ‹úÀê€›[ùY›
H¬àõ›»îŸ]\òZ[Yà	
	òZ[\ôKë^Ÿ\[€ãìY\‹ÿYŸJHõ€òX⁄»ÿ\»[ò€€\]N»ô\Ÿ\ùôH[ú›[\àòX⁄›\	…òX⁄›\]	»[ô[ùô\›Yÿ]Nà	
	õ€òX⁄—\úõ‹ú»Zõ⁄[à	Œ»	 HÇàBàõ›»îŸ]\òZ[Y[ôHö[‹àŸ\ùöXŸKÿ€€ôöY›\ò][€àÿ\»ô\›‹ôYàòX⁄›\à	…òX⁄›\]	Ààÿ]\ŸNà	
	òZ[\ôKë^Ÿ\[€ãìY\‹ÿYŸJHÇüHö[ò[H¬àYà
	ù[[ôH	ÿ⁄ H»	ÿ⁄Àë\‹‹ŸJ
HBüBÇöYà
[õ›	ò[úÿX›[€î›XÿŸYYY
H»õ›»	‘Ÿ]\ò[úÿX›[€àYõ›ôXX⁄Hô\öYöYYX[H›]Kâ»B