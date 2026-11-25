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
        $allowed = @(
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null).Value,
            [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null).Value,
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        )
        $localServiceSid = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null).Value
        if ($IncludeLocalService) { $allowed += $localServiceSid }
        $rules = @($existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -notin $allowed) {
                throw "Existing private installer directory grants access to an unapproved identity: $Path"
            }
            if (-not $IncludeLocalService -and $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $rule.IdentityReference.Value -eq $localServiceSid) {
                throw "Installer backup directory must not be readable by the GatewayCore service account: $Path"
            }
        }
        if (-not $existing.AreAccessRulesProtected) {
            # Existing product subdirectories can have been created by the
            # service and inherit from a previously secured product parent.
            # Validate every inherited allow above before replacing inheritance
            # with the exact product ACL; never normalize a broad grant.
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
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    $sid, [Security.AccessControl.FileSystemRights]::FullControl,
                    ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow))
            }
            Set-Acl -LiteralPath $Path -AclObject $acl
            return
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
    $reverseProxyProperty = $config.PSObject.Properties['ReverseProxy']
    if ($null -eq $reverseProxyProperty -or $null -eq $reverseProxyProperty.Value) {
        $config | Add-Member -NotePropertyName ReverseProxy -NotePropertyValue ([pscustomobject]@{ Routes=[pscustomobject]@{}; Clusters=[pscustomobject]@{} }) -Force
    }
    $reverseProxy = $config.PSObject.Properties['ReverseProxy'].Value
    if ($reverseProxy -isnot [pscustomobject]) { throw 'ReverseProxy configuration must be an object; migration stopped without discarding it.' }
    foreach ($name in @('Routes','Clusters')) {
        $member = $reverseProxy.PSObject.Properties[$name]
        if ($null -eq $member -or $null -eq $member.Value) { $reverseProxy | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{}) -Force }
        if ($reverseProxy.PSObject.Properties[$name].Value -isnot [pscustomobject]) { throw "ReverseProxy.$name must be an object; migration stopped without rewriting it." }
    }
    $kestrelProperty = $config.PSObject.Properties['Kestrel']
    if ($null -eq $kestrelProperty -or $null -eq $kestrelProperty.Value) {
        $config | Add-Member -NotePropertyName Kestrel -NotePropertyValue ([pscustomobject]@{ Endpoints=[pscustomobject]@{} }) -Force
    }
    $kestrel = $config.PSObject.Properties['Kestrel'].Value
    if ($kestrel -isnot [pscustomobject]) { throw 'Kestrel configuration must be an object.' }
    $endpointsProperty = $kestrel.PSObject.Properties['Endpoints']
    if ($null -eq $endpointsProperty -or $null -eq $endpointsProperty.Value) { $kestrel | Add-Member -NotePropertyName Endpoints -NotePropertyValue ([pscustomobject]@{}) -Force }
    $endpoints = $kestrel.PSObject.Properties['Endpoints'].Value
    if ($endpoints -isnot [pscustomobject]) { throw 'Kestrel.Endpoints must be an object.' }
    $dashboard = $endpoints.PSObject.Properties['GatewayCoreDashboard']
    if ($null -ne $dashboard) {
        $dashboardUrl = if ($null -eq $dashboard.Value) { $null } else { $dashboard.Value.PSObject.Properties['Url'] }
        if ($null -eq $dashboardUrl -or $dashboardUrl.Value -cne 'http://127.0.0.1:8080') { throw 'GatewayCoreDashboard must use the installer-owned loopback URL http://127.0.0.1:8080.' }
    } else {
        # An IPv6-only ::1 listener cannot satisfy the installer's IPv4
        # health probe or its desktop dashboard shortcut. Preserve it, and
        # provision a separate IPv4 loopback listener for the management UI.
        $hasIPv4LoopbackEndpoint = $false
        foreach ($endpoint in $endpoints.PSObject.Properties) {
            $endpointUrl = if ($null -eq $endpoint.Value) { $null } else { $endpoint.Value.PSObject.Properties['Url'] }
            if ($null -ne $endpointUrl -and $endpointUrl.Value) {
                $uri = $null
                if ([Uri]::TryCreate([string]$endpointUrl.Value, [UriKind]::Absolute, [ref]$uri) -and $uri.Port -eq 8080) {
                    if ($uri.Scheme -ne 'http' -or -not $uri.IsLoopback -or
                        $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) {
                        throw 'Port 8080 is assigned to a non-loopback or incompatible endpoint; installer cannot safely expose the local dashboard.'
                    }
                    # ASP.NET Core localhost binds loopback on both families.
                    # ::1 binds IPv6 only, so do not count it as IPv4-ready.
                    if ($uri.Host.Trim('[',']') -ne '::1') { $hasIPv4LoopbackEndpoint = $true }
                }
            }
        }
        if (-not $hasIPv4LoopbackEndpoint) {
            $endpoints | Add-Member -NotePropertyName GatewayCoreDashboard -NotePropertyValue ([pscustomobject]@{ Url='http://127.0.0.1:8080' })
            $hosts = $config.PSObject.Properties['AllowedHosts']
            if ($null -ne $hosts -and $hosts.Value -is [string] -and $hosts.Value -and $hosts.Value -ne '*' -and ($hosts.Value -split ';') -notcontains '127.0.0.1') {
                $hosts.Value = $hosts.Value.TrimEnd(';') + ';127.0.0.1'
            }
        }
    }
    if ($null -eq $config.PSObject.Properties['AllowedHosts']) { $config | Add-Member -NotePropertyName AllowedHosts -NotePropertyValue 'localhost;127.0.0.1' }
    $installerProperty = $config.PSObject.Properties['GatewayCoreInstaller']
    if ($null -eq $installerProperty -or $null -eq $installerProperty.Value) { $config | Add-Member -NotePropertyName GatewayCoreInstaller -NotePropertyValue ([pscustomobject]@{}) -Force }
    $installer = $config.PSObject.Properties['GatewayCoreInstaller'].Value
    if ($installer -isnot [pscustomobject]) { throw 'Installer configuration metadata must be an object.' }
    $version = 0
    $versionProperty = $installer.PSObject.Properties['ConfigurationSchemaVersion']
    if ($null -ne $versionProperty -and $null -ne $versionProperty.Value) {
        $version = [int]$versionProperty.Value
    }
    if ($version -gt 1 -or $version -lt 0) { throw "Unsupported runtime configuration schema version: $version" }
    if ($version -lt 1) {
        $installer | Add-Member -NotePropertyName ConfigurationSchemaVersion -NotePropertyValue 1 -Force
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
        foreach ($rule in $rootAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin $allowedRootPrincipals) {
                throw 'Existing ProgramData root grants access to an unapproved identity; preserve it and perform a separately reviewed ACL migration.'
            }
        }
        $previousProductRootSddl = $rootAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
    } else {
        Set-ProductRootAcl $productRoot
    }
    $previousService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
    $previousExecutable = Assert-OwnedService $previousService
    $previousWasRunning = $null -ne $previousService -and $previousService.State -eq 'Running'
    if ($null -ne $previousService) {
        $previousImagePath = [string]$previousService.PathName
        $previousStart = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName").Start
        $previousServiceIdentity = [string]$previousService.StartName
        if ($previousServiceIdentity -notin @('NT AUTHORITY\LocalService','LocalSystem')) {
            throw 'In-place upgrade supports only LocalService or LocalSystem service identities; preserve the existing installation and use a reviewed service-account migration.'
        }
        $oldServiceProperties = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        if ($null -ne $oldServiceProperties.PSObject.Properties['FailureActions']) { $previousFailureActions = $oldServiceProperties.FailureActions }
        if ($null -ne $oldServiceProperties.PSObject.Properties['FailureActionsOnNonCrashFailures']) { $previousFailureActionsOnNonCrash = $oldServiceProperties.FailureActionsOnNonCrashFailures }
        if ($null -ne $oldServiceProperties.PSObject.Properties['Description']) { $previousDescription = $oldServiceProperties.Description }
        $previousEnvironment = Read-ServiceEnvironment $serviceName
        $sourceConfig = Get-ConfigSource $previousService $previousEnvironment
    }
    if ($configExisted) { $sourceConfig = $configPath }
    if (-not $sourceConfig -and $null -eq $previousService) {
        $legacyCandidates = @(Get-ChildItem -LiteralPath (Join-Path $env:ProgramFiles 'GatewayCore\Lab') -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[0-9a-f]{40}$' -and $_.FullName -ne $installRoot } |
            ForEach-Object { Join-Path $_.FullName 'app\appsettings.json' } | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
        if ($legacyCandidates.Count -gt 1) { throw 'Multiple old GatewayCore configurations were found; choose the active one manually before setup.' }
        if ($legacyCandidates.Count -eq 1) { $sourceConfig = [IO.Path]::GetFullPath($legacyCandidates[0]) }
    }

    $stateAclManifest = Get-TreeAclManifest $stateRoot
    $backupId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + $SourceCommit.Substring(0,12)
    $backupPath = Join-Path $backupRoot $backupId
    New-ProductAcl -Path $backupRoot
    New-ProductAcl -Path $backupPath
    if ($stateExisted) {
        $stateFiles = Get-FileManifest $stateRoot
        $backupState = Join-Path $backupPath 'ControlPlane'
        Copy-VerifiedState $stateRoot $backupState $stateFiles
        foreach ($item in @((Get-Item -LiteralPath $backupState -Force)) + @(Get-ChildItem -LiteralPath $backupState -Force -Recurse)) {
            Set-BackupAcl $item.FullName
        }
        $stateAclManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $backupPath 'ControlPlane-acl.json') -Encoding UTF8
        $stateFiles | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $backupPath 'ControlPlane-sha256.json') -Encoding UTF8
    }
    if ($sourceConfig -and $sourceConfig -ne $configPath) {
        $configBackup = Join-Path $backupPath 'source-appsettings.json'
        Copy-Item -LiteralPath $sourceConfig -Destination $configBackup -Force
        if ((Get-FileHash $sourceConfig -Algorithm SHA256).Hash -ne (Get-FileHash $configBackup -Algorithm SHA256).Hash) { throw 'Runtime config backup verification failed.' }
        Set-BackupAcl $configBackup
        $originalConfig = $null
    } elseif ($configExisted) {
        $originalConfig = [IO.File]::ReadAllBytes($configPath)
    }

    $serviceKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $migrationStarted = $true
    if ($null -ne $previousProductRootSddl) { Set-ProductRootAcl $productRoot }
    if ($previousWasRunning) {
        Stop-Service -Name $serviceName
        (Get-Service $serviceName).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(60))
    }
    foreach ($path in @($stateRoot, $configRoot)) {
        if (-not (Test-Path -LiteralPath $path)) { New-ProductAcl -Path $path -IncludeLocalService }
    }
    $config = ConvertTo-ManagedConfig $sourceConfig
    Write-AtomicConfig $config $configPath
    Assert-NoReparsePoints $stateRoot
    foreach ($item in @((Get-Item -LiteralPath $stateRoot -Force)) + @(Get-ChildItem -LiteralPath $stateRoot -Force -Recurse)) {
        Set-StateAcl $item.FullName
    }
    $environment = @("YARP_RUNTIME_CONFIG_PATH=$configPath", 'ASPNETCORE_ENVIRONMENT=Production')

    if ($null -eq $previousService) {
        Invoke-Sc @('create',$serviceName,'binPath=',('"{0}"' -f $exePath),'start=','auto','obj=','NT AUTHORITY\LocalService','DisplayName=','GatewayCore Lab')
        $serviceCreated = $true
    } else {
        $serviceChanged = $true
        Invoke-Sc @('config',$serviceName,'binPath=',('"{0}"' -f $exePath),'start=','auto','obj=','NT AUTHORITY\LocalService')
    }
    if (-not (Test-Path -LiteralPath $serviceKeyPath)) { throw 'SCM service registration did not create its service key.' }
    New-ItemProperty -LiteralPath $serviceKeyPath -Name Environment -PropertyType MultiString -Value $environment -Force | Out-Null
    Invoke-Sc @('description',$serviceName,'GatewayCore Lab gateway and local control center')
    Invoke-Sc @('failure',$serviceName,'reset=','86400','actions=','restart/5000/restart/15000/restart/60000')
    Start-Service -Name $serviceName
    Wait-ServiceHealth $HealthTimeoutSeconds

    $liveService = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($null -eq $liveService -or $liveService.StartName -ne 'NT AUTHORITY\LocalService' -or $liveService.StartMode -ne 'Auto') {
        throw 'The running service does not have the required LocalService / automatic-start settings.'
    }
    foreach ($dir in @($stateRoot,$configRoot,(Join-Path $stateRoot 'data-protection-keys'))) {
        if (-not (Test-Path -LiteralPath $dir) -or -not (Get-Acl -LiteralPath $dir).AreAccessRulesProtected) { throw "Protected service-state ACL verification failed: $dir" }
    }
    [IO.File]::WriteAllText($readyMarker, $SourceCommit, [Text.Encoding]::ASCII)
    $transactionSucceeded = $true
    Write-Host "GatewayCore Lab is installed and healthy. Rollback backup: $backupPath"
} catch {
    $failure = $_
    $rollbackErrors = [Collections.Generic.List[string]]::new()
    try {
        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -ErrorAction Stop
            $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(60))
        }
    } catch { $rollbackErrors.Add("Could not stop failed service: $($_.Exception.Message)") }
    if ($migrationStarted) {
        try {
            if ($configExisted -and $null -ne $originalConfig) {
                [IO.File]::WriteAllBytes($configPath, $originalConfig)
            } elseif (-not $configExisted -and (Test-Path -LiteralPath $configPath)) {
                Remove-Item -LiteralPath $configPath -Force
            } elseif ($sourceConfig -and $sourceConfig -ne $configPath -and (Test-Path -LiteralPath $sourceConfig)) {
                # The old file was never removed or modified; only the new migrated copy is discarded.
                if (Test-Path -LiteralPath $configPath) { Remove-Item -LiteralPath $configPath -Force }
            }
            Restore-TreeAclManifest $stateRoot $stateAclManifest
            if ($null -ne $previousProductRootSddl) {
                $rootRestore = [Security.AccessControl.DirectorySecurity]::new()
                $rootRestore.SetSecurityDescriptorSddlForm($previousProductRootSddl, [Security.AccessControl.AccessControlSections]::Access)
                Set-Acl -LiteralPath $productRoot -AclObject $rootRestore
            }
        } catch { $rollbackErrors.Add("Could not fully restore config/state ACLs: $($_.Exception.Message)") }
    }
    try {
        if ($serviceCreated) {
            Invoke-Sc @('delete',$serviceName)
        } elseif ($serviceChanged) {
            $oldStartMode = switch ($previousStart) { 0 {'boot'} 1 {'system'} 2 {'auto'} 3 {'demand'} 4 {'disabled'} default { throw "Unsupported prior SCM start mode: $previousStart" } }
            Invoke-Sc @('config',$serviceName,'binPath=',$previousImagePath,'start=',$oldStartMode,'obj=',('"{0}"' -f $previousServiceIdentity))
            if ($previousEnvironment.Count -gt 0) {
                New-ItemProperty -LiteralPath $serviceKeyPath -Name Environment -PropertyType MultiString -Value $previousEnvironment -Force | Out-Null
            } else {
                Remove-ItemProperty -LiteralPath $serviceKeyPath -Name Environment -ErrorAction SilentlyContinue
            }
            if ($null -ne $previousFailureActions) {
                New-ItemProperty -LiteralPath $serviceKeyPath -Name FailureActions -PropertyType Binary -Value $previousFailureActions -Force | Out-Null
            } else { Remove-ItemProperty -LiteralPath $serviceKeyPath -Name FailureActions -ErrorAction SilentlyContinue }
            if ($null -ne $previousFailureActionsOnNonCrash) {
                New-ItemProperty -LiteralPath $serviceKeyPath -Name FailureActionsOnNonCrashFailures -PropertyType DWord -Value $previousFailureActionsOnNonCrash -Force | Out-Null
            } else { Remove-ItemProperty -LiteralPath $serviceKeyPath -Name FailureActionsOnNonCrashFailures -ErrorAction SilentlyContinue }
            if ($null -ne $previousDescription) {
                Invoke-Sc @('description',$serviceName,[string]$previousDescription)
            }
            if ($previousWasRunning) {
                Start-Service -Name $serviceName
                Wait-ServiceHealth 60 -SkipTestInjection
            }
        }
    } catch { $rollbackErrors.Add("Could not restore prior service: $($_.Exception.Message)") }
    if (Test-Path -LiteralPath $readyMarker) { Remove-Item -LiteralPath $readyMarker -Force }
    if ($rollbackErrors.Count -gt 0) {
        throw "Setup failed: $($failure.Exception.Message) Rollback was incomplete; preserve installer backup '$backupPath' and investigate: $($rollbackErrors -join '; ')"
    }
    throw "Setup failed and the prior service/configuration was restored. Backup: '$backupPath'. Cause: $($failure.Exception.Message)"
} finally {
    if ($null -ne $lock) { $lock.Dispose() }
}

if (-not $transactionSucceeded) { throw 'Setup transaction did not reach a verified healthy state.' }
