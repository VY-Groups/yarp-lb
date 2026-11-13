# Run on a connected Windows laptop, not necessarily on the air-gapped gateway.
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path 'C:\YARP-Packages' -Force | Out-Null
$url='https://api.nuget.org/v3-flatcontainer/system.directoryservices.protocols/10.0.15/system.directoryservices.protocols.10.0.15.nupkg'
$dest='C:\YARP-Packages\System.DirectoryServices.Protocols.10.0.15.nupkg'
Invoke-WebRequest -Uri $url -OutFile $dest
Get-FileHash -Path $dest -Algorithm SHA256
Write-Host 'Copy this NuGet file to the same C:\YARP-Packages folder on your offline Windows Server.'
