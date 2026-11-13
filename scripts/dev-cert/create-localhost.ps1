# Windows PowerShell 5.1+ / disposable development machine only.
# No purchased SSL certificate needed. Does NOT automatically trust the cert.
param([string]$OutputDirectory = ".\\.local-dev-cert")
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:DEV_PFX_PASSWORD)) {
    throw "Set DEV_PFX_PASSWORD before generating a temporary localhost PFX"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$folder = (Resolve-Path $OutputDirectory).Path
$cert = New-SelfSignedCertificate -DnsName "localhost" `
    -CertStoreLocation "Cert:\\CurrentUser\\My" -Type SSLServerAuthentication `
    -KeyAlgorithm RSA -KeyLength 3072 -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddDays(7)
$password = ConvertTo-SecureString $env:DEV_PFX_PASSWORD -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath (Join-Path $folder "localhost.pfx") `
    -Password $password -Force | Out-Null
Export-Certificate -Cert $cert -FilePath (Join-Path $folder "localhost.cer") `
    -Force | Out-Null
Write-Host "Generated temporary localhost PFX in $folder."
Write-Host "Manually trust the public certificate only on isolated local test machines."
Write-Host "Never commit or deploy the PFX on public/production CA or eSign servers."
