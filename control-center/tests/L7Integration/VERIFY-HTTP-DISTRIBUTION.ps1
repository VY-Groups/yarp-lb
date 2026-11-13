# Read-only HTTP verifier. Works only after the operator creates a LAB route
# to TWO mock backends through the browser and approves the route configuration.
[CmdletBinding()]
param(
  [string]$GatewayUrl = 'http://127.0.0.1:8080/api/identity',
  [string]$HostHeader = 'lab.example.test',
  [ValidateRange(20,2000)][int]$Requests = 200,
  [ValidateRange(0,100)][int]$MinEachPercent = 10
)
$ErrorActionPreference = 'Stop'
$counts=@{}
for($i=0;$i -lt $Requests;$i++) {
    $result=Invoke-RestMethod -Uri $GatewayUrl -Headers @{Host=$HostHeader} -TimeoutSec 10 -ErrorAction Stop
    $node=[string]$result.node
    if ([string]::IsNullOrWhiteSpace($node)) { throw "Missing node identity in response $i" }
    if (!$counts.ContainsKey($node)) { $counts[$node]=0 }
    $counts[$node]++
}
$summary=@($counts.GetEnumerator() | Sort-Object Name | ForEach-Object {
    [pscustomobject]@{ Node=$_.Key; Requests=$_.Value; Share=[math]::Round(100*$_.Value/$Requests,2) }
})
$summary | Format-Table -AutoSize
if($summary.Count -lt 2){throw 'FAIL: requests did not reach both lab backends'}
if(@($summary | Where-Object {$_.Share -lt $MinEachPercent}).Count -gt 0){throw 'FAIL: an active backend received fewer requests than minimum threshold'}
Write-Host 'PASS: real HTTP responses reached both configured lab backends. Health and failover tests still required.' -ForegroundColor Green
