# Issue #51 — matched Windows/Linux WAF capacity evidence

**Software contract only; no measured customer performance or release GO is
claimed.** \`ops/waf/matched_platform_capacity_gate.py\` fails closed unless
the operator supplies a full **60-minute or longer** matching test series
for each of the six combinations:

| Platform | Direct origin | Shipping YARP | Shipping YARP + actual external WAF |
|---|---|---|---|
| Windows Server | required | required | required |
| Ubuntu/RHEL-compatible Linux | required | required | required |

A software-only lab may use separate disposable isolated Windows and Linux
servers with matched deployment revisions and fixture workloads; an actual
production physical site qualifies under #36 separately. Neither a 120-request
Docker benchmark nor synthetic unit-test rows can qualify the service or the
site.

## Required independent approval BEFORE load

The strict policy is a **separate, reviewed JSON file** with these exact
fields. All examples below are types, not approved values; the actual
performance caps and source hashes must come from the operator's change
approval and immutable build:

- \`schemaVersion=1\`, exact 40-character lowercase source commit SHA
- \`wafImageDigest\` pinned to \`owasp/modsecurity-crs@sha256:...\`
- \`trafficProfileSha256\` of the approved complete fixed payload/connection
  mix and approved concurrency, ALPN, keepalive, TLS/HTTP version
- \`windowSeconds\` 60/120/300 and \`windowCount*windowSeconds >= 3600\`
- \`peakBodyGbps\` independently measured peak of at least **0.5 Gbps**, \`headroom\` exactly 0.30 or 0.50. Smaller declared peaks fail closed; larger approved peaks remain valid
- pre-approved \`maxP95Ms\`, \`maxP99Ms\`,
  \`maxWafP99Multiplier\`, \`maxCpuUtilizationPercent\`,
  \`maxAllocatedBytesPerRequest\`, \`maxGcPauseMsPerWindow\`
- \`allowedHttpStatus=[200]\` only

For a confirmed peak of **500 megabits/s** the minimum observed body-byte
throughput is **650 Mbps (30%)** or **750 Mbps (50%)**, in **every**
measured minute. The 500 Mb/s value was user-reported; independently verify
actual link and request-size distribution before locking the policy. It does
not allow counting network framing, HTTP headers or retries as response-body
capacity. Preserve p99/CPU/allocation caps from the original approval;
do not derive them from the actual results.

## Per-window source requirements

\`--evidence\` is a private JSON with \`schemaVersion=1\` and
\`runs.windows\` / \`runs.linux\` objects each containing exactly
\`direct\`, \`yarp\` and \`yarp_waf\`. Each run identifies the same source
commit, traffic profile digest, concurrency, HTTP version, keepalive and
window length. Only the WAF path requires the actual pinned WAF image digest;
other paths must explicitly have \`wafImageDigest: null\`.

Each sequential window contains
\`index,startUtc,endUtc,requests,errors,unexpectedStatuses,responseBodyBytes,
p95Ms,p99Ms,cpuSeconds,allocatedBytes,gcPauseMs,rawWindowSha256\`.
Windows are ordered, monotonic, UTC, gap-bounded, long enough and all six
runs must cover at least 3600 seconds. The raw window hash is a **unique**
uppercase SHA-256. Managed allocation/GC values must be present for
YARP/YARP+WAF; origin-only numbers are null rather than fabricated.
\`cpuSeconds\` means CPU-core seconds across the explicitly measured host
process group, and \`hostCpuCores\` is the measured group's available core
count. Errors, unexpected HTTP statuses, CPU excess, allocation/GC excess,
short/omitted windows, unpinned image, different profiles or p99 violations
produce **NO-GO**.

Run, from an approved *isolated* measurement workstation using actual
signed evidence held privately:

\`\`\`sh
python3 ops/waf/matched_platform_capacity_gate.py \
  --policy /private/waf/approved-three-path-policy.json \
  --evidence /private/waf/observed-windows-6-runs.json \
  --out /private/waf/results/three-path-acceptance-001.json
\`\`\`

The script uses the canonical WAF bounded no-follow input reader and private,
new-only 0600 report writer. The report includes the explicitly non-production
flags \`productionGo:false\` and \`sourceCustodyVerified:false\`. Keep native
oha/k6 run files, perf counters, OS/runtime, .NET GC/alloc samples, SHA-256
bindings, WAF audit verdicts and route-labeled benign/malicious truth tables
under independent protected custody. **This tool does not cryptographically
verify raw-window source custody, independently authenticate a measurement
signer, execute any traffic, attest physical host network isolation or prove
the real operator supplied representative Windows/Linux results.**
Those missing proofs must remain acceptance gates; a synthetic fixture
returning GO is never production GO.

Developers can test the strict software contract with:

\`\`\`sh
python3 -m unittest discover -s ops/waf -p test_matched_platform_capacity_gate.py -v
\`\`\`

This augments the existing real origin/YARP capacity kit under
\`ops/capacity/\` and disposable WAF Docker resource counters; it does not
replace either real generator or the final #36 site capacity/HA drill.
Issue #51 remains open until genuine measured, independently approved
software-integrated comparison evidence and other WAF acceptance gates exist.
