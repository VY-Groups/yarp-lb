# External WAF: ModSecurity + OWASP Core Rule Set (CRS) — experimental integration

The WAF uses an upstream-maintained OWASP CRS image pinned by OCI manifest digest in `compose.lab.yml`, **not** a home-grown security regex filter. The digest was resolved from the official Docker Registry for the upstream stable `4-nginx-alpine-202611190211` tag on 2026-11-20; test runs record the selected digest and verify the same image is used for every policy-mode restart. The disposable CI lab places CRS in front of an unexposed backend and sends real requests through the WAF. Tests assert benign HTTP traffic passes while XSS, SQL injection, and path traversal inputs are blocked in the disposable lab. A separate detection-only pass checks that the same XSS payload is not blocked; evidence is logged for review. A bounded request-body test checks the configured limit. The backend is not published to the runner.

Upstream official docs: https://github.com/coreruleset/modsecurity-crs-docker

## Lab
```bash
bash tests/WafCrs/verify.sh
```

It binds 127.0.0.1:18888 and creates a Docker-private backend network. It captures container logs and removes temporary containers and the network.

## Production gaps

This pinned image snapshot is **lab-only**. Production still requires a maintained image-update cadence with reviewed immutable digests and security updates, HTTPS/TLS and backend trust, inbound protection placement, bypass prevention, anomaly tuning and application-specific exclusions, rule governance, false-positive and performance tests, privacy-safe audit retention, DDoS protection and external load balancing. Blocking one XSS signature is not a comprehensive WAF/security compliance assertion. Control-center WAF provisioning is **not** integrated; mark capability as partial external integration only.


## Extended CI checks (experimental)

The lab uses `MODSEC_RULE_ENGINE=On` for blocking acceptance, then explicitly restarts the WAF with `WAF_MODE=DetectionOnly` and expects the XSS payload to pass. That is a **mode behavior check**, not a false-positive assessment on real user traffic. In blocking mode, a small benign corpus now checks JSON, XML, and a generated ~31 KiB JSON upload. The bounded backend returns only an acceptance marker, content type, and byte count; it never reflects or logs bodies. This corpus is a regression fixture, not a measured false-positive rate or representative customer traffic study. The lab sets a 128 KiB total request-body limit and a 64 KiB in-memory body limit; an oversized POST must be rejected (the tested ModSecurity/nginx connector returns 403, not necessarily 413), and CI confirms the explicit body-limit diagnostic in the WAF audit log. CI uses intentionally representative SQLi/path traversal attacks, but this is not a substitute for the full upstream CRS regression suite. Audit logs are uploaded from disposable CI runners only; production logs require sanitization and retention policies.

**Important:** an edge-only WAF cannot stop direct origin access. Keep the backend private, pin an upstream container digest for production, set and audit policy exclusions with real traffic in detection-only mode, and measure throughput/latency against an unprotected control. Ruleset updates must go through an independently approved signed and reversible deployment path, which does not yet exist.

## Corpus evidence artifact

`artifacts/waf-crs/blocking-corpus-report.json` records the fixed synthetic blocking corpus by case and route, with HTTP status, expected class, TP/TN/FP/FN counts, missing and unexpected responses. Incomplete runs retain explicitly missing results and do not publish false-positive/false-negative rates. The test requires every fixture to complete without a false positive or false negative. The report contains no request payloads and excludes body-limit and detection-only checks, which retain their existing separate assertions. This is a small synthetic regression corpus, not a production false-positive/false-negative estimate or a replacement for an agreed representative corpus, severity analysis, or load testing.

## Immutable lab image and matched mode comparison

For a repeatable lab use `bash tests/WafCrs/verify.sh`; its default is the reviewed upstream digest in `compose.lab.yml`. An explicit `WAF_IMAGE` override must also be an upstream repository digest. The script records the selected digest, pins every mode restart to it, and checks the actual image ID. Digest pinning does not establish trusted signature provenance or a reviewed production update process. The benchmark runs a separate disposable client on the private compose network, never publishing the backend. Each phase performs 120 alternating fixed GET and JSON POST requests at concurrency four, with a fresh HTTP/1 connection per request and no retry. All responses must match the expected backend marker/metadata; any transport, status or body error fails the phase. Artifacts include per-phase successful throughput and p50/p95/p99 from monotonic timings, only percentile values for complete runs. The five phases are direct origin, blocking CRS, detection-only CRS, nginx-only proxy (ModSecurity off, disposable lab only), and restored blocking mode; the restored phase independently requires a known XSS to be blocked again. This is a synthetic nginx comparison, not direct-vs-YARP-vs-WAF capacity or a representative customer workload. No latency/throughput production target is inferred or relaxed; CPU, memory, allocations, repeated sustained runs, production signed policy approval, rule exclusions and representative corpus acceptance remain open. Do not use the proxy-only mode on a deployed edge.

## Expanded harmless-traffic ground truth

The disposable CI corpus now sends a real self-signed **public** X.509 DER certificate with `application/pkix-cert` through the WAF to the bounded, body-redacting acceptance backend. The corresponding private key is generated in a restricted temporary directory, removed on exit and **never** uploaded as an artifact. Ordinary Unicode query text and an opaque preference cookie are tested as additional benign requests. The synthetic corpus records each fixture's explicit ground-truth severity and confusion counts by route and severity; it does not infer a rule's actual CRS severity from HTTP status. Missing or unexpected results fail the blocking-corpus acceptance; there is no exception, automatic allowlisting or lowered blocking threshold. This small fixture set is not a production false-positive rate, a realistic signing-transaction workload or a WAF policy rollback certification.

### Tested PKIX false-positive exception (lab only)

[WAF CI](../../actions/runs/44860172585) found that standard CRS 4.30.0 rule `920420` rejects a valid disposable public X.509 DER upload using `application/pkix-cert`. The exact-match local rule `REQUEST-900-LAB-PKIX.conf`, mounted read-only before the CRS load, applies `ctl:ruleRemoveById=920420` **only** if method is POST, URI exactly `/acceptance`, and Content-Type exactly `application/pkix-cert`. All other CRS rules and the original anomaly threshold remain in effect. Acceptance also sends the identical certificate to `/not-allowed` and requires blocking HTTP 403 there; a global exception would fail. The local rule is not deployed, rendered, or activated by the Control Center and is not approval for a production exception. Production would require an owned, expiry-bounded, reviewed and reversible policy lifecycle under #51.

### Enforced disposable exception governance (not production authorization)

The exact `POST /acceptance` `application/pkix-cert` exclusion for CRS rule `920420` is now accompanied by [the lab policy manifest](exception-policy.lab.json). Before starting Docker, `verify.sh` runs stdlib-only tests and a preflight validator that require a single explicit fixture owner, strict method/path/content-type/rule ID, a **45-day maximum** issue-to-expiry window, a currently valid UTC expiration, and an unmodified exact ModSecurity rule mounted once as read-only. Unexpected fields, duplicate keys, broad scopes and expired policies fail closed; the existing WAF attack and outside-route negative requests remain mandatory. The CI fixture owner is **not** an approved production security owner. No runtime rule-approval API, external audit, multi-tenant policy or customer WAF deployment exists here. A real production policy needs independent review, operator ownership, recorded change/ticket, expiry enforcement, rollback and site-specific FP/FN and performance acceptance under #51.

### WAF lab Compose boundary preflight

The disposable exception preflight now validates the complete active `waf` and
`protected-app` Compose stanzas against reviewed fixture settings, not only
the exception manifest and read-only rule mount. It fails closed if a lab
revision changes the engine mode expression, body-limit rejection, inbound
anomaly threshold, audit engine, additional rule/environment inputs, WAF
loopback binding or origin isolation. Negative stdlib unit tests exercise
those mutation paths before Docker starts. This is a strict lab fixture lock,
**not** a general Compose/YAML policy parser or production WAF governance.
A legitimate lab Compose update requires a reviewed update to this fixture
contract and fresh end-to-end allow/block acceptance.

### Detection-mode attack categories and restored blocking

The disposable WAF acceptance now sends the same labeled XSS, SQL injection,
and path-traversal payloads to the `DetectionOnly` instance and proves both
that the origin received each request (HTTP 200 with the exact origin marker)
and that CRS logged the relevant 941xxx, 942xxx, and 930xxx rule families.
It writes `artifacts/waf-crs/detection-corpus-report.json` containing only the
category, status and audit-family observation, without any raw payload.
After the engine is restored to blocking mode, all three classes must return
HTTP 403. The image digest and policy remain pinned as in the existing lab.
These three disposable probes do not establish real-customer false-positive
rates, comprehensive OWASP coverage, per-customer WAF tuning or production
capacity. Issue #51 remains open for that broader acceptance.

### Private operator-supplied WAF corpus replay (#51)

The disposable WAF lab now supports an **optional real local replay** of a
security-reviewed, privately stored customer/route corpus. The runner is
`tests/WafCrs/operator_corpus_acceptance.py`, triggered only when the caller
supplies `WAF_OPERATOR_CORPUS=/private/path/corpus.json` to the existing
`bash tests/WafCrs/verify.sh` command. It runs **after** restoring the
same pinned CRS image to blocking mode; it never changes anomaly thresholds,
sends requests to public networks or repeats a potentially non-idempotent POST.
The HTTP target is hard-coded to `127.0.0.1:18888` with redirects disabled.
The fixture stays in its private original path and is not added to this
repository, written into the artifacts directory or echoed in log output.

Required strict JSON schema:
```json
{
  "schemaVersion": 1,
  "maxFalsePositives": 0,
  "maxFalseNegatives": 0,
  "cases": [
    {"id":"benign-json","route":"app","method":"POST",
     "path":"/acceptance","expected":"benign","severity":"none",
     "contentType":"application/json","body":"{}"},
    {"id":"benign-query","route":"app","method":"GET",
     "path":"/?q=normal","expected":"benign","severity":"none",
     "contentType":"text/plain","body":""},
    {"id":"xss","route":"app","method":"GET",
     "path":"/?q=<script>alert(1)</script>","expected":"malicious",
     "severity":"high","contentType":"text/plain","body":""},
    {"id":"traversal","route":"app","method":"GET",
     "path":"/?file=../../etc/passwd","expected":"malicious",
     "severity":"high","contentType":"text/plain","body":""}
  ]
}
```
This is an **example schema**, not a verified representative dataset; review
actual customer fixtures and tenant consent before use. The runner requires
4–256 uniquely named cases, at least two of each ground-truth class, strictly
bounded URI/body, GET or POST only, and a fixed allowlist of request media
types. Missing, duplicate or extra JSON fields, invalid encodings, unsafe
request targets, non-zero FP/FN allowances and oversized inputs fail before
network activity. Any benign HTTP 403 is FP; any malicious HTTP 200 reaching
the exact synthetic origin marker is FN; unexpected status/timeout/connection
errors fail separately. No retries, redirects, external targets or automatic
relaxation of CRS rules are permitted.

The output `artifacts/waf-crs/operator-corpus-report.json` contains only
case **identifiers**, pseudonymous route IDs, test-specified severity,
ground-truth class, HTTP status and TP/TN/FP/FN/ERROR counts. It omits
request paths, queries, bodies, headers, origin contents and customer
identifiers. A per-route/severity confusion matrix is included. All test
cases must match their ground truth; one false positive/negative or transport
error fails the run. The CI unit test uses its own loopback HTTP server
to verify this contract and the ability to catch missed attacks, blocked
benign requests, unexpected redirects and malicious JSON mutations.

**Not a production certification:** no private customer corpus is committed
or run by GitHub Actions, and the lab is nginx/CRS rather than a real
Windows/Linux GatewayCore/YARP production deployment. This is an acceptance
mechanism for evidence that operators must still provide and review. Real
multi-tenant rule lifecycle/approval, sustainable p95/p99/CPU/allocations,
independent Windows/Linux deployment and signed policy rollback remain open
in #51. No issue closure or production WAF GO is implied.
### Exact private backend response contract in operator corpus replay

The optional private-corpus runner now verifies the actual bounded lab
backend's method-specific success response rather than searching for a
substring marker. A successful GET must return exactly the fixed newline-
terminated text marker and its text/plain media type. A successful POST must
return the exact small JSON object `accepted=true`, expected normalized
`contentType` and exact byte count; unknown/duplicate fields, mismatched
bytes, unrelated HTTP 200 responses and malformed response bodies are
classified as **ERROR**, never accepted as a true-negative response or a
false-negative WAF bypass. Unit tests use the real backend response shape and
prove forged GET markers or POST metadata cannot pass. Request bodies and
backend payloads remain excluded from the generated report. This validates
only the disposable loopback acceptance origin, not a production backend,
customer WAF integration or the remaining #51 criteria.

### Strict benchmark origin-response evidence (#51)

The disposable five-phase synthetic benchmark rejects ambiguous or truncated
declared response lengths, duplicate HTTP Content-Length framing, unsupported
transfer encoding, and oversized or wrong-media-type origin responses. JSON
POST success requires the *exact* accepted/contentType/bytes fields with an
actual integer byte count and no duplicate JSON properties. GET requires the
exact fixed origin marker and text media type. The benchmark supports valid
chunked responses without a declared Content-Length.

Run `python3 -m unittest discover -s tests/WafCrs -p 'test_benchmark_contract.py' -v`
to exercise positive and forged-origin examples before Docker acceptance.
This prevents false benchmark successes; it does **not** provide representative
customer FP/FN, signed production rule governance, real YARP+WAF Windows
and Linux capacity, or certify issue #51 as complete.

### Operator-corpus response Transfer-Encoding validation (#51)

The private operator-corpus acceptance now rejects duplicate or unsupported
`Transfer-Encoding` response fields, `Content-Length` with any transfer coding,
and multiple `Content-Length` headers. The only accepted transfer coding is
a single `chunked` header (decoded by Python's HTTP client); ordinary exact
length or close-delimited origin-marker responses remain supported. A local
HTTP regression intentionally forges the correct origin body under an
unsupported `gzip` transfer code and must yield ERROR rather than TN.
Additional unit cases reject duplicate and combined framing declarations.
This strengthens evidence integrity, not CRS rule coverage, production rule
governance, or measured false-positive/false-negative performance.

### Whole-response validation for synthetic WAF throughput (#51)

The five-phase lab benchmark now rejects **all** duplicated
`Transfer-Encoding` response headers, mixed/combined transfer codings,
`Content-Length` conflicts, and any response whose bounded read has not
reached end-of-message. A valid HTTP status or an exact-looking prefix does
not count as successful origin delivery. The existing 4 KiB evidence bound,
no-retry workload, fixed concurrency and no-relaxed-threshold gate remain
unchanged. Real loopback regression tests cover duplicate transfer coding,
large responses with unread bytes, truncated chunked framing, and a valid
complete response. Benchmark results are still synthetic comparative
diagnostics, **not** representative Windows/Linux YARP+CRS capacity or
customer security acceptance. Issue #51 remains open.
