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
