# External WAF: ModSecurity + OWASP Core Rule Set (CRS) — experimental integration

The WAF uses the upstream-maintained `owasp/modsecurity-crs:nginx` image, **not** a home-grown security regex filter. The disposable CI lab places CRS in front of an unexposed backend and sends real requests through the WAF. Tests assert benign HTTP traffic passes while XSS, SQL injection, and path traversal inputs are blocked in the disposable lab. A separate detection-only pass checks that the same XSS payload is not blocked; evidence is logged for review. A bounded request-body test checks the configured limit. The backend is not published to the runner.

Upstream official docs: https://github.com/coreruleset/modsecurity-crs-docker

## Lab
```bash
bash tests/WafCrs/verify.sh
```

It binds 127.0.0.1:18888 and creates a Docker-private backend network. It captures container logs and removes temporary containers and the network.

## Production gaps

This rolling `nginx` tag is **lab-only**. Production requires a reviewed immutable image digest and security updates, HTTPS/TLS and backend trust, inbound protection placement, bypass prevention, anomaly tuning and application-specific exclusions, rule governance, false-positive and performance tests, privacy-safe audit retention, DDoS protection and external load balancing. Blocking one XSS signature is not a comprehensive WAF/security compliance assertion. Control-center WAF provisioning is **not** integrated; mark capability as partial external integration only.


## Extended CI checks (experimental)

The lab uses `MODSEC_RULE_ENGINE=On` for blocking acceptance, then explicitly restarts the WAF with `WAF_MODE=DetectionOnly` and expects the XSS payload to pass. That is a **mode behavior check**, not a false-positive assessment on real user traffic. In blocking mode, a small benign corpus now checks JSON, XML, and a generated ~31 KiB JSON upload. The bounded backend returns only an acceptance marker, content type, and byte count; it never reflects or logs bodies. This corpus is a regression fixture, not a measured false-positive rate or representative customer traffic study. The lab sets a 128 KiB total request-body limit and a 64 KiB in-memory body limit; an oversized POST must be rejected (the tested ModSecurity/nginx connector returns 403, not necessarily 413), and CI confirms the explicit body-limit diagnostic in the WAF audit log. CI uses intentionally representative SQLi/path traversal attacks, but this is not a substitute for the full upstream CRS regression suite. Audit logs are uploaded from disposable CI runners only; production logs require sanitization and retention policies.

**Important:** an edge-only WAF cannot stop direct origin access. Keep the backend private, pin an upstream container digest for production, set and audit policy exclusions with real traffic in detection-only mode, and measure throughput/latency against an unprotected control. Ruleset updates must go through an independently approved signed and reversible deployment path, which does not yet exist.

## Corpus evidence artifact

`artifacts/waf-crs/blocking-corpus-report.json` records the fixed synthetic blocking corpus by case and route, with HTTP status, expected class, TP/TN/FP/FN counts, missing and unexpected responses. Incomplete runs retain explicitly missing results and do not publish false-positive/false-negative rates. The test requires every fixture to complete without a false positive or false negative. The report contains no request payloads and excludes body-limit and detection-only checks, which retain their existing separate assertions. This is a small synthetic regression corpus, not a production false-positive/false-negative estimate or a replacement for an agreed representative corpus, severity analysis, or load testing.

## Immutable lab image and matched mode comparison

For a repeatable lab use `WAF_IMAGE=owasp/modsecurity-crs@sha256:<reviewed-digest> bash tests/WafCrs/verify.sh` with the actual upstream digest. Explicit mutable image overrides are rejected; an omitted override uses the existing rolling lab tag once, records its repository digest, then pins every mode restart to that digest and checks the actual image ID. This does not establish trusted signature provenance or a reviewed production image. The benchmark runs a separate disposable client on the private compose network, never publishing the backend. Each phase performs 120 alternating fixed GET and JSON POST requests at concurrency four, with a fresh HTTP/1 connection per request and no retry. All responses must match the expected backend marker/metadata; any transport, status or body error fails the phase. Artifacts include per-phase successful throughput and p50/p95/p99 from monotonic timings, only percentile values for complete runs. The five phases are direct origin, blocking CRS, detection-only CRS, nginx-only proxy (ModSecurity off, disposable lab only), and restored blocking mode; the restored phase independently requires a known XSS to be blocked again. This is a synthetic nginx comparison, not direct-vs-YARP-vs-WAF capacity or a representative customer workload. No latency/throughput production target is inferred or relaxed; CPU, memory, allocations, repeated sustained runs, production signed policy approval, rule exclusions and representative corpus acceptance remain open. Do not use the proxy-only mode on a deployed edge.
