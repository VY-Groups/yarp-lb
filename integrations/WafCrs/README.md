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

The lab uses `MODSEC_RULE_ENGINE=On` for blocking acceptance, then explicitly restarts the WAF with `WAF_MODE=DetectionOnly` and expects the XSS payload to pass. That is a **mode behavior check**, not a false-positive assessment on real user traffic. The lab sets a 128 KiB total request-body limit and a 64 KiB in-memory body limit; an oversized POST must be rejected (the tested ModSecurity/nginx connector returns 403, not necessarily 413), and CI confirms the explicit body-limit diagnostic in the WAF audit log. CI uses intentionally representative SQLi/path traversal attacks, but this is not a substitute for the full upstream CRS regression suite. Audit logs are uploaded from disposable CI runners only; production logs require sanitization and retention policies.

**Important:** an edge-only WAF cannot stop direct origin access. Keep the backend private, pin an upstream container digest for production, set and audit policy exclusions with real traffic in detection-only mode, and measure throughput/latency against an unprotected control. Ruleset updates must go through an independently approved signed and reversible deployment path, which does not yet exist.
