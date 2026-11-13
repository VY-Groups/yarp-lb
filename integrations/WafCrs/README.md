# External WAF: ModSecurity + OWASP Core Rule Set (CRS) — experimental integration

The WAF uses the upstream-maintained `owasp/modsecurity-crs:nginx` image, **not** a home-grown security regex filter. The disposable CI lab places CRS in front of an unexposed backend and sends real requests through the WAF. Tests assert benign HTTP traffic passes and an XSS request is rejected with 403. The backend is not published to the runner.

Upstream official docs: https://github.com/coreruleset/modsecurity-crs-docker

## Lab
```bash
bash tests/WafCrs/verify.sh
```

It binds 127.0.0.1:18888 and creates a Docker-private backend network. It captures container logs and removes temporary containers and the network.

## Production gaps

This rolling `nginx` tag is **lab-only**. Production requires a reviewed immutable image digest and security updates, HTTPS/TLS and backend trust, inbound protection placement, bypass prevention, anomaly tuning and application-specific exclusions, rule governance, false-positive and performance tests, privacy-safe audit retention, DDoS protection and external load balancing. Blocking one XSS signature is not a comprehensive WAF/security compliance assertion. Control-center WAF provisioning is **not** integrated; mark capability as partial external integration only.
