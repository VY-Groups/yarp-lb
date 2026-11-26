# ADC operator diagnostics CLI

Run from the extracted source checkout on Windows or Linux with Python 3. No pip packages or network package downloads are needed.

```
python control-center/tools/adc_diag.py https://management.example.internal:8443 --ca-file organization-root.pem
```

Omit the CA file if the management certificate is trusted by Python's platform trust store. Use the exact management origin; redirects, HTTP, credentials embedded in URLs and environment proxies are refused. Do not disable certificate verification. The command prompts interactively for username, password and, when required by the configured server, email OTP. Use `--provider directory` for configured LDAPS sign-in. Interactive browser OIDC is not implemented: use the browser for OIDC; never enable a recovery account solely to use diagnostics.

Read the actual versioned privacy notice and type ACCEPT only if you wish to acknowledge it. Declining retrieves no diagnostic data. Credentials, session cookies and CSRF tokens are not included in the report or written to disk. The command attempts authenticated logout and clears in-memory cookies even on failure. It performs no configuration mutations; authentication, policy acknowledgement and logout still create their normal audit events.

The JSON output contains configured object counts (routes, clusters, disabled destinations, monitor profiles, real servers, service groups and provisioned virtual services), local HTTP counters and mean duration. Inventory is configured state, not runtime health; counters reset on restart and are not fleet-wide or an atomic snapshot. No route addresses, raw configuration or identity data are exported. Zero traffic is not evidence of health.

Troubleshooting: HTTP 401/403 indicates authentication or authorization rejection; 428 indicates missing privacy acknowledgement; 503 may indicate service or OTP unavailability. Redirect rejection means use the actual management HTTPS origin. For TLS errors verify hostname, CA chain and system time. Do not retry passwords or OTP automatically. Use a minimally privileged account. If logout cannot be confirmed, inform the administrator and follow your session incident procedure.

This increment is source-distributed, not yet included in the offline installer or a native CLI. Independent CI and real authenticated endpoint acceptance are required; no live deployment is claimed.
