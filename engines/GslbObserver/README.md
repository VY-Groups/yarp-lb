# External readiness observer

Start one instance per service and observer vantage with `dotnet GslbObserver.dll /absolute/observer.json`. Give each observer its own signing key and restrict its private listener to the authorised DNS nodes. Trust the client CA on the observer host and configure the DNS client certificate's SHA-256 fingerprint. The observer performs a fresh probe to its configured service for every challenge. A TCP connection alone cannot produce a signed readiness verdict.

```json
{
  "ListenAddress": "127.0.0.1",
  "Port": 18443,
  "PublicUrl": "https://validator.example:18443/ready",
  "HealthUrl": "https://service.example/transaction-ready",
  "ServerCertificatePem": "/private/server.crt",
  "ServerKeyPem": "/private/server.key",
  "SigningKeyPem": "/private/observer-p256.key",
  "AllowedClientSha256": ["<64 hexadecimal characters>"]
}
```

The server certificate must match the public URL. The signing key is separate from TLS credentials. Configure the matching public key on each DNS node. Restart the processes after changing key material or trust configuration. A DNS node accepts readiness only when both configured observers and its own local probe succeed.

All observer TLS, report-signing, and report-client TLS private keys must be absolute regular files. Linux opens each key path component-by-component without following symlinks and validates the owner and permissions of the opened file and every parent directory. Owners must be root or the service identity; group/other key access and group/other-writable parent directories are rejected. A sticky directory such as root-owned `/tmp` is allowed. The PEM bytes are read from the same validated handle; owner-read access is required (`0600` is recommended). Windows opens each file without following a final reparse point and imports the bytes read from that same handle, but application-level owner/ACL validation is not implemented, so restrict each key to the observer service identity with deployment ACLs. Other operating systems are not supported by this key loader.

For an agent that reports to multiple independent DNS authorities, use `ReportUrls` instead of `ReportUrl`:

```json
"ReportUrls": [
  "https://dns-a.example:18444/agent-health/v1/reports",
  "https://dns-b.example:18444/agent-health/v1/reports"
]
```

The list is limited to eight unique HTTPS report endpoints with the fixed report path. One signed report and persisted sequence number are sent concurrently to all configured authorities; each authority validates and replay-fences it using its own local state. A failed endpoint is logged independently and does not prevent delivery to other endpoints. Existing `ReportUrl` configurations remain supported.
