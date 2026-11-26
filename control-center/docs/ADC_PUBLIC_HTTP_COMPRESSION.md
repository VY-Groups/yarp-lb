# Public HTTP asset compression

Open Routes, select Application access policy, enable Public HTTP asset compression and submit through the ordinary independent change approval workflow. The option is off by default. Disable it through another reviewed change or use existing approved rollback.

This first profile negotiates gzip or Brotli for anonymous GET requests on plaintext HTTP, and only known-length (1 KiB to 16 MiB) public static CSS, JavaScript and SVG responses with explicit positive public max-age. It refuses TLS, authentication, cookies, queries, ranges, conditional requests, session affinity, response cookies, private/no-store/no-transform directives, validators and integrity digests. It does not alter origin-supplied encodings. The built-in ASP.NET streaming compression middleware handles the encoding and associated response headers. Only use the setting on trusted public static asset routes. It does not enable or enforce caching. Do not disable HTTPS to use this feature; HTTPS acceleration requires a separately reviewed design.

Verify using curl --compressed and compare the decoded body with identity; inspect Content-Encoding and Vary. Monitor CPU, throughput, upstream errors and p99 under representative traffic. No capacity improvement, production deployment, HTTP cache, HTTPS compression, or physical acceptance is claimed.
