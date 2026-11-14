# HTTP backend compatibility — v0.1 developer preview

GatewayCore is an HTTP L7 reverse proxy implemented with YARP. **IIS, Apache
httpd, Nginx, Caddy, Node.js, Tomcat, Kestrel and other RFC-compatible HTTP
origin servers require no special server-specific gateway engine plugin.** An
HTTP or HTTPS origin URL is configured as a YARP destination. The gateway does
not install or manage any of these servers.

## Desktop/standalone lab
1. Verify the IIS, Apache or Nginx test site itself responds (e.g.
   `curl http://127.0.0.1/`). Use an isolated, nonproduction origin.
2. In the management console, use **Architecture & setup → Fill single-server
   test draft**. Review and confirm the design. No traffic is changed.
3. Under **Setup Center**, use **Local IIS / Apache / Nginx test** to make
   a draft route to the loopback origin. It requires another administrator
   to approve before live routing changes. Loopback **HTTP is accepted only
   in this test wizard**; remote destinations need properly trusted HTTPS.
4. After approval, test `/lab/` from the local listener. Verify that
   responses match the direct origin and that admin/metrics endpoints remain
   inaccessible on the traffic socket.

The initial standalone quick-start design is metadata only. It cannot
silently configure firewall bindings, certificates, IIS or web-server state.

## External ingress controllers
- **NGINX Ingress Controller** and **other Kubernetes ingress controllers**
  can be deployed *upstream* of GatewayCore. This is an **integration
  topology**, not a built-in GatewayCore ingress controller.
- Configure the ingress controller's upstream Service/Endpoints according to
  the cluster's supported discovery and TLS verification rules. Host/path
  forwarding, trusted forwarded headers, WebSockets, gRPC and ingress
  health/readiness must be validated end-to-end.
- Never expose the management, metrics, certificate-key or administrative
  listener through public ingress.
- A laptop bound to `127.0.0.1:8080` cannot be addressed by a Kubernetes
  ingress on another machine. Separate network listeners, trusted TLS and
  network admission are needed before remote integration.

## Protocol and hosting boundaries
- IIS / Apache / Nginx origins: HTTP(S) reverse proxy supported via YARP
  configuration, subject to site-specific validation (authentication,
  virtual hosts, redirects, forwarded headers, TLS and health checks).
- Ingress controllers: deploy externally and integrate; **not supplied or
  managed** by the GatewayCore Windows ZIP.
- Layer-4 TCP/UDP, WAF, service mesh, GSLB and full Kubernetes operator
  lifecycle are **not implemented** by adding HTTP origin choices.
- SMTP is **optional** for local HTTP routing. It is needed only if the
  administrator elects to enable email OTP. SMTP test 503 means no
  successful relay acceptance, not a gateway routing failure.
- Production readiness is **NO-GO** until independent server, security and
  operational acceptance is recorded.
