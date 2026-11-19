# eSign public and private route profile

The Setup Center's **Application pools (eSign preset)** action creates independent host/path routes and YARP clusters in the local unsaved draft. Each pool has two HTTPS destinations and an explicit routing choice. Choose eSign, SSCA Admin, RA, OCSP, TCA, eSign CA, Public API, or Private API. The wizard never writes live config or calls an application backend; a submitted change still requires a different administrator's approval.

The default eSign profile creates both a public and a private API pool. SSCA Admin, RA, TCA, and eSign CA are constrained to private-only scope; OCSP and Public API are constrained to public-only scope; Private API is constrained to private-only scope. Those scope choices only create the corresponding route/cluster records and do not bind network listeners.

## Choose a mode per eSign deployment

- **Active-active equal share** uses RoundRobin between both servers.
- **Active-active weighted** uses the entered destination weights. Weights split requests; they do not select by geography or provide failover guarantees.
- YARP's `HealthyAndUnknown` availability setting preserves the existing bootstrap behavior for active-active pools: a destination can receive traffic before its first successful active health check. Use Primary/DR mode when traffic must fail closed until a successful readiness check; otherwise configure and monitor a real readiness endpoint and understand that early requests may reach an unverified destination.
- **Primary plus DR standby** uses PrimaryBackup. The second server is marked backup. Active readiness checks are mandatory for this mode; passive-only health cannot promote the standby safely. YARP's standard `HealthyAndUnknown` candidate policy is retained for compatibility, while the custom PrimaryBackup selector excludes every destination whose active health state is still `Unknown` or `Unhealthy`. The service therefore returns 503 rather than sending early traffic to an unverified standby; failover waits for a successful active check.
- **Active checks** poll the configured readiness path. **Passive-only** learns from real traffic failures, so requests may fail before the destination is ejected. This is a reduced-capability fallback, not equivalent health validation.

The selected mode applies independently to both pools. The public route and private route have different host matches, route IDs, cluster IDs, and destination lists. This keeps their proxy policy and backend pools separate.

## Public/private boundary

A route host match and a cluster label do not create a network security boundary. Bind private API ingress to a restricted listener/interface, enforce the source network with firewall/ACL rules, and verify that management endpoints remain on the management plane. This wizard does not create listeners, DNS, firewall rules, certificates, or backend services. Do not place private RA, SSCA, signing or administrative operations behind a public listener based only on a private hostname.

For regional routing, this L7 profile has no GeoIP or country database selection. Use an explicitly approved upstream DNS/GSLB or network-routing policy, or deliberately configure weights. Weighted traffic is not equivalent to geolocation.

## Health and drain

Backend Management can inspect the current YARP active health, passive health and in-flight request count for this GatewayCore process. `Unknown` is not `Healthy`, and each gateway reports only its own state. A **Drain new traffic** action changes the destination's `TrafficState` in the unsaved draft. It removes the backend from new-request selection after independent approval and rollout; it does not cancel in-flight requests. Use the normal change-request and fleet rollout process, then inspect every gateway separately.

No automatic retry or replay is added for eSign, CA signing, approval or other non-idempotent operations. Verify application data/session consistency and end-to-end transaction behavior separately before enabling multi-site failover.
