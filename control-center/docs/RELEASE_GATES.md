# CA production release gates — 0.1 development baseline

The following checks must be **actually evidenced**, independently reviewed, and signed off before moving this application into a GatewayCore CA change window. A green Setup Center status only describes configuration, not proof of successful failover or compliance.

## G0: Build, package, rollback

- Windows Server 2022 with supported .NET 10 patch baseline; project builds from approved offline NuGet feed with **zero compiler errors**.
- Browser frontend loads without CSP violations; anonymous requests to protected API endpoints return 401; CSRF/role denial behavior verified.
- The application persists no C# source backup inside the compilation project; installer rollback and configuration backups both restore cleanly.
- Controlled disaster recovery test restores identity settings, Data Protection keys and encryption to the intended machine(s); test with separate OS identities.

## G1: Authentication and separation of duties

- HTTPS-only administrative listeners with strong TLS, trusted certificates, HSTS where appropriate, network ACL and management-plane segmentation.
- Approved enterprise SSO with phishing-resistant FIDO2/passkey or smart card assurance; LDAPS + email OTP alone does not meet this gate.
- Two different administrators actually submit and approve a staged change; Viewer cannot mutate; revoked Operator has sessions invalidated.
- Recovery account is vaulted, controlled and periodically tested; no hardcoded/default passwords.

## G2: Config distribution and audit

- Versioned, signed or otherwise authenticated desired-state changes stored in a protected controller datastore with quorum/leader election if using multiple controllers.
- Every gateway applies the same approved revision; stale/partitioned node cannot silently overwrite current desired state.
- Fleet failure injection: blocked agent, expired certificate, broken DNS, partial rollout, controller crash; manual reconciliation documented and tested.
- Audit records exported to independent retention-protected or WORM storage, with integrity/sequence verification, access reviews and alerting. Local JSONL alone fails this gate.

## G3: Traffic data plane

- Production reverse-proxy VIP has health-aware distribution across both YARP gateways (DNAT alone is not gateway HA).
- Two .NET API nodes serve simultaneously; stop either node and verify fresh requests are routed to the survivor after bounded detection time. No data loss or duplicate issuance actions.
- Both surviving single nodes meet **100% peak production load** (capacity test), not merely 50% normal load.
- Verify trusted backend TLS/SNI, forwarded headers, original Host behavior, mTLS/partner identity headers, webhook callbacks, HSTS/redirects, HTTP/2/gRPC/WebSockets if used, and timeouts.
- Application state, file uploads, tokens, distributed jobs, sessions and Postgres/Pgpool connectivity are safe on both nodes.

## G4: CA trust services

- Classify every route: GatewayCore public website, partner API, eKYC, RA/SSCA, restricted tools, OCSP, CRL. Separate public and private ingress; maintain firewall and IAM trust boundaries.
- Validate OCSP GET/POST binary payloads, cache headers, revocation freshness and URLs already embedded in certificates before cutover; CRL objects remain reachable with expected paths/content types.
- Protect HSM and issuance services from external reverse-proxy exposure; require CA operations/CPS change approval.

## Not yet implemented in 0.1

- End-to-end remote software provisioning; fleet-wide leader/standby reconciliation; enterprise OIDC/FIDO2 SSO; independently immutable audit storage; automatically proven safe failover.

These are engineering tasks and infrastructure integrations, not a checkbox that can safely be turned on through a frontend alone.
