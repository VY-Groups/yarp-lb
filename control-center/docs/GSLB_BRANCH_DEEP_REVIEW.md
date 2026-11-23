# GSLB Branch — Engineering and Security Review

**Review date:** 2026-11-23  
**Reviewed branch tip:** `origin/gslb` at `2811a63c03735f9e3825517e3bb094e65b3f0c71`  
**GatewayCore main at review:** `50f7a55b37d4d77050973d983d60849e4d0fff5c`  
**Scope:** Static review of the branch tree, architecture, configuration, DNS/DNSSEC, API, agent, health, routing, storage, tests and branch history. No source code was copied or changed in this review.

## Summary

The branch is a substantial standalone Go DNS traffic-management system, not a module that can be merged into GatewayCore. It contains an authoritative DNS service, agent and DNS-authority runtimes, routing strategies, health probes, an HTTP management API, a CLI, persistence, metrics and demo deployments. The code tree contains about 338 tracked paths and uses Go 1.23 with `miekg/dns`, MaxMind readers, Prometheus, memberlist and bbolt.

Its strongest architectural idea is separating regional agents from DNS-serving authorities and combining agent observations with independent probes. It also has several useful routing concepts—weighted selection, priority failover, GeoIP/custom CIDR mapping, ECS and measured latency—and a fairly broad unit-test suite.

The current branch must **not** be treated as production-ready. Static review found serious DNSSEC key exposure and fail-open behavior, weak trust boundaries around ECS and API proxy headers, and missing authoritative-DNS proof/zone behavior. Distributed authority is independent-node operation, not quorum or partition fencing. The branch has no GitHub Actions workflow at its current tip, and a Go runtime is unavailable in this environment, so its Go tests were not run here.

## Repository and branch facts

- The tip is a separate Go codebase (Go `1.23.0`) with `cmd/`, `pkg/`, `config/`, `docs/`, demos and container files.
- `origin/main` and `origin/gslb` have **no Git merge base**. The branch cannot be treated as a GatewayCore feature branch; its Git history is unrelated to the current .NET/YARP history.
- Two recent branch commits removed the GitHub workflow files. There are no workflow files in `.github/workflows` at the reviewed tip.
- The root `LICENSE` at this tip contains only a one-line informal permission statement. Meanwhile, `README.md` describes dual licensing and Go source headers retain AGPL-3.0-or-later / alternate commercial-license identifiers. The root file therefore does not provide a complete, internally consistent license record; the one-line statement alone should not be used as a redistribution or integration determination.
- GitHub reported no PRs with this branch as head or base, and the branch had no branch-protection response. The user requested removal of the `gslb` branch; deletion is an administrative branch-ref operation, not a code merge.

## Architecture and implemented areas

### Runtime layout

The service command wires the long-running process. Agent mode monitors configured backends and sends status; authority mode receives agent updates, runs independent health checks, owns DNS serving, and exposes APIs. A separate CLI command contains management operations. Packages are separated into `agent`, `api`, `config`, `dns`, `dnssec`, `geo`, `gossip`, `health`, `metrics`, `overwatch`, `routing`, `store` and `version`.

The DNS server starts UDP and TCP listeners on the configured address. The handler supports A, AAAA and DNSKEY query processing and returns NOTIMP for other query types. Routing implementations include round-robin, weighted, priority failover, geographic selection and learned-latency selection. Health code includes HTTP/HTTPS and TCP probes, thresholds, parallel validation and status tracking. State uses a bbolt-backed store. The agent latency collector has Linux and Windows implementations.

### Useful design elements

- Separate agent and authority runtime modes.
- Independent backend validation can prevent a single agent's claim from being the only health signal.
- Bounded probe concurrency, health thresholds and fallback routing reduce some forms of probe overload and flapping.
- GeoIP database lookup and operator CIDR mappings are separate mechanisms.
- The Go source includes tests across core packages, and the Makefile defines `go test -race ./...`.
- Example configs and deployment/incident docs make the intended operating model visible.

These are source-level observations. They do not establish public DNS interoperability, key lifecycle correctness, split-brain safety, load capacity or operational acceptance.

## Findings requiring attention

### Critical — signing errors return the unsigned answer

In `pkg/dns/handler.go`, `signResponse` logs a signer error and returns the original message. When DNSSEC is enabled but signing fails, the normal A/AAAA/NXDOMAIN answer can therefore leave the server unsigned instead of failing closed. A resolver that expects authenticated data cannot distinguish this response as the intended DNSSEC failure behavior. Signer failure should produce a bounded SERVFAIL with no unsigned answer or partial signatures, and UDP/TCP regression tests should exercise the real serving path.

### Critical — management endpoint serializes private DNSSEC keys

`pkg/dnssec/keys.go` defines `KeyPair.PrivateKey` as a JSON field. `pkg/api/dnssec_handlers.go`'s `/api/v1/dnssec/keys` handler returns `KeyManager.GetAllKeys()`, whose values include those `KeyPair` objects. The endpoint is protected by an IP ACL only; any client admitted by that ACL can receive private signing material. `pkg/dnssec/store.go` JSON-marshals the same key pair into the bbolt store, so private key bytes are also persisted without encryption by this layer. Public key/status responses must use a distinct public-only DTO, and private signing keys need a protected key store with explicit access and rotation controls.

### High — key synchronization permits unauthenticated HTTP and “newest wins” imports

`pkg/dnssec/sync.go` builds URLs from configured peer strings and uses the default `http.Client`; it does not enforce HTTPS, client/server certificate pinning or cryptographic authentication of the returned key set. The receiver imports whichever key is considered newer. Combined with the key endpoint above, a network attacker or misconfigured peer can expose or replace signing state. Key exchange needs authenticated transport, public-only payloads, pinned peer identity, explicit key epochs/rollover rules and rejection of conflicting same-epoch keys.

### High — generated NSEC3 denial proofs are synthetic

`pkg/dnssec/nsec3.go` fabricates predecessor/successor hash strings using character increment/decrement and returns two synthesized records for NXDOMAIN. `closestEncloser` always returns the apex. That is not a complete proof construction over the zone's actual owner-name hash set, delegation points and wildcard/closest-encloser relationships. The test suite should validate complete signed denial responses with an independent DNSSEC validator, including existing names, non-existent names, wildcard cases, empty non-terminals and delegation boundaries. Internal record-shape tests are insufficient evidence that validating resolvers accept or reject the proof correctly.

### High — ECS is accepted from any requester without validation or trust policy

`pkg/geo/ecs.go` selects the first ECS option and `GetClientIP` prefers it over the packet source whenever ECS is enabled. The parser does not establish that the sender is a trusted recursive resolver, and it does not validate address family/prefix consistency before the supplied address reaches GeoIP/routing. Any DNS client can therefore claim a different client subnet and influence routing; the subnet is also treated as sensitive location input. ECS needs a trusted resolver allowlist, strict RFC field validation, bounded/masked IPv4 and IPv6 prefixes, and correct response-scope behavior. ECS should be disabled by default unless that trust policy is configured.

### High — API authorization can be bypassed when proxy-header trust is enabled

`pkg/api/server.go`'s `getClientIP` trusts the first `X-Forwarded-For`/`X-Real-IP` value whenever `TrustProxyHeaders` is true; it does not verify that `RemoteAddr` belongs to an approved proxy. If the API listener is reachable directly, a caller can spoof an allowed address and pass the IP ACL. The ACL is the API's access control in this code path; it is not user authentication or role-based authorization. Bind management APIs privately, verify the immediate peer against configured proxy CIDRs before honoring forwarded headers, and add spoofing tests.

### High — the management API is plain HTTP

The server constructs `http.Server` and calls `ListenAndServe`, not `ListenAndServeTLS`. Unless a separately secured local proxy is guaranteed, management endpoints—including key and configuration endpoints—are sent without transport encryption. The config and operator docs should make the required private TLS termination explicit, or the service should support direct TLS/mTLS.

### High — no distributed authority/quorum fencing

The architecture explicitly has each Overwatch authority serve DNS independently, while agent gossip/validation updates local state. There is no N-of-M cross-authority health quorum, lease/fencing mechanism or proof that a DNS node isolated by a partition stops publishing stale positive health. Nodes can observe different probe outcomes and answer differently. This architecture can provide independent availability, but it does not by itself satisfy safe partition behavior or authenticated multi-authority agreement.

### Medium — authoritative DNS coverage is narrow

The DNS handler dispatches A, AAAA and DNSKEY and returns NOTIMP for other query types. It does not show complete NS/SOA apex answers, delegation/zone cuts, general TXT/CNAME support or full negative-answer SOA behavior. The service therefore needs external authoritative-DNS conformance tests before customers delegate a zone to it. Its no-recursion behavior is a useful boundary, but it is not a substitute for those records and proofs.

### Medium — some advertised management and prediction areas are stubs or threshold alerts

The application wires stub providers for node, gossip, audit and routing views, even though the README presents broad management capabilities. The `Predictor` implementation is based on fixed CPU/memory/error-rate thresholds; application wiring does not construct it in the inspected runtime path. That is threshold-based early warning, not a demonstrated predictive failure model. Capability claims and UI status should distinguish working integrations from placeholders.

### Medium — build/CI evidence is absent at this branch tip

The branch contains unit tests and a race-test Make target, but its GitHub workflow files were removed in the two latest branch commits. Go was not installed in the review environment (`go` was not recognized), so `go test -race ./...` and `go vet ./...` could not be run. No passing exact-head CI result is available for this tip. Treat the README's “production-ready” language as unverified until reproducible CI, integration, DNSSEC-validator and deployment acceptance are restored.

## Suitability for GatewayCore

The branch demonstrates useful product-level patterns—separate agents/authorities, health-aware DNS routing, bounded probing, GeoIP/CIDR routing, and operator workflows. It is not compatible with GatewayCore's runtime or repository history: it is Go, has no merge base with the current .NET branch, and contains independent DNS/API/storage/security models. Reuse would require a separate technical and licensing decision. This review makes no code-integration recommendation beyond **do not merge the branch wholesale**.

For GatewayCore, the useful next step is to implement only clearly specified behaviors behind the existing .NET DNS/health boundaries, with strict resolver trust, DNSSEC validator tests, authority fencing, Windows/Linux exact-head CI and operator controls. The implementation and acceptance should remain owned and testable in GatewayCore's own source tree.

## Verification record

- Branch metadata and source inspected at `2811a63c03735f9e3825517e3bb094e65b3f0c71`.
- GatewayCore baseline identified at `50f7a55b37d4d77050973d983d60849e4d0fff5c`.
- Git merge-base check: none.
- GitHub branch protection: not configured/reported for `gslb`.
- PR search: no PR found with `gslb` as head or base.
- Workflow files at branch tip: none.
- Local Go tests: not run; Go toolchain unavailable on this machine.
- Review disposition: static engineering/security review only; production readiness not established.
