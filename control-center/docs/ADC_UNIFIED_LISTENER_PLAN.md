# Unified ADC listener plan (Phase 2)

This opt-in host-level contract is shared by the HTTP gateway, independent TCP/UDP engine and signed L4 agent. It is a bounded first listener-management increment, not a remote OS or certificate provisioning API. The same reviewed local manifest must be provisioned by the host administrator for each process; service accounts get read-only access, no general users can write it. Use an absolute regular file in protected host state. Set GATEWAYCORE_ADC_LISTENER_PLAN_FILE in all three service environments. Existing deployments without it remain compatible. Changing bindings requires an approved maintenance window, protected manifest backup, corresponding engine configs and explicit service restart; a file-only signed activation is not a runtime restart. Restore the compatible manifest and previous configurations before rollback/restart. Do not bypass management mTLS, VIP authority or license checks. Never bind a TCP/UDP engine to a protected management address.

Example (adapt addresses to the approved isolated topology):

```json
{"version":1,"listeners":[{"id":"gateway-http","ip":"127.0.0.1","port":18080,"protocol":"HTTP"},{"id":"gateway-https","ip":"127.0.0.1","port":18443,"protocol":"HTTPS3"},{"id":"gateway-admin","ip":"127.0.0.2","port":19443,"protocol":"ADMIN"},{"id":"gateway-metrics","ip":"127.0.0.2","port":19444,"protocol":"METRICS"},{"id":"app-stream","ip":"127.0.0.1","port":19000,"protocol":"TCP"},{"id":"app-datagram","ip":"127.0.0.1","port":19000,"protocol":"UDP"}]}
```

The four reserved gateway IDs must match the isolated base listeners, every configured virtual socket must have an identical entry and HTTPS3 must match actual HTTP version 3. TCP/UDP may share a numeric port on distinct transports; HTTPS3 consumes both. IDs are case-insensitively unique; IPs are normalized; wildcard, mapped IPv4, management overlaps and duplicate transport tuples are rejected. L4 retains IPv4-only and explicit non-loopback opt-in. The engine reserves all sockets before starting forwarding and cleans up on a failed bind. Agent prepare captures whether the host plan was enforced in the durable L4 transaction sequence record. Activate and rollback revalidate the current plan and refuse a missing plan for a plan-required transaction (HTTP 409, without replacing configuration or fencing rollback). Explicit legacy transactions remain compatible when no plan exists, and must validate a newly configured plan if present. Older staged L4 transactions with no recorded mode are ambiguous and must be re-prepared with a new signed sequence after checking the active revision; do not infer legacy mode from missing metadata. This does not change non-L4 transaction records. The authenticated virtual-servers API reports plan metadata separately from provisioned HTTP service bindings; it never represents L4 as an HTTP route or asserts runtime health. 

## Phase 2 acceptance tracker increment

| Gate | Evidence | State |
|---|---|---|
| Typed common socket model and conflict checks | AdcListenerPlan and FleetConfigSignatureTests | CI pending |
| Safe exact local configuration binding | GatewayListenerIsolation and shipping L4 startup; real TCP/UDP suite with shared-plan fixture | CI pending |
| Signed L4 staging compatibility | Agent prepare/activate/rollback revalidate current manifest | Integration acceptance pending |
| Read-only authenticated plan metadata | virtual-servers API and legacy API contract | CI pending |
| Unified editable registry, coordinated signed plan distribution, browser editor, migration and cross-process restart/rollback | Further implementation required; no claim of completed Phase 2 | Pending |

Physical multi-host acceptance and production authorization remain issue #36. Preserve the frozen software release baseline separately. No production signing claim.
