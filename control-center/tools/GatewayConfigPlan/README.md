# GatewayConfigPlan

This small offline tool provides a read-only, versioned plan for a deliberately narrow YARP route/cluster profile. It is useful in a Git review or CI job before an operator submits a change through the existing two-person approval API.

```json
{
  "schemaVersion": 1,
  "routes": {
    "web": { "ClusterId": "app", "Match": { "Path": "/{**catch-all}" } }
  },
  "clusters": {
    "app": { "Destinations": { "primary": { "Address": "https://app.example.test/" } } }
  }
}
```

Run `dotnet run --project control-center/tools/GatewayConfigPlan -- validate desired.json` to validate a standalone desired document in CI without reading live gateway state. Its output contains only the schema version and route/cluster/destination counts. Run `dotnet run --project control-center/tools/GatewayConfigPlan -- plan current.json desired.json` for a deterministic ID-only diff. Plan output contains only route/cluster IDs with add/update/remove actions; neither command includes configuration values, addresses, or document hashes. Unsupported schema versions, unknown fields at any level, invalid IDs, invalid route references, unsafe backend origins, and invalid route paths fail closed. Revision hashes are intentionally omitted to avoid exposing a guess oracle for low-entropy secret-bearing input.

Schema 1 supports only routes with `ClusterId` plus `Match.Path`, and clusters with 1–40 named destinations containing a root HTTP(S) origin. It does not accept other YARP properties, transforms, health policy, disabled destinations, or certificate references; use the current server workflow for configurations outside this subset. Both commands are offline and read-only: neither writes gateway files, contacts a gateway, queues approval, nor applies a plan. Validation success does not prove runtime health. This is not the server's full configuration validator and does not implement signed Git provenance, reconciler/drift handling, Terraform, Kubernetes Gateway API, or fleet rollback. Actual changes must still go through the Control Center's reviewed change-request workflow. Schema version 1 has no migration implementation; unsupported versions are rejected.

## Offline Gateway API V1 subset import

`dotnet run --project control-center/tools/GatewayConfigPlan -- import-gateway-api bundle.json` reads a bounded explicitly exported JSON bundle and returns desired schema-1 JSON. Output includes service addresses (unlike the redacted plan); redirect only to a protected file. It never contacts Kubernetes or writes gateway state. The declared controllerName is the reserved illustrative `gatewaycore.example/offline`, not a registered production controller. The supported subset is deliberately limited to one HTTP port-80 listener, explicit Same-namespace **route attachment**, one HTTPRoute with one root PathPrefix rule and one existing ClusterIP Service port declared TCP/appProtocol http, default cluster.local DNS suffix. A route may target a differently namespaced Service **only** when the exported bundle includes an explicit matching target-namespace-owned `gateway.networking.k8s.io/v1` ReferenceGrant: one `from` (HTTPRoute in the route namespace) and one `to` (a specifically named core Service in the target namespace). No wildcard, unnamed or unused permission is accepted. The importer validates both the referenced Service and the scoped grant and fails closed on missing/mismatched metadata, groups, kinds, namespaces, or service identity. There is no cluster lookup, watch, status, permission publication or deployment: revoking a real grant after export does **not** automatically withdraw a running YARP route. Re-import and submit a new reviewed change when a grant changes. No other metadata/spec fields, TLS/hostnames, filters, weights, cross-namespace route attachment, external names, path matching approximations, controller status or live reconciliation. Export only the explicitly supported projection; do not silently strip real semantic fields to make an unsupported resource pass. Use the existing review workflow to submit a validated desired configuration; do not treat this output as a full replacement for unrelated routes. This is a first independently tested import contract, not Kubernetes Gateway API conformance or an actual controller. Terraform, signed Git provenance, controller ownership, live multi-node reconciliation and rollback remain #49 work.

Example bundle:
```json
{
  "gatewayClass": {"apiVersion":"gateway.networking.k8s.io/v1","kind":"GatewayClass","metadata":{"name":"lab"},"spec":{"controllerName":"gatewaycore.example/offline"}},
  "gateway": {"apiVersion":"gateway.networking.k8s.io/v1","kind":"Gateway","metadata":{"name":"edge","namespace":"apps"},"spec":{"gatewayClassName":"lab","listeners":[{"name":"http","protocol":"HTTP","port":80,"allowedRoutes":{"namespaces":{"from":"Same"}}}]}},
  "httpRoutes": [{"apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute","metadata":{"name":"web","namespace":"apps"},"spec":{"parentRefs":[{"name":"edge","sectionName":"http"}],"rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backendRefs":[{"name":"api","port":8080}]}]}}],
  "services": [{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"apps"},"spec":{"type":"ClusterIP","ports":[{"port":8080,"protocol":"TCP","appProtocol":"http"}]}}]
}
```

### Explicit cross-namespace Service permission (offline-only)

For the same one-route bundle, place the backend Service in namespace `shared`,
set the route's one `backendRefs[0].namespace` to `shared`, and include the
following object under optional top-level `referenceGrants`:

```json
[{
  "apiVersion": "gateway.networking.k8s.io/v1",
  "kind": "ReferenceGrant",
  "metadata": {"name": "allow-apps-api", "namespace": "shared"},
  "spec": {
    "from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": "apps"}],
    "to": [{"group": "", "kind": "Service", "name": "api"}]
  }
}]
```

The grant must be owned by the referenced Service's namespace and name the
exact Service. The document validates only an **exported snapshot**: it cannot
ensure the grant still exists or is authorized when the plan is approved.
Cross-namespace permissions are not made permanent by this translation, and
no Gateway API controller/watch, ReferenceGrant revocation or automatic
reconciliation is implemented. Operators must revalidate the full current
cluster snapshot and route access immediately before separate two-person
approval, and must revoke deployed routes through that process when grants
change. Fail-closed tests cover wrong source/target namespaces, resource types,
API groups, missing grants, extra permissions, unused grants and ambiguous
metadata. Cross-namespace Secrets, TLS and path-rewrite semantics remain
unsupported. This is a narrow #49 implementation increment, not Gateway API
conformance certification.

## Ambiguous-input and memory limits

The offline schema-1 validator and plan parser reject duplicate properties
(including case variants and equivalent Unicode-escaped names) at **all JSON
nesting levels** before materializing values. A Git review and an operator
must not interpret the same document differently due to last-value-wins
parsing. The CLI bounds both current and desired files to 512 KiB before
decoding, uses strict UTF-8, checks for concurrent append during read, and
does not echo rejected JSON values. It remains a **read-only subset planner**,
not a signed GitOps reconciler or Kubernetes controller.

## Imported bundle byte safety

The CLI's `import-gateway-api` path uses strict UTF-8 decoding, the same
512 KiB input limit and a post-read length recheck. It explicitly clears the
raw bounded input byte array whether conversion or supported-schema validation
succeeds or fails. Invalid UTF-8, oversized bundles and unsupported semantic
fields return a generic nonzero error with no partial translated output or
exception trace. The resulting desired document intentionally contains
service origins; store it only in a protected file for human review and never
print it in public CI logs. These protections do not implement Git signature
verification, reconciliation, apply, drift detection or a Kubernetes controller.
