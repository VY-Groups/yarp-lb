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

Run `dotnet run --project control-center/tools/GatewayConfigPlan -- plan current.json desired.json`. The JSON output contains only route/cluster IDs with add/update/remove actions; it does not include configuration values, addresses, or document hashes. Unsupported schema versions, unknown fields at any level, invalid IDs, invalid route references, unsafe backend origins, and invalid route paths fail closed. Revision hashes are intentionally omitted to avoid exposing a guess oracle for low-entropy secret-bearing input.

Schema 1 supports only routes with `ClusterId` plus `Match.Path`, and clusters with 1–40 named destinations containing a root HTTP(S) origin. It does not accept other YARP properties, transforms, health policy, disabled destinations, or certificate references; use the current server workflow for configurations outside this subset. This command never writes gateway files, contacts a gateway, queues approval, or applies a plan. It is not the server's full configuration validator and does not implement signed Git provenance, reconciler/drift handling, Terraform, Kubernetes Gateway API, or fleet rollback. Actual changes must still go through the Control Center's reviewed change-request workflow. Schema version 1 has no migration implementation; unsupported versions are rejected.
