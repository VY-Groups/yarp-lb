# GatewayConfigPlan

This small offline tool provides a read-only, versioned plan for the supported YARP route/cluster subset. It is useful in a Git review or CI job before an operator submits a change through the existing two-person approval API.

```json
{
  "schemaVersion": 1,
  "routes": {
    "web": { "ClusterId": "app", "Match": { "Path": "/{**catch-all}" } }
  },
  "clusters": {
    "app": { "Destinations": { "primary": { "Address": "https://app.example.test/" } } }
  },
  "disabled": {}
}
```

Run `dotnet run --project control-center/tools/GatewayConfigPlan -- plan current.json desired.json`. The JSON output contains only SHA-256 revisions and route/cluster/destination IDs with add/update/remove actions; it does not include destination addresses or configuration values. Unsupported schema versions, unknown envelope fields, invalid IDs, invalid route references, unsafe backend origins, and invalid route paths fail closed.

This command never writes gateway files, contacts a gateway, queues approval, or applies a plan. It is not yet the server's full configuration validator and does not implement signed Git provenance, reconciler/drift handling, Terraform, Kubernetes Gateway API, or fleet rollback. Actual changes must still go through the Control Center's reviewed change-request workflow. Schema version 1 has no migration implementation; unsupported versions are rejected.
