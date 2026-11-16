# Management readiness observation

The dashboard reads `GET /admin/api/gateway-readiness` through the authenticated
management API. Administrator, Operator and Viewer may inspect this read-only
endpoint; anonymous access is denied. In isolated mode the existing management
IP, mTLS and network allowlist still apply. The endpoint does not expose backend
addresses, credentials or configuration.

Response: `{"ready":false,"scope":"Local active destination health","collectedUtc":"..."}`.
A successful management request is not proof that a backend is healthy: only an
explicit boolean `ready: true` permits the positive indicator. The value uses
the same active YARP destination-health predicate as data-plane readiness.
It means at least one active destination is healthy, not every route, fleet
member, DNS engine or application transaction is ready.

The public/data-plane `/gateway/health/ready` contract is preserved: HTTP 200
with `ready: true` or HTTP 503. It remains blocked on the management listener
in isolated mode. The UI no longer needs to cross that separation.

Polling retains its 30-second interval. Each request clears the previous green
display to Checking, has a five-second deadline, cancels superseded work and
rejects out-of-order or old-session responses. Timeout, transport/authentication
failure or malformed data cannot show a healthy state. Logout aborts pending
readiness work. Management API requests use no-store caching.

Tests: shipped-JavaScript VM regressions cover the endpoint, boolean schema,
checking state, deadline, late success, cancellation, logout, malformed values
and hidden shells. The existing real Control Center E2E suite checks anonymous
denial and read access for all three authenticated roles. These tests are CI
evidence, not a 99.9% availability guarantee or physical deployment acceptance.
