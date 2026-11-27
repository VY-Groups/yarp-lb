# Declarative route method admission

Under Routes → Application access policy, set Allowed HTTP methods to a comma-separated set of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. Empty means preserve the previous unrestricted behavior. Methods are case-sensitive; wildcards, duplicate values, empty members, CONNECT, TRACE and custom verbs cannot be configured in this first increment.

Submit and independently approve the draft. The selected route's runtime guard executes after access authorization but before load balancing and forwarding, returning 405 with Allow and no-store on disallowed methods. This does not modify routing matches or cause fallback to another route. The existing signed fleet validation refuses malformed settings. To remove the guard, clear the field and approve a new revision.

For APIs, explicitly include OPTIONS if CORS preflight is needed and HEAD if clients require it. Use the existing review and rollback workflows. Verify the allowed method succeeds and a blocked method returns 405 without origin execution. This is bounded declarative method admission, not arbitrary scripting, body inspection, identity authentication, or a full traffic-policy language.
