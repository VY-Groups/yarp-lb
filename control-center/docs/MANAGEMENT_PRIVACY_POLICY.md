# Management privacy notice and acceptance

The backend owns the notice and its SHA-256 content version. The dashboard renders that text before exposing management data; /dashboard/privacy is a read-only copy accessible before login and from the footer. Accept & continue is required after authentication (including OTP, OIDC and Viewer). Decline keeps the console locked and allows review or sign-out.

API clients must GET /admin/api/session, review privacyText and explicitly POST /admin/api/privacy/accept with {"version":"<privacyVersion>"} and the existing X-CSRF-Token. The server audits acceptance and issues a separate protected HttpOnly cookie bound to the account, authenticated session and exact notice version. Other management APIs return 428 without acceptance; existing authentication, roles, CSRF and step-up requirements still apply. Public proxy traffic, gateway health and OIDC callbacks are unaffected. Refresh retains acceptance; a new login or policy change requires acknowledgement.

The technical notice is not a jurisdiction-specific compliance certification. The deploying organization must review retention, recipients, contact details and legal requirements before production. Existing frozen release artifacts do not include this feature. Full CI and independent review are required before freezing a new candidate.

Real API and Chromium tests exercise decline, acceptance, stale versions, missing CSRF, direct API blocking and session refresh. Disposable test clients explicitly acknowledge the current notice; there is no production bypass.

Additional browser checks verify the receipt is HttpOnly and SameSite=Strict, tampering does not grant access, and a previously valid receipt cannot unlock a new login. The API test also checks anonymous acceptance refusal, public notice availability, an audit event and absence of side effects from blocked writes. A 401 on the policy screen returns to sign-in; a 428 clears stale management state, closes any open editor and reloads the session notice. No mutation is automatically retried.

The notice text is normalized to LF before rendering and SHA-256 hashing so Windows and Linux builds agree on the same revision regardless of source checkout line endings. The real API fixture verifies the returned notice bytes match the returned revision.
