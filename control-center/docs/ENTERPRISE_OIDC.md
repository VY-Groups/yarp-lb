# Enterprise SSO and upstream phishing-resistant MFA (opt-in)

GatewayCore uses the ASP.NET Core OpenID Connect handler for Authorization Code + PKCE, state/correlation, nonce, signature and JWKS rotation. It does not implement a WebAuthn relying party or store passkeys: the configured identity provider must actually verify the RP origin, challenge, user presence and verification and issue a trusted assurance claim. An arbitrary "mfa" AMR is not sufficient.

## Before enabling

1. Provision the local recovery Administrator and enable/test its SMTP OTP before turning on enterprise mode. Create local accounts with the intended role; their password is not usable in enterprise mode. Keep at least two distinct mapped administrators for the existing two-person workflow.
2. Register a confidential OIDC client at a single HTTPS issuer. Register exactly MANAGEMENT_ORIGIN/admin/oidc/callback and MANAGEMENT_ORIGIN/admin/oidc/signed-out as its post-logout redirect URI. The provider must publish an HTTPS `end_session_endpoint` in discovery for federated logout. Enable code flow, S256 PKCE, signed ID tokens and an IdP policy that mandates phishing-resistant authentication. Configure the ID token to contain immutable sub, aud, auth_time, acr, amr and groups. Allow only the configured management origin and existing management-side mTLS/IP restrictions. A reverse proxy must not spoof Host or TLS; forwarded headers are not enabled by this feature.
3. Choose an exact IdP-specific phishing-resistant ACR and one exact method from fido2, webauthn, passkey, hwk. The ACR must be documented by the IdP as requiring phishing-resistant authentication, not merely hardware-key presence. Check the real provider's signed claims; not every IdP emits these claims by default. Unsupported profiles fail closed.
4. Create an owner-only config and separate client secret file, with absolute paths and protected parent directories. On Windows, set the file owner to the service identity, SYSTEM or local Administrators and grant access only to the service identity, SYSTEM and local Administrators; GatewayCore verifies the file owner and rejects any other allow ACE at startup/read time. On Linux use mode 0600. Keep parent directories protected as well. OIDC JSON rejects unknown fields and duplicate property names, including case-only aliases at nested account records. No real secret in Git or logs.

Set GATEWAY_OIDC_CONFIG_FILE to the absolute JSON configuration file. Example (replace all illustrative values):
```json
{
  "Issuer": "https://idp.example.invalid/realm/gateway",
  "ClientId": "gateway-control-center",
  "ClientSecretFile": "/etc/gatewaycore/private/oidc-client-secret",
  "ManagementOrigin": "https://manage.example.invalid:9443",
  "RequiredAcr": "urn:example:phishing-resistant",
  "RequiredAmr": "fido2",
  "BreakGlassUsername": "recovery",
  "Accounts": [
    { "Subject": "immutable-idp-subject-a", "Username": "alice", "Group": "gateway-admins", "Role": "Administrator" },
    { "Subject": "immutable-idp-subject-b", "Username": "bob", "Group": "gateway-admins", "Role": "Administrator" },
    { "Subject": "immutable-idp-subject-c", "Username": "operator", "Group": "gateway-operators", "Role": "Operator" }
  ]
}
```

Restart the gateway. The login page offers Enterprise SSO / passkey. A mapped identity maps by exact issuer + immutable subject + required group and matching existing local role; no auto-enrollment, email matching or IdP-asserted privilege elevation. A configured policy requires enterprise sign-in for every normal account; only the named local recovery Administrator can sign in with password plus delivered OTP. The recovery mechanism is a logged, deliberately weaker emergency exception, not FIDO2. Disable the account or revoke its local security stamp to invalidate existing cookies; a policy edit plus restart invalidates previous tickets. Removing the environment setting restores legacy behavior; old enterprise-mode cookies are rejected.

The normal session is limited to 10 minutes after the signed auth_time; every authenticated administrative mutation except logout requires authentication within five minutes. Sign out, sign in again, then explicitly review/retry a denied change; no automatic replay. The existing CSRF, RBAC, local account enable flag, security stamp, rate limit, management isolation and two-person approval remain enforced. No access/refresh/ID tokens are stored in local session cookies. A federated user signs out through the provider's discovered end-session endpoint; GatewayCore sends its client ID, a protected state value and the exact registered callback, but does not send an ID-token hint because tokens are deliberately not persisted. Providers may require an explicit confirmation when no ID-token hint is supplied. Local recovery accounts use local cookie sign-out. This front-channel request asks the IdP to end its session; it does not replace back-channel revocation or guarantee notification delivery to other applications/replicas. Immediate provider revocation, live multi-IdP verification, direct WebAuthn and recovery policy acceptance remain open.

## Acceptance boundary

Unit/security CI checks issuer, audience, claim multiplicity, required group, role mapping, assurance method, fresh authentication, local policy changes, and on Windows accepts only the documented service/SYSTEM/Administrators ACL while rejecting broad Users access to either policy or secret. The framework supplies protocol-level state, nonce, PKCE, lifetime and signature checks; Linux security CI runs the actual gateway against a disposable HTTPS IdP with independent RSA signatures and real authorization-code exchange. It asserts S256, exact redirect URI, state/nonce, mapped role, login/logout and denial of plaintext/local bypass, tampered state, nonce, issuer, audience, missing FIDO2 evidence, unauthorized group, expiry and forged signature. Results must be verified against the exact PR head; the fixture is not a real passkey authenticator. Production testing requires actual IdP registration, real passkey authenticator, key rotation/outage, certificate trust and break-glass drill. The data plane is unchanged. Do not enable enterprise mode before staging acceptance.

## Provider-initiated back-channel logout

Register the exact HTTPS management URL MANAGEMENT_ORIGIN/admin/oidc/backchannel-logout with the trusted IdP. The existing management listener IP/mTLS restrictions still apply; provision its client certificate where required. Never expose the endpoint through the public proxy listener.

Send a bounded application/x-www-form-urlencoded POST with a single logout_token field. GatewayCore validates the token signature using trusted issuer discovery/JWKS, exact issuer and sole client audience, supported signing algorithm, fresh iat (two minutes with 30 seconds future skew), jti, the standard back-channel logout event and absence of nonce; unknown subjects, ordinary ID tokens and malformed envelopes are rejected. The JOSE `typ` header may be absent; when supplied, it must be exactly `logout+jwt`. A subject claim is mandatory, even when sid is also present. This is conservative subject-wide revocation, not a sid-only session implementation.

The local mapped account's durable OIDC revocation cutoff and security stamp change before HTTP 200. Existing cookies fail validation on their next request; callbacks carrying auth_time at or before the cutoff cannot establish another session. A later successful authentication must have a newer signed auth_time. Older/equal logout notices are idempotent and cannot churn the stamp of a newer session, including after restart. Password resets preserve the cutoff. No raw token, nonce, subject or provider credentials are written to the audit log; the local username and cutoff are recorded. A durable audit-through checkpoint keeps failed local audit appends pending: the endpoint returns 503 until a retry records the logout, then returns 200. A crash after append but before checkpoint persistence can create a duplicate record on retry; it cannot silently acknowledge an unrecorded logout. The existing login guard serializes user-state updates. Account records are written to a unique temporary file, flushed, then atomically replaced; local filesystem and protected parent directories remain trusted.

An in-flight operation already authorized before logout is not retroactively undone. Each independent management replica must receive the trusted notification; this code does not provide distributed cookie revocation or detect provider account changes when no logout event is delivered. External audit integration, real-provider interoperability and multi-replica notification acceptance remain separate work.

The disposable real HTTPS IdP CI tests RP-initiated logout using the exact client ID/callback and protected state, rejects CSRF-less logout, verifies no ID token is persisted or sent, and checks local cookie termination after the provider callback. It also tests a signed valid back-channel logout, malformed/wrong issuer/audience/nonce/event/subject/jti/forged/stale notices, next-request cookie invalidation, stale authentication denial, a fresh new session, repeated old logout and restart preservation. Test results must be checked on this exact PR head. Real-provider logout confirmation behavior, notifications, client authentication and multi-node delivery require environment acceptance.
