using System.Security.Claims;

internal static class EnterpriseOidcPolicyTests
{
    internal static void Run()
    {
        static void Check(bool ok, string message)
        {
            if (!ok) throw new Exception("FAIL: " + message);
            Console.WriteLine("PASS: " + message);
        }
        static bool Reject(Action action)
        {
            try { action(); return false; }
            catch (InvalidDataException) { return true; }
        }
        var settings = new OidcSettings("https://idp.example.invalid/realm", "gateway-client",
            Path.GetFullPath("secret.fixture"), "https://gateway.example.invalid:9443",
            "urn:company:phishing-resistant", "fido2", "recovery",
            [new OidcAccount("immutable-subject", "alice", "gateway-operators", "Operator")]);
        var policy = new EnterpriseOidcPolicy(settings);
        var now = DateTimeOffset.UtcNow;
        Claim[] valid = [
            new("sub", "immutable-subject"), new("aud", "gateway-client"),
            new("acr", settings.RequiredAcr), new("amr", "fido2"),
            new("auth_time", now.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new("groups", "gateway-operators"), new("roles", "Administrator")];
        ClaimsPrincipal Principal(IEnumerable<Claim> claims) => new(new ClaimsIdentity(claims, "fixture"));
        bool Accept(IEnumerable<Claim> claims, string? issuer = null) =>
            policy.ValidateToken(Principal(claims), issuer ?? settings.Issuer, now, out _, out _);
        Check(policy.ValidateToken(Principal(valid), settings.Issuer, now, out var mapped, out _) &&
              mapped?.Username == "alice" && mapped.Role == "Operator",
            "signed claims can map only explicitly configured subject and local operator role");
        Check(!Accept(valid, "https://idp.example.invalid/other"), "OIDC issuer substitution rejected");
        Check(!Accept(valid.Append(new Claim("aud", "other-client"))), "multiple audiences rejected");
        Check(!Accept(valid.Append(new Claim("azp", "other-client"))), "unauthorized party rejected");
        Check(!Accept(valid.Append(new Claim("sub", "another"))), "ambiguous immutable subject rejected");
        Check(!Accept(valid.Where(x => x.Type != "sub")), "missing subject rejected");
        Check(!Accept(valid.Where(x => x.Type != "groups")), "missing authorized group rejected");
        Check(!Accept(valid.Where(x => x.Type != "acr")), "missing assurance class rejected");
        Check(!Accept(valid.Where(x => x.Type != "amr").Append(new Claim("amr", "mfa"))),
            "generic MFA cannot substitute for configured FIDO2 assurance method");
        Check(!Accept(valid.Where(x => x.Type != "auth_time").Append(new Claim("auth_time",
            now.AddMinutes(-6).ToUnixTimeSeconds().ToString()))), "stale step-up authentication rejected");
        Check(!Accept(valid.Where(x => x.Type != "auth_time").Append(new Claim("auth_time",
            now.AddMinutes(2).ToUnixTimeSeconds().ToString()))), "future authentication time rejected");
        Check(!Accept(valid.Where(x => x.Type != "sub").Append(new Claim("sub", "unknown"))),
            "unknown user not automatically provisioned");
        Check(Reject(() => new EnterpriseOidcPolicy(settings with { Issuer = "http://idp.example.invalid" })) &&
              Reject(() => new EnterpriseOidcPolicy(settings with { RequiredAmr = "mfa" })),
            "insecure issuer and generic MFA configuration rejected");
        Check(Reject(() => new EnterpriseOidcPolicy(settings with {
              Accounts = [settings.Accounts[0], settings.Accounts[0] with { Subject = "different" }] })),
            "multiple subjects cannot share local account");
        Check(Reject(() => new EnterpriseOidcPolicy(settings with { BreakGlassUsername = "alice" })),
            "recovery account cannot overlap federated mapping");
        Check(policy.MatchesOrigin("https", "gateway.example.invalid:9443") &&
              !policy.MatchesOrigin("http", "gateway.example.invalid:9443") &&
              !policy.MatchesOrigin("https", "gateway.example.invalid:9444") &&
              !policy.MatchesOrigin("https", "evil.example.invalid:9443"),
            "enterprise administration restricted to configured management TLS origin");
        var ticket = Principal([new(EnterpriseOidcPolicy.SubjectClaim, "immutable-subject"),
            new(EnterpriseOidcPolicy.AuthTimeClaim, now.ToUnixTimeSeconds().ToString()),
            new(EnterpriseOidcPolicy.PolicyClaim, policy.Fingerprint)]);
        Check(policy.SessionValid(ticket, "alice", "Operator", now) &&
              !policy.SessionValid(ticket, "alice", "Administrator", now) &&
              !policy.SessionValid(ticket, "other-user", "Operator", now),
            "local cookie is bound to mapped identity and role");
        Check(policy.SessionValid(ticket, "alice", "Operator", now.AddMinutes(6)) &&
              !policy.SessionValid(ticket, "alice", "Operator", now.AddMinutes(6), stepUp: true) &&
              !policy.SessionValid(ticket, "alice", "Operator", now.AddMinutes(10)),
            "short absolute session and stricter mutation step-up deadline enforced");
        var replaced = new EnterpriseOidcPolicy(settings with { RequiredAcr = "urn:changed" });
        Check(!replaced.SessionValid(ticket, "alice", "Operator", now),
            "policy change revokes existing federated session");
    }
}
