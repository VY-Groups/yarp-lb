using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed record OidcAccount(string Subject, string Username, string Group, string Role);
internal sealed record OidcSettings(string Issuer, string ClientId, string ClientSecretFile,
    string ManagementOrigin, string RequiredAcr, string RequiredAmr,
    string BreakGlassUsername, OidcAccount[] Accounts);

/// <summary>Explicit, single-issuer, operator-provisioned bindings. No token
/// can create an account, choose a local role, or map by mutable email.</summary>
internal sealed class EnterpriseOidcPolicy
{
    internal const string Scheme = "EnterpriseOidc";
    internal const string Callback = "/admin/oidc/callback";
    internal const string SubjectClaim = "gc_oidc_subject";
    internal const string AuthTimeClaim = "gc_oidc_auth_time";
    internal const string PolicyClaim = "gc_oidc_policy";
    internal const string RecoveryClaim = "gc_recovery";
    internal static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);
    internal static readonly TimeSpan StepUpLifetime = TimeSpan.FromMinutes(5);
    internal OidcSettings Settings { get; }
    internal string Fingerprint { get; }
    private readonly Dictionary<string, OidcAccount> subjects;

    internal EnterpriseOidcPolicy(OidcSettings settings)
    {
        static bool Text(string? s, int max) => s is { Length: > 0 } && s.Length <= max &&
            !s.Any(char.IsControl) && s == s.Trim();
        static bool User(string? s) => s is { Length: >= 3 and <= 40 } &&
            s.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.');
        static bool Https(string? s, bool origin) => Uri.TryCreate(s, UriKind.Absolute, out var u) &&
            u.Scheme == Uri.UriSchemeHttps && u.Host.Length > 0 && u.UserInfo.Length == 0 &&
            u.Query.Length == 0 && u.Fragment.Length == 0 &&
            (!origin || (u.AbsolutePath == "/" && s == u.GetLeftPart(UriPartial.Authority)));
        if (!Text(settings.Issuer, 512) || !Https(settings.Issuer, false) ||
            !Text(settings.ManagementOrigin, 512) || !Https(settings.ManagementOrigin, true) ||
            !Text(settings.ClientId, 256) || !Text(settings.ClientSecretFile, 1024) ||
            !Path.IsPathFullyQualified(settings.ClientSecretFile) || !Text(settings.RequiredAcr, 256) ||
            settings.RequiredAmr is not ("fido2" or "webauthn" or "passkey" or "hwk") ||
            !User(settings.BreakGlassUsername) || settings.Accounts is not { Length: >= 1 and <= 512 })
            throw new InvalidDataException("Invalid enterprise OIDC configuration");
        subjects = new(StringComparer.Ordinal);
        var usernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var account in settings.Accounts)
        {
            if (account is null || !Text(account.Subject, 512) || !User(account.Username) ||
                !Text(account.Group, 256) || account.Role is not ("Administrator" or "Operator" or "Viewer") ||
                account.Username.Equals(settings.BreakGlassUsername, StringComparison.OrdinalIgnoreCase) ||
                !subjects.TryAdd(account.Subject, account) || !usernames.Add(account.Username))
                throw new InvalidDataException("OIDC accounts must use unique subject and local username bindings");
        }
        Settings = settings;
        Fingerprint = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(settings)));
    }

    internal static EnterpriseOidcPolicy? FromFile(string? path)
    {
        if (path is null) return null;
        var bytes = ReadPrivate(path, 262144);
        if (!HasUniqueJsonPropertyNames(bytes))
            throw new InvalidDataException("OIDC configuration contains duplicate property names");
        var settings = JsonSerializer.Deserialize<OidcSettings>(bytes,
            new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow })
            ?? throw new InvalidDataException("OIDC settings missing");
        // Allow operators to keep secret-file locations outside the JSON file.
        // A present but empty override is rejected by the normal path validation.
        var secretFileOverride = Environment.GetEnvironmentVariable("GATEWAY_OIDC_CLIENT_SECRET_FILE");
        if (secretFileOverride is not null)
            settings = settings with { ClientSecretFile = secretFileOverride };
        return new EnterpriseOidcPolicy(settings);
    }

    // Reject ambiguous configuration at every nesting level before the
    // serializer's last-value-wins behavior can change a security policy or
    // a subject-to-role binding without making that ambiguity visible.
    internal static bool HasUniqueJsonPropertyNames(ReadOnlySpan<byte> json)
    {
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        return HasUniqueJsonPropertyNames(document.RootElement);
    }

    private static bool HasUniqueJsonPropertyNames(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || !HasUniqueJsonPropertyNames(property.Value))
                    return false;
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                if (!HasUniqueJsonPropertyNames(item))
                    return false;
        }
        return true;
    }

    internal string ReadClientSecret()
    {
        var secret = Encoding.UTF8.GetString(ReadPrivate(Settings.ClientSecretFile, 4096)).TrimEnd('\r','\n');
        if (secret.Length == 0 || secret.Any(char.IsControl))
            throw new InvalidDataException("Invalid OIDC client secret");
        return secret;
    }

    internal static byte[] ReadPrivate(string path, int max)
    {
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("OIDC config/secret must be an existing absolute non-link path");
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
             UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
             UnixFileMode.OtherExecute)) != 0)
            throw new InvalidDataException("OIDC config/secret requires owner-only access");
        if (OperatingSystem.IsWindows()) ValidateWindowsFileAcl(path);
        using var file = File.OpenRead(path);
        if (file.Length is < 1 || file.Length > max) throw new InvalidDataException("OIDC file exceeds size bound");
        var bytes = new byte[(int)file.Length];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1) throw new InvalidDataException("OIDC file changed during read");
        return bytes;
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsFileAcl(string path)
    {
        try
        {
            var serviceSid = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidDataException("Cannot identify the Windows service account");
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administratorsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                serviceSid.Value, systemSid.Value, administratorsSid.Value
            };
            var security = new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
                !allowed.Contains(owner.Value))
                throw new InvalidDataException("OIDC config/secret owner must be the service account, SYSTEM or Administrators");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (rule.AccessControlType == AccessControlType.Allow &&
                    rule.IdentityReference is SecurityIdentifier sid && !allowed.Contains(sid.Value))
                    throw new InvalidDataException("OIDC config/secret ACL grants access outside the service account, SYSTEM and Administrators");
            }
        }
        catch (InvalidDataException) { throw; }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            throw new InvalidDataException("Cannot verify restrictive Windows ACL for OIDC config/secret", ex);
        }
    }

    internal bool IsBreakGlass(string? username) =>
        string.Equals(username, Settings.BreakGlassUsername, StringComparison.OrdinalIgnoreCase);
    internal bool RecoverySessionValid(ClaimsPrincipal principal, string username, string role, string provider) =>
        provider == "Local" && role == "Administrator" && IsBreakGlass(username) &&
        Single(principal, RecoveryClaim) == Fingerprint &&
        !principal.HasClaim(claim => claim.Type == SubjectClaim);

    internal bool MatchesOrigin(string scheme, string? host) =>
        !string.IsNullOrWhiteSpace(host) &&
        Uri.TryCreate(scheme + "://" + host, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0 && uri.AbsolutePath == "/" &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.GetLeftPart(UriPartial.Authority), Settings.ManagementOrigin, StringComparison.OrdinalIgnoreCase);

    internal OidcAccount? Resolve(string? subject) =>
        subject is not null && subjects.TryGetValue(subject, out var row) ? row : null;

    internal static string? Single(ClaimsPrincipal principal, string type)
    {
        var matches = principal.FindAll(type).Take(2).ToArray();
        return matches.Length == 1 ? matches[0].Value : null;
    }

    internal bool ValidateToken(ClaimsPrincipal principal, string issuer, DateTimeOffset now,
        out OidcAccount? account, out long authTime)
    {
        account = null; authTime = 0;
        if (issuer != Settings.Issuer || Single(principal, "aud") != Settings.ClientId ||
            Single(principal, "acr") != Settings.RequiredAcr ||
            !principal.FindAll("amr").Any(c => c.Value == Settings.RequiredAmr) ||
            !long.TryParse(Single(principal, "auth_time"), NumberStyles.None, CultureInfo.InvariantCulture, out authTime) ||
            !Fresh(authTime, now, StepUpLifetime)) return false;
        var azp = principal.FindAll("azp").Take(2).ToArray();
        if (azp.Length > 1 || (azp.Length == 1 && azp[0].Value != Settings.ClientId)) return false;
        var row = Resolve(Single(principal, "sub"));
        if (row is null || !principal.FindAll("groups").Any(x => x.Value == row.Group)) return false;
        account = row;
        return true;
    }

    internal static bool Fresh(long authTime, DateTimeOffset now, TimeSpan maximum)
    {
        var seconds = now.ToUnixTimeSeconds();
        return authTime > 0 && authTime <= seconds + 30 &&
            authTime > seconds - (long)maximum.TotalSeconds;
    }

    internal static bool AfterRevocation(ClaimsPrincipal principal, long revokedBefore) =>
        revokedBefore >= 0 && long.TryParse(Single(principal, AuthTimeClaim),
            NumberStyles.None, CultureInfo.InvariantCulture, out var time) && time > revokedBefore;

    internal bool SessionValid(ClaimsPrincipal principal, string username, string role, DateTimeOffset now,
        bool stepUp = false)
    {
        var row = Resolve(Single(principal, SubjectClaim));
        return row is not null && row.Username.Equals(username, StringComparison.OrdinalIgnoreCase) &&
            row.Role == role && Single(principal, PolicyClaim) == Fingerprint &&
            long.TryParse(Single(principal, AuthTimeClaim), NumberStyles.None, CultureInfo.InvariantCulture, out var time) &&
            Fresh(time, now, stepUp ? StepUpLifetime : SessionLifetime);
    }
}
