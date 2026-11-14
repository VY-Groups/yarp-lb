// GatewayCore administration: Active Directory over LDAPS only.
// Group membership is checked at sign-in AND on each authenticated request.
// A domain account must match an explicitly configured AD group to receive access.
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;

sealed record DirectorySettings(
    bool Enabled = false,
    string Host = "",
    int Port = 636,
    string SearchBaseDn = "",
    string BindUsername = "",
    string EncryptedBindPassword = "",
    string AdminGroupDn = "",
    string OperatorGroupDn = "",
    string ViewerGroupDn = "");

sealed record DirectorySettingsInput(
    bool Enabled,
    string Host,
    int Port,
    string SearchBaseDn,
    string BindUsername,
    string Password,
    string AdminGroupDn,
    string OperatorGroupDn,
    string ViewerGroupDn);

sealed record DirectoryLoginResult(string SamAccountName, string DistinguishedName, string Email, string Role);
sealed record DirectoryLoginTest(string Username, string Password);

sealed class DirectoryAuthService
{
    private const string NestedMembershipOid = "1.2.840.113556.1.4.1941";
    private readonly string _configPath;
    private readonly IDataProtector _protector;
    private readonly object _saveLock = new();

    public DirectoryAuthService(IDataProtectionProvider provider, string stateDirectory)
    {
        // Use the SAME already-validated state root as the control plane.
        // Linux production, disposable EC2 CI and Windows each select their
        // own root before DI starts; never create a second identity store.
        if (string.IsNullOrWhiteSpace(stateDirectory) || !Path.IsPathFullyQualified(stateDirectory))
            throw new ArgumentException("Directory state root must be an absolute path", nameof(stateDirectory));
        if (!Directory.Exists(stateDirectory))
            throw new DirectoryNotFoundException("Control plane state root missing: " + stateDirectory);
        _configPath = Path.Combine(stateDirectory, "active-directory.json");
        _protector = provider.CreateProtector("GatewayCoreYarp.DirectoryBindPassword.v1");
    }

    public DirectorySettings Read() => File.Exists(_configPath)
        ? JsonSerializer.Deserialize<DirectorySettings>(File.ReadAllText(_configPath)) ?? new()
        : new();

    public object PublicSettings()
    {
        var s = Read();
        return new { s.Enabled, s.Host, s.Port, s.SearchBaseDn, s.BindUsername,
            s.AdminGroupDn, s.OperatorGroupDn, s.ViewerGroupDn,
            passwordConfigured = !string.IsNullOrEmpty(s.EncryptedBindPassword),
            authentication = "LDAPS password bind; AD nested-group authorization; OTP required",
            tls = "TLS certificate chain and hostname validation are not bypassed" };
    }

    public void Save(DirectorySettingsInput input)
    {
        Validate(input);
        lock (_saveLock)
        {
            var previous = Read();
            var changedIdentity = !string.Equals(input.BindUsername, previous.BindUsername, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(input.Host, previous.Host, StringComparison.OrdinalIgnoreCase);
            var protectedPassword = !string.IsNullOrWhiteSpace(input.Password)
                ? _protector.Protect(input.Password)
                : changedIdentity ? "" : previous.EncryptedBindPassword;
            var settings = new DirectorySettings(input.Enabled, input.Host.Trim(), input.Port,
                input.SearchBaseDn.Trim(), input.BindUsername.Trim(), protectedPassword,
                input.AdminGroupDn.Trim(), input.OperatorGroupDn.Trim(), input.ViewerGroupDn.Trim());
            if (settings.Enabled)
            {
                if (string.IsNullOrWhiteSpace(protectedPassword))
                    throw new ArgumentException("Provide an AD bind service account password before enabling LDAP login.");
                CheckServiceConnection(settings); // fail closed; don't save enabled configuration if TLS/bind/group checks fail
            }
            var tmp = _configPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(settings));
            File.Move(tmp, _configPath, true);
        }
    }

    public void TestSavedConnection()
    {
        var s = Read();
        ValidateStored(s);
        CheckServiceConnection(s);
    }

    public DirectoryLoginResult? TryLogin(string username, string password)
    {
        if (!Regex.IsMatch(username ?? "", "^[A-Za-z0-9_.-]{1,64}$") || string.IsNullOrEmpty(password)) return null;
        var settings = Read();
        if (!settings.Enabled) return null;
        using var reader = ServiceConnection(settings);
        var user = FindUser(reader, settings, username);
        if (user is null) return null;
        // Never relay the submitted password to an HTTP endpoint or persist it.
        using var userConn = NewConnection(settings, user.Value.Dn, password);
        userConn.Bind();
        var role = ResolveRole(reader, settings, user.Value.Dn);
        if (role is null || string.IsNullOrWhiteSpace(user.Value.Email)) return null;
        return new DirectoryLoginResult(username, user.Value.Dn, user.Value.Email, role);
    }

    public bool StillAuthorized(string prefixedUsername, string expectedDn, string expectedRole)
    {
        var settings = Read();
        if (!settings.Enabled || !prefixedUsername.StartsWith("ad:", StringComparison.OrdinalIgnoreCase)) return false;
        using var conn = ServiceConnection(settings);
        var username = prefixedUsername[3..];
        var user = FindUser(conn, settings, username);
        return user is not null &&
            string.Equals(user.Value.Dn, expectedDn, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(ResolveRole(conn, settings, user.Value.Dn), expectedRole, StringComparison.Ordinal);
    }

    private (string Dn, string Email)? FindUser(LdapConnection conn, DirectorySettings s, string username)
    {
        var filter = $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={EscapeFilter(username)}))";
        var res = (SearchResponse)conn.SendRequest(new SearchRequest(s.SearchBaseDn, filter,
            SearchScope.Subtree, "mail", "userAccountControl"));
        if (res.Entries.Count != 1) return null;
        var entry = res.Entries[0];
        if (!entry.Attributes.Contains("userAccountControl") ||
            !int.TryParse(entry.Attributes["userAccountControl"]?[0]?.ToString(), out var flags) ||
            (flags & 0x2) != 0) return null;
        var email = entry.Attributes.Contains("mail") ? entry.Attributes["mail"]?[0]?.ToString() ?? "" : "";
        return (entry.DistinguishedName, email);
    }

    private static string? ResolveRole(LdapConnection conn, DirectorySettings s, string dn)
    {
        if (InGroup(conn, dn, s.AdminGroupDn)) return "Administrator";
        if (InGroup(conn, dn, s.OperatorGroupDn)) return "Operator";
        if (InGroup(conn, dn, s.ViewerGroupDn)) return "Viewer";
        return null;
    }

    private static bool InGroup(LdapConnection conn, string userDn, string groupDn)
    {
        if (string.IsNullOrWhiteSpace(groupDn)) return false;
        // LDAP_MATCHING_RULE_IN_CHAIN resolves nested memberOf relationships in AD DS.
        var filter = $"(memberOf:{NestedMembershipOid}:={EscapeFilter(groupDn)})";
        var result = (SearchResponse)conn.SendRequest(new SearchRequest(userDn, filter,
            SearchScope.Base, "distinguishedName"));
        return result.Entries.Count == 1;
    }

    private static string EscapeFilter(string s) => s.Replace("\\", "\\5c")
        .Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");

    private static LdapConnection NewConnection(DirectorySettings s, string bindIdentity, string password)
    {
        var endpoint = new LdapDirectoryIdentifier(s.Host, s.Port, true, false);
        var conn = new LdapConnection(endpoint, new NetworkCredential(bindIdentity, password), AuthType.Basic)
        {
            Timeout = TimeSpan.FromSeconds(6)
        };
        conn.SessionOptions.ProtocolVersion = 3;
        conn.SessionOptions.SecureSocketLayer = true;
        // No VerifyServerCertificate override! Windows validates trust/hostname.
        return conn;
    }

    private LdapConnection ServiceConnection(DirectorySettings s)
    {
        ValidateStored(s);
        var conn = NewConnection(s, s.BindUsername, _protector.Unprotect(s.EncryptedBindPassword));
        try { conn.Bind(); return conn; }
        catch { conn.Dispose(); throw; }
    }

    private void CheckServiceConnection(DirectorySettings s)
    {
        using var conn = ServiceConnection(s);
        var baseResult = (SearchResponse)conn.SendRequest(new SearchRequest(s.SearchBaseDn,
            "(objectClass=*)", SearchScope.Base, "distinguishedName"));
        if (baseResult.Entries.Count != 1) throw new InvalidOperationException("LDAP search base not available.");
        foreach (var groupDn in new[]{s.AdminGroupDn, s.OperatorGroupDn, s.ViewerGroupDn})
        {
            if (string.IsNullOrWhiteSpace(groupDn)) continue;
            var groupResult = (SearchResponse)conn.SendRequest(new SearchRequest(groupDn,
                "(objectClass=group)", SearchScope.Base, "distinguishedName"));
            if (groupResult.Entries.Count != 1)
                throw new InvalidOperationException("An allowed Active Directory security group was not found.");
        }
    }

    private static void Validate(DirectorySettingsInput input)
    {
        if (input.Host is null || input.SearchBaseDn is null || input.BindUsername is null || input.Password is null ||
            input.AdminGroupDn is null || input.OperatorGroupDn is null || input.ViewerGroupDn is null)
            throw new ArgumentException("Missing Active Directory configuration fields.");
        if (!Regex.IsMatch(input.Host.Trim(), "^[a-zA-Z0-9][a-zA-Z0-9.-]{1,252}[a-zA-Z0-9]$") ||
            input.Port is not (636 or 3269) || input.BindUsername.Length > 256 ||
            input.Password.Length > 512 || input.SearchBaseDn.Length > 1000 ||
            input.AdminGroupDn.Length > 1000 || input.OperatorGroupDn.Length > 1000 || input.ViewerGroupDn.Length > 1000)
            throw new ArgumentException("Use a DNS hostname and LDAPS port 636 (or global catalog 3269).");
        if (input.Enabled && (string.IsNullOrWhiteSpace(input.BindUsername) ||
            string.IsNullOrWhiteSpace(input.AdminGroupDn) ||
            !input.SearchBaseDn.Contains("DC=", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("A service bind identity, search base and administrator AD security group are required.");
    }

    private static void ValidateStored(DirectorySettings s)
    {
        Validate(new DirectorySettingsInput(s.Enabled,s.Host,s.Port,s.SearchBaseDn,
            s.BindUsername,"",s.AdminGroupDn,s.OperatorGroupDn,s.ViewerGroupDn));
        if (string.IsNullOrWhiteSpace(s.EncryptedBindPassword))
            throw new InvalidOperationException("Service account password not configured.");
    }
}
