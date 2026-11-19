using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

/// <summary>
/// Creates the Windows control-plane state tree with an explicit ACL. DPAPI
/// LocalMachine protects key contents but does not replace filesystem access
/// control for the wrapped key XML.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsStateProtection
{
    public static string InitializeStateDirectory(string productDirectory, string stateDirectory)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows state protection is Windows-only");
        if (string.IsNullOrWhiteSpace(productDirectory) || !Path.IsPathFullyQualified(productDirectory) ||
            string.IsNullOrWhiteSpace(stateDirectory) || !Path.IsPathFullyQualified(stateDirectory))
            throw new InvalidOperationException("Windows state paths must be absolute");

        productDirectory = Path.GetFullPath(productDirectory);
        stateDirectory = Path.GetFullPath(stateDirectory);
        if (!string.Equals(Path.GetDirectoryName(stateDirectory), productDirectory, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(stateDirectory), "ControlPlane", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Windows state must be productDirectory\\ControlPlane");

        EnsurePrivateDirectory(productDirectory);
        EnsurePrivateDirectory(stateDirectory);
        var keyDirectory = Path.Combine(stateDirectory, "data-protection-keys");
        EnsurePrivateDirectory(keyDirectory);
        foreach (var keyFile in Directory.EnumerateFiles(keyDirectory, "*.xml"))
            ValidatePrivateFile(keyFile);
        return stateDirectory;
    }

    private static void EnsurePrivateDirectory(string path)
    {
        var existed = Directory.Exists(path);
        if (!existed) Directory.CreateDirectory(path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Windows control-plane state must not be a reparse point");

        if (existed)
        {
            ValidatePrivateDirectoryAcl(path);
            return;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddFullControl(security, WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Current Windows identity has no SID"),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        AddFullControl(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit);
        new DirectoryInfo(path).SetAccessControl(security);

        ValidatePrivateDirectoryAcl(path);
    }

    private static void ValidatePrivateDirectoryAcl(string path)
    {
        var actual = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access);
        if (!actual.AreAccessRulesProtected)
            throw new InvalidOperationException(
                "Existing Windows control-plane directory has inherited ACLs; protect it through a reviewed offline migration");
        var allowed = AllowedPrincipals();
        foreach (FileSystemAccessRule rule in actual.GetAccessRules(includeExplicit: true, includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !allowed.Contains((SecurityIdentifier)rule.IdentityReference))
                throw new InvalidOperationException(
                    "Existing Windows control-plane directory has an unapproved allow rule; use a reviewed offline ACL migration");
        }
    }

    private static void ValidatePrivateFile(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Windows Data Protection key files must not be reparse points");
        var actual = new FileInfo(path).GetAccessControl(AccessControlSections.Access);
        var allowed = AllowedPrincipals();
        foreach (FileSystemAccessRule rule in actual.GetAccessRules(includeExplicit: true, includeInherited: true,
                     targetType: typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                !allowed.Contains((SecurityIdentifier)rule.IdentityReference))
                throw new InvalidOperationException(
                    "Existing Windows Data Protection key file has an unapproved allow rule; use a reviewed offline ACL migration");
        }
    }

    private static HashSet<SecurityIdentifier> AllowedPrincipals()
    {
        return
        [
            WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("Current Windows identity has no SID"),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
        ];
    }

    private static void AddFullControl(ObjectSecurity security, SecurityIdentifier sid, InheritanceFlags inheritance)
    {
        var rule = new FileSystemAccessRule(sid, FileSystemRights.FullControl, inheritance,
            PropagationFlags.None, AccessControlType.Allow);
        if (security is DirectorySecurity directory) directory.AddAccessRule(rule);
        else if (security is FileSecurity file) file.AddAccessRule(rule);
        else throw new InvalidOperationException("Unsupported Windows ACL object");
    }
}
