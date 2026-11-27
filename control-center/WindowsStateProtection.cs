using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;

internal sealed class WindowsPrivateFileAclException : InvalidOperationException
{
    internal WindowsPrivateFileAclException():base("Existing Windows private file has an unapproved allow rule; use a reviewed offline ACL migration"){}
}

/// <summary>
/// Creates the Windows control-plane state tree with an explicit ACL. DPAPI
/// LocalMachine protects key contents but does not replace filesystem access
/// control for the wrapped key XML.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsStateProtection
{
    public static string InitializeStateDirectory(string productDirectory, string stateDirectory, bool installerLocalSystem = false)
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

        if (installerLocalSystem && (Directory.Exists(productDirectory) || File.Exists(productDirectory)))
            throw new InvalidOperationException("Installer provisioning requires absent state");
        EnsurePrivateDirectory(productDirectory, installerLocalSystem);
        EnsurePrivateDirectory(stateDirectory, installerLocalSystem);
        var keyDirectory = Path.Combine(stateDirectory, "data-protection-keys");
        EnsurePrivateDirectory(keyDirectory, installerLocalSystem);
        foreach (var keyFile in Directory.EnumerateFiles(keyDirectory, "*.xml"))
            ValidatePrivateFile(keyFile);
        return stateDirectory;
    }

    /// <summary>
    /// Verify the source/offline staging directory without creating it or
    /// modifying existing ACLs. Reject ancestors traversing reparse points.
    /// </summary>
    public static void ValidateOfflineKeyRingDirectory(string path) => ValidateOfflineKeyRingDirectory(path,false);

    internal static void ValidateOfflineKeyRingDirectory(string path,bool classifyFileAcl)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) || !Directory.Exists(path))
            throw new InvalidOperationException("Offline Windows key-ring directory must already exist");
        RejectReparseAncestors(path);
        ValidatePrivateDirectoryAcl(path);
        foreach (var file in Directory.EnumerateFiles(path))
            ValidatePrivateFile(file,classifyFileAcl);
    }

    /// <summary>
    /// Creates a NEW private offline staging directory; never alters an
    /// existing directory or its ACLs as a side effect of migration.
    /// </summary>
    public static void CreateNewOfflinePrivateDirectory(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) || Directory.Exists(path) ||
            File.Exists(path) || new DirectoryInfo(path).LinkTarget is not null)
            throw new InvalidOperationException("Offline Windows staging directory must be absent");
        var parent = Path.GetDirectoryName(Path.GetFullPath(path))
            ?? throw new InvalidOperationException("Offline Windows staging parent missing");
        ValidateOfflineKeyRingDirectory(parent);
        EnsurePrivateDirectory(path);
    }

    private static void EnsurePrivateDirectory(string path, bool installerLocalSystem = false)
    {
        // Directory.CreateDirectory follows existing parent junctions and
        // symlinks. Reject linked ancestors BEFORE creating any state under
        // their targets, not just a linked final component after creation.
        RejectReparseAncestors(path);
        var existed = Directory.Exists(path);
        if (!existed) Directory.CreateDirectory(path);
        RejectReparseAncestors(path);

        if (existed)
        {
            ValidatePrivateDirectoryAcl(path);
            return;
        }

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        if (!installerLocalSystem)
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

    private static void RejectReparseAncestors(string path)
    {
        var current = Path.GetFullPath(path);
        while (true)
        {
            try
            {
                // LinkTarget also catches a dangling link, where Exists()
                // may report false. Inspect every existing ancestor, including
                // those above the product directory and the final component.
                if (new DirectoryInfo(current).LinkTarget is not null ||
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException(
                        "Windows control-plane state path must not traverse a junction or symbolic link");
            }
            catch (FileNotFoundException) { } // Not yet created; inspect its parent.
            catch (DirectoryNotFoundException) { }

            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) ||
                string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
                break;
            current = parent;
        }
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

    private static void ValidatePrivateFile(string path,bool classifyFileAcl=false)
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
            {
                if(classifyFileAcl)throw new WindowsPrivateFileAclException();
                throw new InvalidOperationException(
                    "Existing Windows Data Protection key file has an unapproved allow rule; use a reviewed offline ACL migration");
            }
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
