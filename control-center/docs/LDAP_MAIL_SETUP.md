# SpeedSign YARP 0.1 — Active Directory (LDAPS) and SMTP/OTP setup

## First run and sign-in

Open `http://127.0.0.1:8080/dashboard` in a browser **on the test server**. On the screen labelled **Create initial administrator**, enter a local recovery administrator username, a valid mailbox, and a unique 16–256 character password. This **local account is not an Active Directory account**. Complete initial setup, then sign in. Keep the account for emergency recovery, restrict its use, and manage its password securely.

Choose **Mail & OTP** from the sidebar (Administrator role only), then **Active Directory**. Once AD is enabled, the login page has a sign-in-method selector: *Local administrator* or *Active Directory / LDAPS*.

## Offline prerequisite

Microsoft NuGet package `System.DirectoryServices.Protocols` **10.0.15** is needed in addition to your existing `Yarp.ReverseProxy` package. The package is an official Microsoft library. If the gateway cannot reach NuGet, download it from your connected laptop:

```powershell
New-Item -ItemType Directory -Path C:\YARP-Packages -Force | Out-Null
Invoke-WebRequest -Uri 'https://api.nuget.org/v3-flatcontainer/system.directoryservices.protocols/10.0.15/system.directoryservices.protocols.10.0.15.nupkg' -OutFile 'C:\YARP-Packages\System.DirectoryServices.Protocols.10.0.15.nupkg'
Get-FileHash C:\YARP-Packages\System.DirectoryServices.Protocols.10.0.15.nupkg -Algorithm SHA256
```

Transfer the `.nupkg` using your approved transfer channel to `C:\YARP-Packages` on the test gateway. Preserve the other existing local `.nupkg` packages. 0.1 installer adds the PackageReference, performs an offline restore, compiles, and rolls back source files if it fails. It does not change `appsettings.json` or stored administrator accounts.

## Step 1 — Configure mail

Use **Mail & OTP** (not the old settings modal):

- SMTP FQDN: a relay reachable from the gateway, e.g. `mail.internal.example.com`
- TCP port: normally 587 or 25 with STARTTLS. `.NET SmtpClient` in this version does **not** support implicit-TLS port 465.
- Sender: an allowed mailbox (`yarp-noreply@yourdomain.example`)
- Credentials: optional for an approved anonymous relay, otherwise use a dedicated restricted SMTP account
- Check **Require STARTTLS**. Leave **Require email OTP** unchecked.

**Save SMTP settings**, then **Send test to my account**. The relay must accept the message; check the mailbox actually received it. Then check **Require email OTP** and save again. The backend blocks enabling OTP if the current relay settings do not match a successful SMTP test.

The test sends only to the signed-in local administrator's registered email, is rate-limited, and does not expose the SMTP credential. The credential is protected by .NET Data Protection with Windows DPAPI on this host. The test acknowledgement proves relay acceptance, not final delivery to the mailbox.

## Step 2 — Prepare Active Directory

Request from your AD administrator:

- An LDAPS-enabled domain controller FQDN with a trusted certificate whose SAN matches the FQDN
- Outbound TCP 636 (or 3269 for Global Catalog) from the test gateway to the DC
- A **read-only** directory service account UPN and password (e.g. `svc_yarp_bind@corp.example`), not Domain Admin
- Search base DN (e.g. `DC=corp,DC=example`)
- Three dedicated security groups, with their complete distinguished names:
  - `CN=YARP-Administrators,OU=Security,DC=corp,DC=example`
  - `CN=YARP-Operators,OU=Security,DC=corp,DC=example`
  - `CN=YARP-Viewers,OU=Security,DC=corp,DC=example`
- Each permitted user's `mail` attribute populated with a real mailbox for OTP

Verify from the gateway:

```powershell
Resolve-DnsName dc01.corp.example
Test-NetConnection dc01.corp.example -Port 636
```

No domain-join requirement for the LDAPS simple-bind flow, but the server must trust the DC certificate chain. **Never disable LDAP TLS verification**.

## Step 3 — Configure AD in the frontend

Open **Active Directory** and enter: DC hostname, port 636, search base DN, bind UPN and password, and the three AD group DNs. Select **Enable Active Directory login** and press **Save & validate directory**. The save performs an LDAPS certificate-validated service bind and group-base checks. Click **Test saved LDAPS** to retest the connection. Use the optional **Test an AD account** form to verify credentials and mapped role without saving the password.

Only AD users mapped to an authorized group can sign in. Direct and nested membership is evaluated through the AD LDAP matching rule `1.2.840.113556.1.4.1941` (standard `memberOf` transitive rule). AD primary-group membership is not inferred by this check: configure dedicated explicit security groups instead.

Then sign out, choose **Active Directory / LDAPS** on the login form, supply the AD `sAMAccountName` and password, and verify the email OTP code. AD credentials are bound to the domain controller via LDAPS; the password is not stored by SpeedSign.

If an AD account is disabled, membership is removed, the DC is unavailable, or its certificate fails validation, existing AD console sessions fail closed on revalidation. An AD user can also be offboarded in the **Admin accounts** page; to fully offboard, remove the user from the AD security group or disable the AD account in AD.

## Management limitations / production controls

- These features are **code delivered for a local test listener**, NOT production-verified. Run Windows `dotnet build`, SMTP acceptance tests, LDAP sign-in tests, cookie/session tests, and a security assessment.
- Email OTP is *not phishing-resistant MFA*. For CA production, use approved identity federation (e.g. enterprise IdP with FIDO2/passkeys/smart-card) and audited break-glass procedures.
- Admin console remains bound to `127.0.0.1:8080` in the existing test `appsettings.json`. Do not expose it as HTTP to any network. Configure HTTPS and admin-only network access in a separate production deployment.
- The LDAP bind password and SMTP secret are encrypted at rest by Windows DPAPI-bound Data Protection. Use a restricted Windows Service identity and ACLs on `C:\ProgramData\SpeedSignYarp\ControlPlane`. Keep backups and recovery keys protected. DPAPI secrets on one gateway cannot simply be copied to another.
- This is Active Directory DS (not generic OpenLDAP), Windows credentials over **LDAPS**, not Kerberos integrated SSO.
- Authentication and admin configuration remain local to one management instance. Multi-controller shared state and SSO are not implemented here.
- Do not enable unauthenticated management endpoints, use inline scripts/styles, or turn off certificate validation to troubleshoot.
