# Frozen GatewayCore #48 test candidate

**Production NO-GO.** This is a controlled-test binary candidate, not a production installer or a claim of issue closure. Windows Server 2022 x64 and Ubuntu 24.04 x64 are the tested CI targets. RHEL host/systemd/SELinux, physical fleet, production PKI and recovery remain separate site acceptance. The build includes a self-contained .NET runtime but OS native dependencies and protected state/credential provisioning are still required.

Freeze main, run the original 16 v0.1 required workflows and the explicit #48 lifecycle workflows in assess_issue48.py at that same main SHA (dispatch missing workflows without moving main). Then dispatch Frozen main issue 48 candidate verification on main. The workflow rejects missing/failed/pending checks or evidence from a topic branch or another commit. It produces a report and two candidate archives with independently read-back checked file hashes and SHA256SUMS.txt. It does not publish a GitHub release or deploy. A package hash is integrity evidence, not a signer trust decision or proof that the extracted binary has passed service startup.

For offline transfer, record the full SOURCE_COMMIT.txt and independently obtain the GitHub Actions artifact hash and SHA256SUMS.txt over an authenticated channel. On Windows use Get-FileHash -Algorithm SHA256; on Linux use sha256sum -c SHA256SUMS.txt. Refuse mismatch. Extract into a NEW versioned binary directory, not into live ProgramData or Linux state. Never copy an appsettings file, key-ring XML, local identity database, passwords or PFX from a candidate. Provision the existing reviewed private state and runtime configuration separately using DATA_PROTECTION_PLATFORM_SUPPORT.md, the documented systemd/SCM instructions, and LINUX_DP_DISTRIBUTED_RUNTIME.md from the exact source. Do not run the old partial source-staging INSTALL.ps1 as an upgrade of this binary candidate.

Before enabling traffic, use an isolated test identity, verify exact package executable startup, cookie persistence, required listener/route behavior, and the supported mode's recovery/rotation tests. Record package SHA, OS/runtime, verified commands and evidence. Roll back by draining the node, stopping it, restoring the prior approved binary path without replacing its key ring, and restarting with still-required historical wrapping identities and independently approved configuration. Never roll back the shared authority or overwrite protected state; use the signed recovery procedure if state recovery is needed. A package workflow pass does not complete #48 without independent review and integrated runtime evidence.

### Extracted executable checks

The candidate workflow now builds and verifies packages on PRs as disposable regression tests as well as on a frozen main dispatch. Only the successful frozen-main path uploads the candidate archives. It rechecks archive SHA256 before fresh extraction, runs the actual extracted Linux native apphost through existing missing/invalid wrapping credential and persistent-cookie restart checks, and runs the extracted Windows executable through the existing LocalSystem and LocalService SCM DPAPI tests. No rebuild substitutes for the tested archive. These are hosted-runner checks, not a production installation or physical acceptance.

### Frozen-main workflow sequencing

The candidate workflow starts on the relevant main merge or manual main dispatch. A narrowly scoped Actions-write job dispatches only missing named workflows against main after checking the exact frozen SHA; it polls for their results, stops on a main change or any failure, and cannot publish a release. Original 16 baseline and 15 lifecycle checks are retained, with two additional mandatory ADC VIP provider/runtime and address-journal checks (33 total); all are matched by committed path/name; CodeQL is expected from the ordinary main push. PR jobs execute the contract and archive smoke, not an incomplete path-filtered release verdict. The legacy v0.1 auditor still enforces its original 16 checks when dispatched; its PR run executes contract tests only. The mandatory frozen-main gate supersedes path-filtered PR release polling, not the release thresholds. No automatic rerun of failed acceptance jobs.

After ADC Priority 1 integration, frozen candidate evidence additionally requires the exact-main Windows/Linux provider/controller commissioning and VIP address/journal workflows. Their successful PR runs cannot substitute for main evidence. The existing live Raft workflow remains mandatory. This does not establish physical #36 acceptance or zero downtime.

## Self-contained offline handoff (ordinary isolated test mode)

The candidate ZIP/tar.gz includes the approved documentation and the public,
platform-specific VIP commissioning tool; it intentionally excludes secrets,
live configuration, identity state, entitlement material and customer keys.
The bundled operator references retain repository-relative paths. Both archives include the complete local SOP link targets and their transitive public references, including the Windows guide for readers of the Linux package. Bundled CI YAML is reference material only; historical external URLs remain optional evidence, not offline installation prerequisites. Staging and extraction check local file-link resolution, including exact filename case, without a network or checkout. Read
`control-center/docs/END_USER_SOP.md`,
`control-center/docs/DATA_PROTECTION_PLATFORM_SUPPORT.md`,
`ops/fleet/LINUX_DP_DISTRIBUTED_RUNTIME.md` (if applicable), and
`ops/ha/ADC_DISTRIBUTED_VIP_ADMISSION.md`. Historical evidence in these documents
is identified by its own source revision; it is not a new release result.

**Transfer and integrity:** Download the artifact container and independently
record its Actions SHA-256 digest. Extract the outer artifact container to a
staging directory; the inner archive and SHA256SUMS.txt belong together.
Obtain the expected inner archive digest and complete source SHA through an
independently trusted release record. A self-supplied checksum does not prove
authenticity. On Windows PowerShell, from staging:

    $archive = Get-Item -LiteralPath '<approved exact archive filename>'
    $actual = (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash
    if ($actual -ne '<independently approved inner SHA256>') { throw 'Archive digest mismatch' }

On Linux, compare SHA256SUMS.txt to the independently approved digest, then run
`sha256sum -c SHA256SUMS.txt` from staging. Refuse mismatch on either platform.
Extract only into a new administrator-controlled version directory. Compare
SOURCE_COMMIT.txt to the full approved SHA and verify the expected native
apphost and bundled handoff are present before commissioning.

### Windows

For a service-backed fresh installation or upgrade, use the separate ordinary
Windows offline lab Setup EXE built from the same approved source and its
own checksums, following `ops/windows-installer/README.md`. The binary
candidate ZIP is not an installer; do not register its apphost over an
existing Setup-managed service. Preserve the existing approved service identity,
protected ProgramData, configuration and retained prior image path. The Setup
workflow tests upgrade and failed-health automatic rollback; an intentional
post-upgrade rollback is an independently approved change. Do not uninstall a
version that owns the live service before completing that change. Verify health,
authenticated session continuity, listener isolation and authorized routes after
installation, upgrade or rollback. Do not migrate DPAPI ciphertext between hosts.

### Linux

The candidate tar.gz contains the self-contained native apphost. Provision
the dedicated non-root gateway service account, root-controlled binary directory,
protected runtime/state directories, listener settings and wrapping credentials
according to the bundled platform documentation before service startup. The
bundled `ops/systemd/gatewaycore-yarp.service` is the existing framework-dependent
template: for this self-contained archive, use an independently reviewed
systemd drop-in (not an unreviewed in-place edit) with:

    [Service]
    ExecStart=
    ExecStart=/opt/gatewaycore-yarp/current/GatewayCoreYarp

Keep the template's existing non-root identity, environment, capability bounds
and private state controls. Point the root-owned current link at the extracted
version's **app** directory; never put mutable configuration, credentials or keys
in the release archive. Confirm native OS dependencies and apply the approved
service configuration on an isolated test host. Use `systemctl daemon-reload`,
`systemctl start gatewaycore-yarp` and `systemctl status gatewaycore-yarp`
only after preflight. Check configured management TLS, readiness, authentication
and routes; do not expose a new public listener as an installation shortcut.

For an upgrade, retain the prior immutable binary directory and record the old
link target, service definition, approved configuration revision, state/backup
inventory and compatible wrapping identities. Drain through the approved HA
workflow, stop the service, switch the root-controlled current link to the
new app directory using an atomic same-filesystem rename, start and verify
readiness and session continuity before admitting traffic. Rollback reverses the
binary link/service change after drain and stop, retaining compatible approved
state and credentials. If state/schema compatibility or authority is uncertain,
stop and use the reviewed recovery workflow; never overwrite a live key ring
or roll back a quorum revision. Recheck the original approved traffic and
security gates before resuming. The archive smoke proves extracted-app startup
and restart, not a customer-host service upgrade or network acceptance.

### VIP commissioning

Use only the platform tool in `ops/ha` and the bundled ADC instructions. Its
default plan mode does not apply configuration; provision distinct authorized
role credentials and verified policy digest separately. Do not copy fixtures or
enable a controller that has unresolved journal recovery. No commissioning
script is executed by extracting the archive. Physical site acceptance remains
#36.
