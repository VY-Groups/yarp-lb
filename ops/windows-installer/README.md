# GatewayCore offline Windows lab installer

This is an **ordinary, unsigned lab installer**, not a commercial signed package or a production certification. It supports x64 Windows Server 2022 and later and is self-contained; it does not download a runtime. Setup does not open firewall ports or enable a public listener.

## Fresh install and upgrade

1. Obtain `GatewayCore-Setup-win-x64.exe`, `SHA256SUMS.txt`, and `SOURCE_COMMIT.txt` from a successful exact-source **Windows offline lab Setup EXE** workflow run. Do not use an unreviewed pull-request artifact for customer testing.
2. Verify the EXE with `Get-FileHash -Algorithm SHA256`, then run Setup elevated on an isolated test server.
3. Setup checks the OS, architecture, administrator rights, disk space, versioned install path, service ownership, and reparse points before changing service or state.
4. Files are installed side-by-side under `Program Files\GatewayCore\Lab\<full-source-SHA>`. The service runs as `NT AUTHORITY\LocalService` with automatic startup. Its binary directory is read-only to the service account.
5. Runtime configuration and Data Protection state live under `%ProgramData%\GatewayCoreYarp\ControlPlane`. The service preserves existing HTTP loopback endpoints on port `8080` when safe. If only `http://[::1]:8080` exists, Setup adds a separate IPv4-only `127.0.0.1:8080` management listener for the health gate and dashboard; it refuses a conflicting non-loopback listener. Routes and other settings are preserved during supported configuration migration. Setup does not change firewall rules.
6. Before migration, Setup creates a local, access-controlled backup of the existing state and runtime configuration and verifies file hashes. Migration updates the configuration schema marker while preserving existing JSON settings. DPAPI key contents and administrator data are not rewritten. Legacy branded identity stores remain blocked by the application’s existing migration guard.
7. Setup switches the service to the new version, starts it, and waits up to 90 seconds for `GET http://127.0.0.1:8080/gateway/health` to return a healthy response. Only after that check does the interactive installer automatically open the dashboard as the original, non-elevated user. Silent install does not launch a browser.
8. If migration, service startup, or health validation fails, Setup returns an explicit nonzero process exit code. After Inno finalizes its uninstall log, Setup invokes the candidate uninstaller only if SCM confirms the failed version does not own the service. The installer retains files for operator recovery if service ownership cannot be excluded; it never reports success in that case. The service installer stops the candidate and restores the prior runtime configuration, service executable, service identity, startup mode, environment, recovery settings, and state ACLs. It retains the protected backup for investigation. On a failed fresh install, state is retained for recovery; Setup never deletes it to force a retry.

## Rollback and uninstall

Successful upgrades retain the previous versioned binary directory and a protected state/configuration backup. To roll back, stop the service and use an administrator session to restore the prior service image path from the retained backup/runbook; the installer performs automatic rollback only when the new service fails its immediate health check. Do not copy Windows DPAPI state to another host.

Uninstall stops and removes the GatewayCore service only when its image path points to the version being uninstalled. It removes that version’s installer-owned files and keeps `%ProgramData%` state and backups. Uninstalling an older version cannot stop a service already switched to a newer version.

## Acceptance boundary

The `Windows offline lab Setup EXE` GitHub Actions workflow builds and executes the actual Setup EXE on disposable Windows Server 2022 runners. It tests fresh install, a real service-backed upgrade with existing administrator/DPAPI state, configuration backup/migration, a deliberately failed health gate with nonzero Setup exit, failed-candidate cleanup and automatic rollback, IPv6-only loopback upgrade, same-version overwrite refusal, dashboard/readiness gating, and uninstall with state retention. These Windows-hosted checks do not establish physical Windows Server, certificate, capacity, production signing, external backup custody, or #36 HA acceptance. Production remains NO-GO until the separate release gates pass.
