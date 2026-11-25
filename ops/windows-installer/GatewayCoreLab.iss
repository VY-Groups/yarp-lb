#ifndef SourceCommit
  #error SourceCommit is required
#endif
#ifndef PayloadDir
  #error PayloadDir is required
#endif
#ifndef SetupOut
  #error SetupOut is required
#endif
[Setup]
AppId=GatewayCore-Lab-{#SourceCommit}
AppName=GatewayCore Lab (ordinary test build)
AppVersion=0.1
DefaultDirName={autopf}\GatewayCore\Lab\{#SourceCommit}
DisableDirPage=yes
UsePreviousAppDir=no
DisableProgramGroupPage=yes
DefaultGroupName=GatewayCore Lab
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#SetupOut}
OutputBaseFilename=GatewayCore-Setup-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=GatewayCore Lab ({#SourceCommit})
UninstallDisplayIcon={app}\app\GatewayCoreYarp.exe
CloseApplications=no
RestartApplications=no
[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "Install-GatewayCoreLab.ps1"; DestDir: "{app}\ops\windows-installer"; Flags: ignoreversion
Source: "Remove-GatewayCoreLabService.ps1"; DestDir: "{app}\ops\windows-installer"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}\ops\windows-installer"; Flags: ignoreversion; AfterInstall: InstallAndVerifyService
[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked
[Icons]
Name: "{group}\GatewayCore Dashboard"; Filename: "http://127.0.0.1:8080/dashboard"
Name: "{commondesktop}\GatewayCore Dashboard"; Filename: "http://127.0.0.1:8080/dashboard"; Tasks: desktopicon
Name: "{group}\Installation and rollback instructions ({#SourceCommit})"; Filename: "{app}\ops\windows-installer\README.md"
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\ops\windows-installer\Remove-GatewayCoreLabService.ps1"" -InstallRoot ""{app}"""; RunOnceId: RemoveGatewayCoreService; Flags: runhidden waituntilterminated
[Run]
Filename: "http://127.0.0.1:8080/dashboard"; Flags: shellexec runasoriginaluser skipifsilent; Check: DashboardReady
[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Expected: String;
begin
  Result := '';
  Expected := ExpandConstant('{autopf}\GatewayCore\Lab\{#SourceCommit}');
  if CompareText(ExpandConstant('{app}'), Expected) <> 0 then begin
    Result := 'GatewayCore Lab only supports its fixed, versioned Program Files directory.';
    Exit;
  end;
  if DirExists(Expected) then
    Result := 'This exact build is already installed. Setup will not overwrite its files; use a newer build or uninstall this version first.';
end;

function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
  InstallationType: String;
begin
  Log('GatewayCore Lab InitializeSetup entered.');
  Result := False;
  if not IsWin64 then begin
    MsgBox('GatewayCore Lab requires 64-bit Windows.', mbError, MB_OK);
    Exit;
  end;
  if not IsAdmin then begin
    MsgBox('Run GatewayCore Lab Setup as a local administrator.', mbError, MB_OK);
    Exit;
  end;
  GetWindowsVersionEx(Version);
  if (Version.Build < 20348) or
     (not RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'InstallationType', InstallationType)) or
     (CompareText(InstallationType, 'Server') <> 0) then begin
    MsgBox('GatewayCore Lab Setup supports Windows Server 2022 or later only.', mbError, MB_OK);
    Exit;
  end;
  Log('GatewayCore Lab InitializeSetup prerequisites passed.');
  Result := True;
end;

function DashboardReady(): Boolean;
begin
  Result := FileExists(ExpandConstant('{app}\.dashboard-ready'));
end;

procedure GatewayCoreInstallerOutput(const S: String; const Error, FirstLine: Boolean);
begin
  if Error then
    Log('GatewayCore installer output capture failed: ' + S)
  else
    Log('GatewayCore installer: ' + S);
end;

procedure InstallAndVerifyService();
var
  ExitCode: Integer;
  Parameters: String;
begin
  Log('GatewayCore Lab performing service installation during the transactional file-install phase.');
  begin
    Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\ops\windows-installer\Install-GatewayCoreLab.ps1') +
      '" -InstallRoot "' + ExpandConstant('{app}') + '" -SourceCommit "{#SourceCommit}"';
    if not ExecAndLogOutput(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Parameters,
      ExpandConstant('{app}'), SW_SHOWNORMAL, ewWaitUntilTerminated, ExitCode, @GatewayCoreInstallerOutput) then
      RaiseException('Could not launch the transactional GatewayCore service installer.');
    Log(Format('GatewayCore Lab service installer exit code=%d.', [ExitCode]));
    if ExitCode <> 0 then
      RaiseException('GatewayCore service setup or health verification failed. The previous service and configuration were restored by the installer script. Setup must fail and remove the candidate files; inspect the retained ProgramData backup before retrying.');
  end;
end;
