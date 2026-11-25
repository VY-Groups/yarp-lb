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
[Icons]
Name: "{group}\Installation and rollback instructions ({#SourceCommit})"; Filename: "{app}\README.md"
[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Expected: String;
begin
  Result := '';
  Expected := ExpandConstant('{autopf}\GatewayCore\Lab\{#SourceCommit}');
  if CompareText(ExpandConstant('{app}'), Expected) <> 0 then begin
    Result := 'The lab installer only supports its fixed versioned Program Files directory.';
    Exit;
  end;
  if DirExists(ExpandConstant('{commonappdata}\GatewayCoreYarp')) then begin
    Result := 'Existing GatewayCore state detected. Setup will not overwrite or change its permissions. Preserve the state and arrange a reviewed offline migration before installing this fresh lab build.';
    Exit;
  end;
  if DirExists(Expected) then
    Result := 'This version already exists. Do not overwrite binaries or state. Drain and stop its service before uninstalling.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ExitCode: Integer;
begin
  if CurStep = ssPostInstall then begin
    if not Exec(ExpandConstant('{app}\app\GatewayCoreYarp.exe'), '--windows-prepare-state',
      ExpandConstant('{app}\app'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      RaiseException('Could not launch secure state provisioning. Setup cannot complete.');
    if ExitCode <> 0 then
      RaiseException('Secure state provisioning failed. Existing state is not automatically modified. Contact the administrator for offline recovery.');
  end;
end;
