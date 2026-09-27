; Arcaeon for Windows: Inno Setup script. STUB.
;
; NOT BUILT. NOT SIGNED. Nothing in this repository compiles it, and no step
; of the build or the tests runs Inno Setup. It is the shape a real installer
; would take, kept here so the choice is concrete:
;   - building it needs Inno Setup 6 on a Windows machine (ISCC.exe);
;   - shipping it needs a code-signing certificate, which is spend and is
;     the maintainer's call, not a build step;
;   - until both happen, the Windows door is install.ps1 on the site, a
;     readable script that prints its steps and runs them only with -Apply.
;
; What the installer would do: check for the py launcher, run
;   py -m pip install --user "arcaeon[mcp]"
; then
;   py -m arcaeon doctor
; for the current user only (no administrator rights). It carries no Python
; and no wheel of its own; pip fetches the package at install time on the
; user's machine.

#define AppName "Arcaeon"
#define AppVersion "0.0.0-stub"

[Setup]
AppId=arcaeon-user-install-stub
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Arcaeon
DefaultDirName={localappdata}\Arcaeon
PrivilegesRequired=lowest
DisableProgramGroupPage=yes
CreateAppDir=no
Uninstallable=no
OutputBaseFilename=arcaeon-setup-UNSIGNED-STUB
; No SignTool line on purpose: a signing certificate is spend, not a build step.

[Run]
Filename: "py"; Parameters: "-m pip install --user ""arcaeon[mcp]"""; Flags: runhidden waituntilterminated; StatusMsg: "Installing arcaeon for this user..."
Filename: "py"; Parameters: "-m arcaeon doctor"; Flags: waituntilterminated postinstall; Description: "Check the install (arcaeon doctor)"

[Code]
function InitializeSetup(): Boolean;
var
  Code: Integer;
begin
  Result := Exec('py', '--version', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  if not Result then
    MsgBox('The py launcher was not found. Install Python 3.10 or newer from python.org first.',
           mbError, MB_OK);
end;
