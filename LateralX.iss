; LateralX — Windows Installer Script
; Requires: Inno Setup 6  (https://jrsoftware.org/isinfo.php)
; Compile:  iscc LateralX.iss
; Output:   installer\LateralX-Setup.exe

#define AppName      "LateralX"
#define AppVersion   "1.0.0"
#define AppPublisher "LateralX"
#define AppDesc      "Forensic Intelligence Platform"

; ── Installer metadata ───────────────────────────────────────────────────────
[Setup]
AppId={{B4A2F7E8-3C1D-4F5A-9B8E-7D6C5A4B3F2E}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppComments={#AppDesc}

; User-mode install (no UAC prompt) — same approach as VS Code User Installer
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes

; Branding
SetupIconFile=lateralx.ico
UninstallDisplayIcon={app}\lateralx.ico
WizardStyle=modern
WizardSmallImageFile=lateralx.ico

; Output
OutputDir=installer
OutputBaseFilename=LateralX-Setup
Compression=lzma2/ultra64
SolidCompression=yes

; ── Languages ────────────────────────────────────────────────────────────────
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ── Optional tasks ───────────────────────────────────────────────────────────
[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: checked

; ── Files to install ─────────────────────────────────────────────────────────
[Files]
; Python backend
Source: "backend\*";         DestDir: "{app}\backend";        Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__,*.pyc,*.pyo"
; Built React frontend — no Node.js required on the target machine
Source: "frontend\dist\*";   DestDir: "{app}\frontend\dist";  Flags: ignoreversion recursesubdirs createallsubdirs
; App entry point and launchers
Source: "main.py";           DestDir: "{app}"; Flags: ignoreversion
Source: "requirements.txt";  DestDir: "{app}"; Flags: ignoreversion
Source: "launcher.pyw";      DestDir: "{app}"; Flags: ignoreversion
Source: "start.vbs";         DestDir: "{app}"; Flags: ignoreversion
Source: "stop.bat";          DestDir: "{app}"; Flags: ignoreversion
Source: "lateralx.ico";      DestDir: "{app}"; Flags: ignoreversion
; Pre-loaded demo forensic database (BlackVault ransomware scenario)
Source: "forensic.db";       DestDir: "{app}"; Flags: ignoreversion

; ── Shortcuts ────────────────────────────────────────────────────────────────
[Icons]
; Start Menu
Name: "{group}\{#AppName}";             Filename: "{sys}\wscript.exe"; Parameters: """{app}\start.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\lateralx.ico"; Comment: "Launch {#AppName} — {#AppDesc}"
Name: "{group}\Stop {#AppName}";        Filename: "{app}\stop.bat";   WorkingDir: "{app}"; Comment: "Stop the {#AppName} server"
Name: "{group}\Uninstall {#AppName}";   Filename: "{uninstallexe}"
; Desktop (optional)
Name: "{autodesktop}\{#AppName}";       Filename: "{sys}\wscript.exe"; Parameters: """{app}\start.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\lateralx.ico"; Tasks: desktopicon; Comment: "Launch {#AppName} — {#AppDesc}"

; ── Post-install actions ─────────────────────────────────────────────────────
[Run]
; Install Python packages silently (requires internet, ~1 minute)
Filename: "{cmd}"; Parameters: "/c python -m pip install -r ""{app}\requirements.txt"" --quiet --disable-pip-version-check"; WorkingDir: "{app}"; StatusMsg: "Installing Python packages — this takes about a minute..."; Flags: runhidden waituntilterminated

; Optional: launch immediately after install
Filename: "{sys}\wscript.exe"; Parameters: """{app}\start.vbs"""; WorkingDir: "{app}"; Description: "Launch {#AppName} now"; Flags: nowait postinstall skipifsilent

; ── Cleanup on uninstall ─────────────────────────────────────────────────────
[UninstallDelete]
Type: files; Name: "{app}\lateralx.log"

; ── Pre-install Python check ─────────────────────────────────────────────────
[Code]
var
  PythonOK: Boolean;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  PythonOK := Exec(ExpandConstant('{cmd}'), '/c python --version', '',
                   SW_HIDE, ewWaitUntilTerminated, ResultCode)
              and (ResultCode = 0);

  if not PythonOK then
  begin
    MsgBox(
      'Python 3.11 or later is required to run ' + ExpandConstant('{#AppName}') + '.' + #13#10 + #13#10 +
      'Please install Python from python.org first.' + #13#10 +
      'Make sure to check "Add Python to PATH" during installation.' + #13#10 + #13#10 +
      'Then re-run this installer.',
      mbError, MB_OK
    );
    Result := False;
  end else
    Result := True;
end;
