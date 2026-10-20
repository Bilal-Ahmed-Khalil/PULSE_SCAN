; Inno Setup Script for PulseScan
; ----------------------------------------
; 1. First build the .exe with build_exe.bat  (must use --uac-admin)
; 2. Install Inno Setup from https://jrsoftware.org/isdl.php
; 3. Open this file in Inno Setup Compiler
; 4. Click Build → Compile
; 5. The finished installer will be in the "Output" folder

#define MyAppName "PulseScan"
#define MyAppVersion "2.1"
#define MyAppPublisher "PulseScan"
#define MyAppExeName "PulseScan.exe"

[Setup]
AppId={{8F3A2B1C-9D4E-4F6A-B7C8-1E2F3A4B5C6D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=Output
OutputBaseFilename=PulseScan_Setup
SetupIconFile=
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyAppExeName}
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Start with Windows (launch when I log in)"; GroupDescription: "Startup:"; Flags: unchecked

[Dirs]
; Create reports folder with full access for Administrators / users
Name: "{app}\reports"; Permissions: users-modify
Name: "{app}\domain_groups"; Permissions: users-modify

[Files]
; Main executable – built with --uac-admin so it always requests elevation
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Optional: include a default domains file
Source: "domains.txt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{app}\reports"
Type: filesandordirs; Name: "{app}\domain_groups"
Type: files; Name: "{app}\config.json"
Type: files; Name: "{app}\scan_history.json"
