; Parental Control Auto Installer
!include "MUI2.nsh"
!include "FileFunc.nsh"

!define APP_NAME "Parental Control"
!define VERSION "1.0.0"
!define PUBLISHER "ParentalControl Inc."
!define INSTALLER_NAME "ParentalControlAutoInstaller.exe"

Name "${APP_NAME}"
OutFile "${INSTALLER_NAME}"
InstallDir "$PROGRAMFILES\${APP_NAME}"
RequestExecutionLevel admin

; Modern UI Configuration
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "MainApplication" SecMain
    SetOutPath "$INSTDIR"
    
    ; Copy application files
    File "core-service\core-service.exe"
    File /r "ui-admin\dist\*.*"
    File "LICENSE.txt"
    File "README.md"
    
    ; Install and start Windows service
    ExecWait '"$INSTDIR\core-service.exe" --install' $0
    ${If} $0 != 0
        MessageBox MB_OK "Failed to install Windows service. Error code: $0"
        Abort
    ${EndIf}
    
    ; Start the service
    ExecWait '"$INSTDIR\core-service.exe" --start' $0
    ${If} $0 != 0
        MessageBox MB_OK "Failed to start service. Error code: $0"
    ${EndIf}
    
    ; Wait for service to initialize and auto-configure system
    Sleep 3000
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\parental-control-ui.exe"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    CreateShortcut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\parental-control-ui.exe"
    
    ; Registry entries
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "Publisher" "${PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}" "DisplayVersion" "${VERSION}"
    
    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
    MessageBox MB_OK "${APP_NAME} has been installed successfully!$\n$\nThe system has been automatically configured for parental control.$\n$\nYou can now use the desktop shortcut to manage filtering rules."
    
SectionEnd

Section "Uninstall"
    ; Stop and remove service
    ExecWait 'sc stop "ParentalControlService"'
    ExecWait '"$INSTDIR\core-service.exe" --uninstall'
    
    ; Remove files
    RmDir /r "$INSTDIR"
    
    ; Remove shortcuts
    RmDir /r "$SMPROGRAMS\${APP_NAME}"
    Delete "$DESKTOP\${APP_NAME}.lnk"
    
    ; Remove registry entries
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"
    
SectionEnd
