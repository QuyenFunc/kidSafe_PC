!define APP_NAME "Parental Control"
!define COMP_NAME "ParentalControl Inc."
!define VERSION "1.0.0.0"
!define COPYRIGHT "Copyright © 2024 ${COMP_NAME}"
!define DESCRIPTION "Parental Control Desktop Application"
!define INSTALLER_NAME "ParentalControlSetup.exe"
!define MAIN_APP_EXE "parental-control-ui.exe"
!define SERVICE_EXE "core-service.exe"
!define INSTALL_TYPE "SetShellVarContext all"
!define REG_ROOT "HKLM"
!define REG_APP_PATH "Software\Microsoft\Windows\CurrentVersion\App Paths\${MAIN_APP_EXE}"
!define UNINSTALL_PATH "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP_NAME}"

VIProductVersion "${VERSION}"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "CompanyName" "${COMP_NAME}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileDescription" "${DESCRIPTION}"
VIAddVersionKey "FileVersion" "${VERSION}"

SetCompressor ZLIB
Name "${APP_NAME}"
Caption "${APP_NAME} Setup"
OutFile "${INSTALLER_NAME}"
BrandingText "${APP_NAME}"
XPStyle on
InstallDirRegKey "${REG_ROOT}" "${REG_APP_PATH}" ""
InstallDir "$PROGRAMFILES\${APP_NAME}"

!include "MUI.nsh"

!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section -MainProgram
${INSTALL_TYPE}
SetOverwrite ifnewer
SetOutPath "$INSTDIR"

; Copy application files
File "ui-admin\dist\${MAIN_APP_EXE}"
File "core-service\${SERVICE_EXE}"
File /r "ui-admin\dist\*.*"
File "config.json"
File "LICENSE.txt"

; Install and start Windows service
ExecWait '"$INSTDIR\${SERVICE_EXE}" --install'
ExecWait 'sc start "ParentalControlService"'

; Configure Windows to use local DNS
ExecWait 'netsh interface ip set dns "Local Area Connection" static 127.0.0.1'
ExecWait 'netsh interface ip add dns "Local Area Connection" 8.8.8.8 index=2'

; Disable DoH in browsers
${registry::Write} "HKLM\Software\Policies\Google\Chrome" "DnsOverHttpsMode" "off" "REG_SZ" $R0
${registry::Write} "HKLM\Software\Policies\Microsoft\Edge" "DnsOverHttpsMode" "off" "REG_SZ" $R0

SectionEnd

Section -Icons_Reg
SetOutPath "$INSTDIR"
WriteUninstaller "$INSTDIR\uninstall.exe"

; Start menu shortcuts
!insertmacro MUI_STARTMENU_WRITE_BEGIN Application
CreateDirectory "$SMPROGRAMS\${APP_NAME}"
CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" "$INSTDIR\${MAIN_APP_EXE}"
CreateShortCut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
!insertmacro MUI_STARTMENU_WRITE_END

; Registry entries
WriteRegStr ${REG_ROOT} "${REG_APP_PATH}" "" "$INSTDIR\${MAIN_APP_EXE}"
WriteRegStr ${REG_ROOT} "${UNINSTALL_PATH}" "DisplayName" "${APP_NAME}"
WriteRegStr ${REG_ROOT} "${UNINSTALL_PATH}" "UninstallString" "$INSTDIR\uninstall.exe"
WriteRegStr ${REG_ROOT} "${UNINSTALL_PATH}" "DisplayIcon" "$INSTDIR\${MAIN_APP_EXE}"
WriteRegStr ${REG_ROOT} "${UNINSTALL_PATH}" "DisplayVersion" "${VERSION}"
WriteRegStr ${REG_ROOT} "${UNINSTALL_PATH}" "Publisher" "${COMP_NAME}"

SectionEnd

Section Uninstall
${INSTALL_TYPE}

; Stop and remove service
ExecWait 'sc stop "ParentalControlService"'
ExecWait '"$INSTDIR\${SERVICE_EXE}" --uninstall'

; Restore DNS settings
ExecWait 'netsh interface ip set dns "Local Area Connection" dhcp'

; Remove registry policies
${registry::DeleteKey} "HKLM\Software\Policies\Google\Chrome\DnsOverHttpsMode" $R0
${registry::DeleteKey} "HKLM\Software\Policies\Microsoft\Edge\DnsOverHttpsMode" $R0

; Remove files and directories
RmDir /r "$INSTDIR"
RmDir /r "$SMPROGRAMS\${APP_NAME}"

; Remove registry entries
DeleteRegKey ${REG_ROOT} "${REG_APP_PATH}"
DeleteRegKey ${REG_ROOT} "${UNINSTALL_PATH}"

SectionEnd
