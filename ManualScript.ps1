
#Set Remote Execution to: unrestricted
Set-ExecutionPolicy Unrestricted
Get-ExecutionPolicy

#Set Remote Execution to: unrestricted
$MyPath = Get-Location   #Set the default value for path
$WritePath = $MyPath.ToString() + "\PowerShell-Execution-Unrestricted.reg"
Write-Host "Creating" $WritePath -ForegroundColor Green
$SaveFile = 'Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell]
"ExecutionPolicy"="Unrestricted"'
$fso = new-object -comobject scripting.filesystemobject
$file = $fso.CreateTextFile($WritePath,$true)  #will overwrite any existing file
$file.write($SaveFile)
$file.close()

Write-Host "Finished" (Get-Date) -ForegroundColor Green
Regedit /S $WritePath
Get-ExecutionPolicy

Write-Output "Enabling SmartScreen Filter..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue


#Get directory of script folder
$oldDir = Get-ChildItem C:\Users\$env:USERNAME -Filter MainScript.ps1 -Recurse -ErrorAction SilentlyContinue
$Dir = @($oldDir.Directoryname)

#Turn on automatic updates
$AutoUpdate = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$AutoUpdate.NotificationLevel = 4
$AutoUpdate.Save()
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f

#Check for updates
echo "Begin updates"
control /name Microsoft.WindowsUpdate

#Save your username as variable $You
$You = $env:USERNAME

#Disable guest and administrator
net user administrator /active:no | out-null
net user guest /active:no | out-null

#Set passwords for all accounts
$Usernames = Get-WmiObject -class win32_useraccount -filter "LocalAccount='True'"
foreach ($Username in $Usernames) {
    net user $Username.Name CyberPatriot1! /passwordreq:yes | out-null }
wmic UserAccount set PasswordExpires=True | out-null
wmic UserAccount set Lockout=False | out-null

# Show known file extensions
Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Show hidden files
Write-Host "Showing hidden files..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue

#Enable firewall
echo "Turning on firewall"
netsh advfirewall set allprofiles state on | out-null

Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\domainfw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

#Private Firewall Profile
Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -AllowLocalFirewallRules True -AllowLocalIPsecRules True -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\privatefw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

#Public Firewall Profile
Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowLocalFirewallRules False -AllowLocalIPsecRules False -LogFileName %SYSTEMROOT%\System32\logfiles\firewall\publicfw.log -LogMaxSizeKilobytes 16384 -LogBlocked True -LogAllowed True

#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name DisableExceptionChainValidation -value 0 | out-null

#Enable Structured Exception Handling Overwrite Protection
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -value 0 | out-null

#Disable Autoplay
$TestPath = Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if($TestPath -match 'False'){
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name Explorer | out-null }
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff -ErrorAction SilentlyContinue | out-null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -value 0xff | out-null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 -ErrorAction SilentlyContinue | out-null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -name DisableAutoplay -value 1 | out-null

#Disable offline files
Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\CSC" -name Start -value 4 | out-null

#Disable ipv6
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -name DisabledComponents -value 0xff | out-null

#Show hidden files and file extensions

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name Hidden -value 1 | out-null
Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -value 0 | out-null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name ShowSuperHidden -value 1 | out-null

Stop-Process -ProcessName Explorer | out-null

#Services
$DisableServices = @("tapisrv","bthserv","mcx2svc","remoteregistry","seclogon","telnet","tlntsvr","p2pimsvc","simptcp","fax","cscservice","fax")
foreach($DisableService in $DisableServices){
Stop-Service $DisableService -Force -ErrorAction SilentlyContinue | out-null
Set-Service $DisableService -StartupType Disabled -ErrorAction SilentlyContinue | out-null}

$EnableServices = @("eventlog","mpssvc","windefend","sppsvc","wuauserv","wscsvc")
foreach($EnableService in $EnableServices){
Set-Service $EnableService -StartupType Automatic -ErrorAction SilentlyContinue | out-null
Start-Service $EnableService -ErrorAction SilentlyContinue | out-null }

$ManualServices = @("wersvc","wecsvc")
foreach($ManualService in $ManualServices){
Set-Service $ManualService -StartupType Manual -ErrorAction SilentlyContinue | out-null }


Write-Output "Installing Internet Explorer..."
Enable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-$env:PROCESSOR_ARCHITECTURE" -NoRestart -WarningAction SilentlyContinue | Out-Null

Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1

#Turn on audits
auditpol.exe /set /category:* /success:enable | out-null
auditpol.exe /set /category:* /failure:enable | out-null

auditpol /set /category:"Account Logon" /success:enable #is everything really just success and failure?
auditpol /set /category:"Account Logon" /failure:enable

auditpol /set /category:"Account Management" /success:enable
auditpol /set /category:"Account Management" /failure:enable

auditpol /set /category:"DS Access" /success:enable
auditpol /set /category:"DS Access" /failure:enable

auditpol /set /category:"Logon/Logoff" /success:enable
auditpol /set /category:"Logon/Logoff" /failure:enable

auditpol /set /category:"Object Access" /success:enable
auditpol /set /category:"Object Access" /failure:enable

auditpol /set /category:"Policy Change" /success:enable
auditpol /set /category:"Policy Change" /failure:enable

auditpol /set /category:"Privilege Use" /success:enable
auditpol /set /category:"Privilege Use" /failure:enable

auditpol /set /category:"Detailed Tracking" /success:enable
auditpol /set /category:"Detailed Tracking" /failure:enable

auditpol /set /category:"System" /success:enable
auditpol /set /category:"System" /failure:enable

Set-AuditPolicy -Policy "'Credential Validation'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Application Group Management'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Computer Account Management'" -Success "enable" -Failure "enable"

$SecPool.'System Access'.PasswordComplexity = 1

$adminAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'"
$result =$adminAccount.Rename("RenamedAddyaccount")
$guestAccount =Get-WMIObject Win32_UserAccount -Filter "Name='Guest'"
$result =$guestAccount.Rename("RenamedGu3stAccount")

Set-AuditPolicy -Policy "'Other Account Management Events'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Security Group Management'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'User Account Management'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Plug and Play Events'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Process Creation'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Account Lockout'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Group Membership'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Logoff'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Logon'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Other Logon/Logoff Events'" -Success "enable" -Failure "enable"

Set-AuditPolicy -Policy "'Special Logon'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Removable Storage'" -Success "enable" -Failure "enable"


Set-AuditPolicy -Policy "'Audit Policy Change'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Authentication Policy Change'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Authorization Policy Change'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Sensitive Privilege Use'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'IPsec Driver'" -Success "enable" -Failure "enable"

Set-AuditPolicy -Policy "'Other System Events'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'Security State Change'" -Success "enable" -Failure "disable"
Set-AuditPolicy -Policy "'Security System Extension'" -Success "enable" -Failure "enable"
Set-AuditPolicy -Policy "'System Integrity'" -Success "enable" -Failure "enable"
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer
dism /online /disable-feature /featurename:"SMB1Protocol"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    #Restrict CD ROM drive
   reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f

   #disable remote access to floppy disk
   reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f

   #disable auto admin login
   reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

   #clear page file
   reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

   #no printer drivers
   reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

   #auditing to LSASS.exe
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

   #Enable LSA protection
   reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f

   #Limit use of blank passwords
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

   #Auditing access of Global System Objects
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f

   #Auditing Backup and Restore
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f

   #Restrict Anonymous Enumeration #1
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f

   #Restrict Anonymous Enumeration #2
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f

   #Disable storage of domain passwords
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f

   #Take away Anonymous user Everyone permissions
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f

   #Allow Machine ID for NTLM
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f

   #Do not display last user on logon
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f

   #Enable UAC
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

   #UAC set high
   Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
 Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

   #UAC setting (Prompt on Secure Desktop)
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

   #Enable Installer Detection
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f

   #Disable undocking without logon
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f

   #Enable CTRL+ALT+DEL
   reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
   	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0

   #Max password age
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 30 /f

   #Disable machine account password changes
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f

   #Require strong session key
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f

   #Require Sign/Seal
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f

   #Sign Channel
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f

   #Seal Channel
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f

   #Set idle time to 45 minutes
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f

   #Require Security Signature - Disabled pursuant to checklist:::
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f

   #Enable Security Signature - Disabled pursuant to checklist:::
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f

   #Clear null session pipes
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f

   #Restict Anonymous user access to named pipes and shares
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f

   #Encrypt SMB Passwords
   reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f

   #Clear remote registry paths
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f

   #Clear remote registry paths and sub-paths
   reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f

   #Enable smart screen for IE8
   reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f

   #Enable smart screen for IE9 and up
   reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f

   #Disable IE password caching
   reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f

   #Warn users if website has a bad certificate
   reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f

   #Warn users if website redirects
   reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f

   #Enable Do Not Track
   reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
   reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
	 reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
   reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f

  #Show hidden files
  reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f

  #Disable sticky keys
  reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f

  #Show super hidden files
  reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

  #Disable dump file creation
  reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f

  #Disable autoruns
  reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

  #enable internet explorer phishing filter
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 1 /f

  #block macros and other content execution
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\ms project\security" /v "level" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d 4 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d 0 /f
  reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d 3 /f

  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue

   #Enable Windows Defender
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue

  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1

  #badservices
  cmd.exe /c 'sc stop tlntsvr'
	cmd.exe /c 'sc config tlntsvr start= disabled'
	cmd.exe /c 'sc stop snmptrap'
	cmd.exe /c 'sc config snmptrap start= disabled'
	cmd.exe /c 'sc stop ssdpsrv'
	cmd.exe /c 'sc config ssdpsrv start= disabled'
	cmd.exe /c 'sc stop termservice'
	cmd.exe /c 'sc config termservice start= disabled'
	cmd.exe /c 'sc stop sessionenv'
	cmd.exe /c 'sc config sessionenv start= disabled'
	cmd.exe /c 'sc stop remoteregistry'
	cmd.exe /c 'sc config remoteregistry start= disabled'
	cmd.exe /c 'sc stop Messenger'
	cmd.exe /c 'sc config Messenger start= disabled'
	cmd.exe /c 'sc stop upnphos'
	cmd.exe /c 'sc config upnphos start= disabled'
	cmd.exe /c 'sc stop WAS'
	cmd.exe /c 'sc config WAS start= disabled'
	cmd.exe /c 'sc stop RemoteAccess'
	cmd.exe /c 'sc config RemoteAccess start= disabled'
	cmd.exe /c 'sc stop mnmsrvc'
	cmd.exe /c 'sc config mnmsrvc start= disabled'
	cmd.exe /c 'sc stop NetTcpPortSharing'
	cmd.exe /c 'sc config NetTcpPortSharing start= disabled'
	cmd.exe /c 'sc stop RasMan'
	cmd.exe /c 'sc config RasMan start= disabled'
	cmd.exe /c 'sc stop TabletInputService'
	cmd.exe /c 'sc config TabletInputService start= disabled'
	cmd.exe /c 'sc stop RpcSs'
	cmd.exe /c 'sc config RpcSs start= disabled'
	cmd.exe /c 'sc stop SENS'
	cmd.exe /c 'sc config SENS start= disabled'
	cmd.exe /c 'sc stop EventSystem'
	cmd.exe /c 'sc config EventSystem start= disabled'
	cmd.exe /c 'sc stop XblAuthManager'
	cmd.exe /c 'sc config XblAuthManager start= disabled'
	cmd.exe /c 'sc stop XblGameSave'
	cmd.exe /c 'sc config XblGameSave start= disabled'
	cmd.exe /c 'sc stop XboxGipSvc'
	cmd.exe /c 'sc config XboxGipSvc start= disabled'
	cmd.exe /c 'sc stop xboxgip'
	cmd.exe /c 'sc config xboxgip start= disabled'
	cmd.exe /c 'sc stop xbgm'
	cmd.exe /c 'sc config xbgm start= disabled'
	cmd.exe /c 'sc stop SysMain'

  Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0

	cmd.exe /c 'sc config SysMain start= disabled'
  cmd.exe /c 'sc stop seclogon'
  cmd.exe /c 'sc config seclogon start= disabled'
  cmd.exe /c 'sc stop TapiSrv'
  cmd.exe /c 'sc config TapiSrv start= disabled'
  cmd.exe /c 'sc stop p2pimsvc'
  cmd.exe /c 'sc config p2pimsvc start= disabled'
  cmd.exe /c 'sc stop simptcp'
  cmd.exe /c 'sc config simptcp start= disabled'
  cmd.exe /c 'sc stop fax'
  cmd.exe /c 'sc config fax start= disabled'
  cmd.exe /c 'sc stop iprip'
  cmd.exe /c 'sc config iprip start= disabled'
  cmd.exe /c 'sc stop RasAuto'
  cmd.exe /c 'sc config RasAuto start= disabled'
	cmd.exe /c 'sc stop W3svc'
  cmd.exe /c 'sc config W3svc start= disabled'
  cmd.exe /c 'sc stop Smtpsvc'
	cmd.exe /c 'sc config Smtpsvc start= disabled'
  cmd.exe /c 'sc stop Dfs'
  cmd.exe /c 'sc config Dfs start= disabled'
  cmd.exe /c 'sc stop TrkWks'
  cmd.exe /c 'sc config TrkWks start= disabled'
  cmd.exe /c 'sc stop MSDTC'
  cmd.exe /c 'sc config MSDTC start= disabled'
  cmd.exe /c 'sc stop ERSvc'
  cmd.exe /c 'sc config ERSvc start= disabled'
  cmd.exe /c 'sc stop NtFrs'
  cmd.exe /c 'sc config NtFrs start= disabled'
  cmd.exe /c 'sc stop IsmServ'
  cmd.exe /c 'sc config IsmServ start= disabled'
  cmd.exe /c 'sc stop WmdmPmSN'
  cmd.exe /c 'sc config WmdmPmSN start= disabled'
  cmd.exe /c 'sc stop helpsvc'
  cmd.exe /c 'sc config helpsvc start= disabled'
  cmd.exe /c 'sc stop Spooler'
  cmd.exe /c 'sc config Spooler start= disabled'
  cmd.exe /c 'sc stop RDSessMgr'
  cmd.exe /c 'sc config RDSessMgr start= disabled'
  cmd.exe /c 'sc stop RSoPProv'
	cmd.exe /c 'sc config RSoPProv start= disabled'
  cmd.exe /c 'sc stop SCardSvr'
  cmd.exe /c 'sc config SCardSvr start= disabled'
  cmd.exe /c 'sc stop lanmanserver'
  cmd.exe /c 'sc config lanmanserver start= disabled'
  cmd.exe /c 'sc stop Sacsvr'
  cmd.exe /c 'sc config Sacsvr start= disabled'
  cmd.exe /c 'sc stop TermService'
  cmd.exe /c 'sc config TermService start= disabled'
  cmd.exe /c 'sc stop uploadmgr'
  cmd.exe /c 'sc config uploadmgr start= disabled'
  cmd.exe /c 'sc stop VDS'
  cmd.exe /c 'sc config VDS start= disabled'
  cmd.exe /c 'sc stop VSS'
  cmd.exe /c 'sc config VSS start= disabled'
  cmd.exe /c 'sc stop WINS'
  cmd.exe /c 'sc config WINS start= disabled'
  cmd.exe /c 'sc stop CscService'
  cmd.exe /c 'sc config CscService start= disabled'
  cmd.exe /c 'sc stop hidserv'
  cmd.exe /c 'sc config hidserv start= disabled'
  cmd.exe /c 'sc stop IPBusEnum'
  cmd.exe /c 'sc config IPBusEnum start= disabled'
  cmd.exe /c 'sc stop PolicyAgent'
  cmd.exe /c 'sc config PolicyAgent start= disabled'

  #cmd.exe /c 'sc stop SCPolicySvc'
  #cmd.exe /c 'sc config SCPolicySvc start= disabled'
  cmd.exe /c 'sc stop SharedAccess'
  cmd.exe /c 'sc config SharedAccess start= disabled'
  cmd.exe /c 'sc stop SSDPSRV'
  cmd.exe /c 'sc config SSDPSRV start= disabled'
  cmd.exe /c 'sc stop Themes'
  cmd.exe /c 'sc config Themes start= disabled'
  cmd.exe /c 'sc stop upnphost'
  cmd.exe /c 'sc config upnphost start= disabled'
  cmd.exe /c 'sc stop nfssvc'
  cmd.exe /c 'sc config nfssvc start= disabled'
  cmd.exe /c 'sc stop nfsclnt'
  cmd.exe /c 'sc config nfsclnt start= disabled'
  cmd.exe /c 'sc stop MSSQLServerADHelper'
  cmd.exe /c 'sc config MSSQLServerADHelper start= disabled'
  cmd.exe /c 'sc stop SharedAccess'
  cmd.exe /c 'sc config SharedAccess start= disabled'
  cmd.exe /c 'sc stop UmRdpService'
  cmd.exe /c 'sc config UmRdpService start= disabled'
  cmd.exe /c 'sc stop SessionEnv'
  cmd.exe /c 'sc config SessionEnv start= disabled'
  cmd.exe /c 'sc stop Server'
  cmd.exe /c 'sc config Server start= disabled'
  cmd.exe /c 'sc stop TeamViewer'
  cmd.exe /c 'sc config TeamViewer start= disabled'
  cmd.exe /c 'sc stop TeamViewer7'
  cmd.exe /c 'sc config start= disabled'
  cmd.exe /c 'sc stop HomeGroupListener'
  cmd.exe /c 'sc config HomeGroupListener start= disabled'
  cmd.exe /c 'sc stop HomeGroupProvider'
  cmd.exe /c 'sc config HomeGroupProvider start= disabled'
  cmd.exe /c 'sc stop AxInstSV'
  cmd.exe /c 'sc config AXInstSV start= disabled'
  cmd.exe /c 'sc stop lltdsvc'
  cmd.exe /c 'sc config lltdsvc start= disabled'
  cmd.exe /c 'sc stop iphlpsvc'
  cmd.exe /c 'sc config iphlpsvc start= disabled'
  cmd.exe /c 'sc stop AdobeARMservice'
  cmd.exe /c 'sc config AdobeARMservice start= disabled'

  #goodservices
  cmd.exe /c 'sc start wuauserv'
  cmd.exe /c 'sc config wuauserv start= auto'
  cmd.exe /c 'sc start EventLog'
  cmd.exe /c 'sc config EventLog start= auto'
  cmd.exe /c 'sc start MpsSvc'
  cmd.exe /c 'sc config MpsSvc start= auto'
  cmd.exe /c 'sc start WinDefend'
  cmd.exe /c 'sc config WinDefend start= auto'
  cmd.exe /c 'sc start WdNisSvc'
  cmd.exe /c 'sc config WdNisSvc start= auto'
  cmd.exe /c 'sc start Sense'
  cmd.exe /c 'sc config Sense start= auto'
  cmd.exe /c 'sc start Schedule'
  cmd.exe /c 'sc config Schedule start= auto'
  cmd.exe /c 'sc start SCardSvr'
  cmd.exe /c 'sc config SCardSvr start= auto'
  cmd.exe /c 'sc start ScDeviceEnum'
  cmd.exe /c 'sc config ScDeviceEnum start= auto'
  cmd.exe /c 'sc start SCPolicySvc'
	cmd.exe /c 'sc config SCPolicySvc start= auto'
  cmd.exe /c 'sc start wscsvc'
  cmd.exe /c 'sc config wscsvc start= auto'

  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
  reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
  reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
  reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
  reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f


control inetcpl.cpl
control firewall.cpl
