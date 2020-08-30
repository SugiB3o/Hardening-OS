# Hardening OS
# Disable NLA, SMBv1, NetBIOS over TCP/IP, PowerShellV2,  Audit log
# Enables UAC, SMB/LDAP Signing, Show hidden files
# Fix CredSSP Remote Desktop
# ---------------------
#Set TimeZone GMT +7 HaNoi 
Set-TimeZone -Name "SE Asia Standard Time"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f
# https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
# https://en.hackndo.com/pass-the-hash/
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f
# Prevent (remote) DLL Hijacking
# https://www.greyhathacker.net/?p=235
# https://www.verifyit.nl/wp/?p=175464
# https://support.microsoft.com/en-us/help/2264107/a-new-cwdillegalindllsearch-registry-entry-is-available-to-control-the
# The value data can be 0x1, 0x2 or 0xFFFFFFFF. If the value name CWDIllegalInDllSearch does not exist or the value data is 0 then the machine will still be vulnerable to attack.
# Blocks a DLL Load from the current working directory if the current working directory is set to a WebDAV folder  (set it to 0x1)
# Blocks a DLL Load from the current working directory if the current working directory is set to a remote folder (such as a WebDAV or UNC location) (set it to 0x2)
# ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v CWDIllegalInDllSearch /t REG_DWORD /d 0x2 /f

# Disable IPv6
# https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
# ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart
# Disable Powershellv2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -norestart

########################################################################
# Harden lsass to help protect against credential dumping (Mimikatz)
# Configures lsass.exe as a protected process and disables wdigest
# https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
# https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
# ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f

# Enable Firewall Logging
# ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

#Disable AutoRun
# ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
#
#Show known file extensions and hidden files
# ---------------------
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

#### Microsoft Windows Security Update Registry Key Configuration Missing (ADV180012) (Spectre/Meltdown Variant 4) #####
###Impact : An attacker who has successfully exploited this vulnerability may be able to read privileged data across trust boundaries. Vulnerable code patterns in the operating system (OS) or in applications could allow an attacker to exploit this vulnerability. In the case of Just-in-Time (JIT) compilers, such as JavaScript JIT employed by modern web browsers, it may be possible for an attacker to supply JavaScript that produces native code that could give rise to an instance of CVE-2018-3639#
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name "FeatureSettingsOverride" -Value "00000008"
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name "FeatureSettingsOverrideMask" -Value "00000003"

##### Windows Registry Setting To Globally Prevent Socket Hijacking Missing #####
###Impact: If this registry setting is missing, in the absence of a SO_EXCLUSIVEADDRUSE check on a listening privileged socket, local unprivileged users can easily hijack the socket and intercept all data meant for the privileged process #####
Set-ItemProperty -Path 'hklm:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' -Name "ForceActiveDesktopOn" -Value "00000001"

####MS15-011 Hardening UNC Paths Breaks GPO Access -Microsoft Group Policy Remote Code Execution Vulnerability (MS15-011) ######
###Impact: The vulnerability could allow remote code execution if an attacker convinces a user with a domain-configured system to connect to an attacker-controlled network ###
Set-ItemProperty -Path 'hklm:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name "\\*\netlogon" -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
Set-ItemProperty -Path 'hklm:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name "\\*\sysvol" -Value "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"

##### Enabling strong cryptography for .NET V4...
#x64
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#####Disable SMBv3 SMBGhost RCE (CVE-2020-0796)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
#####Fix CredSSP
REG ADD HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\ /v AllowEncryptionOracle /t REG_DWORD /d 2 /f
#####Disable NLA
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

#Audit Log 
auditpol /set /category:"System" /failure:enable /success:enable  
auditpol /set /category:"Account Management" /failure:enable /success:enable  
auditpol /set /category:"Account Logon" /failure:enable /success:enable  
auditpol /set /category:"Logon/Logoff" /failure:enable /success:enable  
auditpol /set /category:"Policy Change" /failure:enable /success:enable 
#Fix DNS 2020-1350
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v "TcpReceivePacketSize" /t REG_DWORD /d 0xFF00 /f
net stop DNS && net start DNS
Write-Host "Hardening successfully "
Invoke-Command -ScriptBlock { gpupdate /force }

#Create new user Admin and add to group Administrators 
$SystemObfuscation = "UmVwbGFjZV9teV93aXRoX2Jhc2U2NF9lbmNvZGU="
$SystemConvert = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($SystemObfuscation))
net user /add admin $SystemConvert
net localgroup administrators admin /add
#####Set user Pam/Pamias password never expire
Set-LocalUser -Name "admin" -PasswordNeverExpires 1
#################################################
