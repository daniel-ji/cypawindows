#SET GROUP POLICY FIRST!!!


#NOTE: CHECK (DEFAULT) GROUPS STILL
#Script to configure Users, create an users.txt file for local users, admins.txt file for local admins
#Disables & Configures Admin & Guest & Default Account
#Disables all unlisted users
#Enables all listed users
#Removes all users that aren't supposed to be admins
#enable change password at next logon
#disable password never expires
#lists all groups ... other than Administrators and Users

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#all accounts
Set-LocalUser -Name (Get-LocalUser *) -PasswordNeverExpires $false -UserMayChangePassword $true
Get-LocalUser * | Disable-LocalUser
Remove-LocalGroupMember -Group "Administrators" -Member (Get-LocalUser *)

#authorized users
$Password = convertto-securestring "Cyberpatriot2020" -asplaintext -force
foreach($line in Get-Content C:\2020hardening\users\users.txt) {
    Get-LocalUser $line | Enable-LocalUser
    Get-LocalUser -Name $line | Set-LocalUser -Password $Password
    Set-LocalUser -Name $line -PasswordNeverExpires $false -UserMayChangePassword $true
}

#authorized admin
foreach($line in Get-Content C:\2020hardening\users\admins.txt) {
    Get-LocalUser $line | Enable-LocalUser
    Get-LocalUser -Name $line | Set-LocalUser -Password $Password
    Set-LocalUser -Name $line -PasswordNeverExpires $false -UserMayChangePassword $true
    Add-LocalGroupMember -Group "Administrators" -Member $line
}

#all accounts
foreach($user in Get-LocalUser *) {
    net user $user /logonpasswordchg:yes
}

#default accounts
Set-LocalUser -Name "tseug" -PasswordNeverExpires $true -UserMayChangePassword $false
Get-LocalUser Guest | Disable-LocalUser 
Set-LocalUser -Name "nimda" -PasswordNeverExpires $true -UserMayChangePassword $false
Get-LocalUser Administrator | Disable-LocalUser
Set-LocalUser -Name "DefaultAccount" -PasswordNeverExpires $true -UserMayChangePassword $false
Get-LocalUser DefaultAccount | Disable-LocalUser

foreach($group in Get-LocalGroup -Name *) {
    Write-Output "`n"
    Write-Output $group | Select-Object name
    Get-LocalGroupMember -Group $group | Select-Object name
}

pause

function Manage-Functionality {
    param (
        [string] $Functionality,
        [string[]] $RelatedServices,
        [string[]] $RelatedFeatures
    )

    $Prompt = Read-Host "${Functionality}? [A/M/D/n]"

    if ($Prompt -eq "D") {
        foreach ($Service in $RelatedServices) {
            Write-Output "Trying to disable $Service"
            Get-Service -Name $Service | Set-Service -StartupType Disabled
            Stop-Service -Force $Service
        }
        foreach ($Feature in $RelatedFeatures) {
            Write-Output "Trying to uninstall $Feature"
            Disable-WindowsOptionalFeature -FeatureName $Feature -Online
        }
    } elseif ($Prompt -eq "A") {
        foreach ($Service in $RelatedServices) {
            Write-Output "Trying to automatic $Service"
            Get-Service -Name $Service | Set-Service -StartupType Automatic
            Start-Service $Service
        }
        foreach ($Feature in $RelatedFeatures) {
            Write-Output "Trying to enable $Feature"
            Enable-WindowsOptionalFeature -FeatureName $Feature -Online
        }
    } elseif ($Prompt -eq "M") {
        foreach ($Service in $RelatedServices) {
            Write-Output "Trying to manual $Service"
            Get-Service -Name $Service | Set-Service -StartupType Manual
            Start-Service $Service
        }
        foreach ($Feature in $RelatedFeatures) {
            Write-Output "Trying to enable $Feature"
            Enable-WindowsOptionalFeature -FeatureName $Feature -Online
        }
    }
}

Manage-Functionality "Fax" @() @("Fax")
Manage-Functionality "Print" @("Spooler") @("Printing-PrintToPDFServices-Features",  "Printing-XPSServices-Features", "Printing-Foundation-Features", "Printing-Foundation-InternetPrinting-Client", "Printing-Foundation-LPDPrintService", "Printing-Foundation-LPRPortMonitor")
Manage-Functionality "RDP" @("SessionEnv", "UmRdpService", "TermService")

#Services
$stopservices = @(
    "telnet"
    "Netlogon"
    "AppVClient"
    "AxInstSV"
    "BthHFSrv"
    "bthserv"
    "CDPUserSvc"
    "CscService"
    "dmwappushservice"
    "dot3svc"
    "EapHost"
    "Fax"
    "fdPHost"
    "FDResPub"
    "FTPSVC"
    "icssvc"
    "IISADMIN"
    "InstallService"
    "iphlpsvc"
    "iprip"
    "IpxlatCfgSvc"
    "irmon"
    "lfsvc"
    "lmhosts"
    "LxssManager"
    "MapsBroker"
    "MessagingService"
    "MSiSCSI"
    "NcaSvc"
    "NcbService"
    "NcdAutoSetup"
    "NetTcpPortSharing"
    "OneSyncSvc"
    "p2pimsvc"
    "p2psvc"
    "PcaSvc"
    "PeerDistSvc"
    "PhoneSvc"
    "PimIndexMaintenanceSvc"
    "PNRPAutoReg"
    "PNRPsvc"
    "PrintNotify"
    "PrintWorkflow"
    "PushToInstall"
    "QWAVE"
    "RasAuto"
    "RasMan"
    "RemoteAccess"
    "RemoteRegistry"
    "RetailDemo"
    "RmSvc"
    "RpcLocator"
    "SCardSvr"
    "ScDeviceEnum"
    "SCPolicySvc"
    "SDRSVC"
    "SEMgrSvc"
    "SensorDataService"
    "SensorService"
    "SensrSvc"
    "SharedAccess"
    "SharedRealitySvc"
    "shpamsvc"
    "simptcp"
    "SmsRouter"
    "SNMP"
    "SNMPTRAP"
    "spectrum"
    "SSDPSRV"
    "stisvc"
    "SysMain"
    "TapiSrv"
    "Themes"
    "UevAgentService"
    "UnistoreSvc"
    "upnphost"
    "UserDataSvc"
    "WalletService"
    "wbengine"
    "WbioSrvc"
    "Wcmsvc"
    "WCNCSVC"
    "WinHttpAutoProxySvc"
    "WinRM"
    "wisvc"
    "WlanSvc"
    "wlidsvc"
    "WMPNetworkSvc"
    "workfolderssvc"
    "xbgm"
    "XblAuthManager"
    "XblGameSave"
    "XboxGipSvc"
    "XboxNetApiSvc"
)
foreach ($service in $stopservices) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
    Stop-Service -Force $service
}

$manualservices = @(
    "BDESVC"
    "diagsvc"
    "IKEEXT"
    "NaturalAuthentication"
    "PolicyAgent"
    "UsoSvc"
    "WdNisSvc"
    "wscsvc"
    "wuauserv"
    "svsvc"
    "TrustedInstaller"
)
foreach ($service in $manualservices) {
    Write-Output "Trying to manual $service"
    Get-Service -Name $service | Set-Service -StartupType Manual
    Start-Service $service
}

$startservices = @(
    "Dhcp"
    "Dnscache"
    "DoSvc"
    "DPS"
    "emet_service"
    "gpsvc"
    "LanmanWorkstation"
    "WSearch"
    "MpsSvc"
    "EventLog"
    "WinDefend"
    "Schedule"
    "SecurityHealthService"
    "Sense"
    "sppsvc"
)
foreach ($service in $startservices) {
    Write-Output "Trying to enable $service"
    Set-Service $service -StartupType Automatic
    Start-Service $service
}

#Features
$UninstallFeatures = @(
    "WindowsMediaPlayer"
    "DirectPlay"
    "SimpleTCP"
    "SNMP"
    "WindowsMediaPlayer"
    "WorkFolders-Client"
    "SMB1Protocol"
    "Internet-Explorer-Optional-amd64"
    "rasrip"
    "TFTP"
)
foreach ($Feature in $UninstallFeatures) {
    Write-Output "Trying to uninstall $Feature"
    Uninstall-WindowsFeature -Name $Feature
}

#Auditpolicy - doesn't work
auditpol /set /category:* /success:enable /failure:enable

#Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-MpPreference -DisableRealtimeMonitoring $false

pause
