#SET GROUP POLICY FIRST!!!

$ADDS  = Read-Host "Is there ADDS? [Y/n]"
if ($ADDS -eq "Y") {

    #NOTE: CHECK (DEFAULT) GROUPS STILL
    #Script to configure AD Users, create an adusers.txt file for local users, adadmins.txt file for local admins
    #Disables & Configures Admin & Guest & Default Account
    #Disables all unlisted users
    #Enables all listed users
    #Removes all users that aren't supposed to be admins
    #enable change password at next logon
    #disable password never expires
    #pw is not stored with reversible encryption
    #smart card is not required
    #lists all locked accounts
    #prompts for account delegation and Kerberos stuff (second to last to fourth to last are unchecked, last is checked)
    #lists all groups ... other than Administrators and Users

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
    #all accounts
    Search-ADAccount -lockedout | Select-Object Name, SamAccountName
    Get-ADUser -Filter * | Set-ADUser -PasswordNeverExpires $false -CannotChangePassword $false -ChangePasswordAtLogon $true -AllowReversiblePasswordEncryption $false -SmartcardLogonRequire $false -TrustedForDelegation $false
    Get-ADUser -Filter * | Disable-ADAccount
    Remove-ADGroupMember -Identity "Administrators" -Member (Get-ADUser -Filter 'Name -ne "nimda"') -Confirm:$False

    #authorized users
    $Password = convertto-securestring "Cyberpatriot2020" -asplaintext -force
    foreach($line in Get-Content C:\2020hardening\adusers\adusers.txt) {
        Get-ADUser -Identity $line | Enable-ADAccount
        Set-ADAccountPassword -Identity $line -Reset -NewPassword $Password
        Set-ADUser -Identity $line -PasswordNeverExpires $false -CannotChangePassword $false -ChangePasswordAtLogon $true -AllowReversiblePasswordEncryption $false
    }

    #authorized admin
    foreach($line in Get-Content C:\2020hardening\adusers\adadmins.txt) {
        Get-ADUser -Identity $line | Enable-ADAccount
        Set-ADAccountPassword -Identity $line -Reset -NewPassword $Password
        Set-ADUser -Identity $line -PasswordNeverExpires $false -CannotChangePassword $false -ChangePasswordAtLogon $true -AllowReversiblePasswordEncryption $false
        Add-ADGroupMember -Identity "Administrators" -Members $line
        Add-ADGroupMember -Identity "Domain Admins" -Members $line
    }

    #default accounts
    Set-ADUser -Identity "tseug" -PasswordNeverExpires $true -CannotChangePassword $true -ChangePasswordAtLogon $false -AllowReversiblePasswordEncryption $false
    Disable-ADACcount -Identity "tseug"
    Set-ADUser -Identity "nimda" -PasswordNeverExpires $true -CannotChangePassword $true -ChangePasswordAtLogon $false -AllowReversiblePasswordEncryption $false
    Disable-ADACcount -Identity "nimda"
    Set-ADUser -Identity "DefaultAccount" -PasswordNeverExpires $true -CannotChangePassword $true -ChangePasswordAtLogon $false -AllowReversiblePasswordEncryption $false
    Disable-ADACcount -Identity "DefaultAccount"

    #prompt kerberos wipe
    $Kerberos = Read-Host "Wipe user Kerberos settings? Y/y"
    if ($Kerberos -eq 'Y' -or $Kerberos -eq 'y') {
        Get-ADUser -Filter * | Set-ADAccountControl -DoesNotRequirePreAuth $true -UseDESKeyOnly $false
        Get-ADUser -Filter * | Set-ADUser -KerberosEncryptionType "None"
    }

    #listing all groups
    foreach($group in Get-ADGroup -Filter *) {
        Write-Output "`n"
        Write-Output $group | Select-Object name
        Get-ADGroupMember -Identity $group | Select-Object name
    }

    pause


} elseif ($ADDS -eq "n") {

    
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
    Get-LocalUser tseug | Disable-LocalUser 
    Set-LocalUser -Name "nimda" -PasswordNeverExpires $true -UserMayChangePassword $false
    Get-LocalUser nimda| Disable-LocalUser
    Set-LocalUser -Name "DefaultAccount" -PasswordNeverExpires $true -UserMayChangePassword $false
    Get-LocalUser DefaultAccount | Disable-LocalUser

    foreach($group in Get-LocalGroup -Name *) {
        Write-Output "`n"
        Write-Output $group | Select-Object name
        Get-LocalGroupMember -Group $group | Select-Object name
    }

    pause

} else {
    Write-Host "bad input"
    exit
}

function Set-Functionality {
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
            Uninstall-WindowsFeature -Name $Feature
        }
    } elseif ($Prompt -eq "A") {
        foreach ($Service in $RelatedServices) {
            Write-Output "Trying to automatic $Service"
            Get-Service -Name $Service | Set-Service -StartupType Automatic
            Start-Service $Service
        }
        foreach ($Feature in $RelatedFeatures) {
            Write-Output "Trying to enable $Feature"
            Install-WindowsFeature -Name $Feature
        }
    } elseif ($Prompt -eq "M") {
        foreach ($Service in $RelatedServices) {
            Write-Output "Trying to manual $Service"
            Get-Service -Name $Service | Set-Service -StartupType Manual
            Start-Service $Service
        }
        foreach ($Feature in $RelatedFeatures) {
            Write-Output "Trying to enable $Feature"
            Install-WindowsFeature -Name $Feature
        }
    }
}

Set-Functionality "Fax" @() @("Fax")
Set-Functionality "Print" @("Spooler") @("LPR-Port-Monitor",  "Internet-Print-Client", "Print-Services")
Set-Functionality "RDP" @("SessionEnv", "UmRdpService", "TermService") @("Remote-Desktop-Services")

#Services
$StopServices = @(
    "iprip"
    "AxInstSV"
    "bthserv"
    #"CDPUserSvc"
    #"PimIndexMaintenanceSvc"
    #"dmwappushservice"
    "MapsBroker"
    #"EapHost"
    #"fdPHost"
    #"FDResPub"
    "lfsvc"
    #"SharedAccess"
    "iphlpsvc"
    #"lltdsvc"
    "AppVClient"
    "NetTcpPortSharing"
    #"CscService"
    #"PrintNotify"
    #"QWAVE"
    #"RmSvc"
    "RasMan"
    "RasAuto"
    "RemoteRegistry"
    "RemoteAccess"
    "RpcLocator"
    #"SensrSvc"
    #"SensorService"
    #"ScDeviceEnum"
    #"SCardSvr"
    #"SCPolicySvc"
    "SNMPTRAP"
    "SSDPSRV"
    "WiaRpc"
    "OneSyncSvc"
    "TapiSrv"
    "Themes"
    "upnphost"
    #"UserDataSvc"
    #"UnistoreSvc"
    #"UevAgentService"
    "WalletService"
    #"WbioSrvc"
    #"Wcmsvc"
    "stisvc"
    "wisvc"
    "icssvc"
    #"dot3svc"
    "XblAuthManager"
    "XblGameSave"
)
foreach ($Service in $StopServices) {
    Write-Output "Trying to disable $Service"
    Get-Service -Name $Service | Set-Service -StartupType Disabled
    Stop-Service -Force $Service
}

$ManualServices = @(
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
    "WerSvc"
    "TrustedInstaller"
    "Sense"
)
foreach ($Service in $ManualServices) {
    Write-Output "Trying to manual $Service"
    Get-Service -Name $Service | Set-Service -StartupType Manual
    Start-Service $Service
}

$StartServices = @(
    "Dhcp"
    "Dnscache"
    "DoSvc"
    "DPS"
    "emet_Service"
    "gpsvc"
    "LanmanWorkstation"
    "WSearch"
    "MpsSvc"
    "EventLog"
    "WinDefend"
    "Schedule"
    "SecurityHealthService"
    "sppsvc"
    "LSM"
    "RpcSs"
    "SamSs"
    "LanmanServer"
    "SENS"
    "SystemEventsBroker"
    "WinRM"
)
foreach ($Service in $StartServices) {
    Write-Output "Trying to enable $Service"
    Set-Service $Service -StartupType Automatic
    Start-Service $Service
}

Write-Output "Listing features..."
pause

Get-WindowsFeature | Where-Object {$_. installstate -eq "installed"} | Format-List Name,Installstate | more
pause

#Features
$UninstallFeatures = @(
    "WindowsMediaPlayer"
    "Direct-Play"
    "Remote-Assistance"
    #"RPC-over-HTTP-Proxy"
    "Simple-TCPIP"
    "FS-SMB1"
    "Telnet-Client"
    "PowerShell-V2"
    "XPS-Viewer"
    #"FS-SyncShareService"
    "RDC"
    "SNMP-Service"
    #"TFTP-Client"
)
foreach ($Feature in $UninstallFeatures) {
    Write-Output "Trying to uninstall $Feature"
    Uninstall-WindowsFeature -Name $Feature
}

$InstallFeatures = @(
    "Windows-Defender"
)
foreach ($Feature in $InstallFeatures) {
    Write-Output "Trying to install $Feature"
    Install-WindowsFeature -Name $Feature
}


#Auditpolicy
Write-Output "Setting audit policy through auditpol"
auditpol /set /category:* /success:enable /failure:enable

#Firewall
Write-Output "Turning firewall on"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-MpPreference -DisableRealtimeMonitoring $false

pause
