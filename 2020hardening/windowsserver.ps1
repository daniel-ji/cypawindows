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
    Remove-ADGroupMember -Identity "Administrators" -Member (Get-ADUser -Filter 'Name -ne "Administrator"') -Confirm:$False

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
    $kerberos = Read-Host "Wipe user Kerberos settings? Y/y"
    if ($kerberos -eq 'Y' -or $kerberos -eq 'y') {
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

#Services
$stopservices = @(
    "Spooler"
    "iprip"
    "SNMPTRAP"
    "SSDPSRV"
    "TapiSrv"
    "telnet"
    "lfsvc"
    "MapsBroker"
    "NetTcpPortSharing"
    "XblAuthManager"
    "XblGameSave"
    "XboxNetApiSvc"
    "RpcLocator"
)
foreach ($service in $stopservices) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
    Stop-Service -Force $service
}
$startservices = @(
    "WSearch"
    "MpsSvc"
    "EventLog"
    "Wuauserv"
    "WinDefend"
    "WdNisSvc"
)
foreach ($service in $startservices) {
    Write-Output "Trying to enable $service"
    Set-Service $service -StartupType Automatic
    Start-Service $service
}

#Features
disable-windowsoptionalfeature -online -featureName rasrip
disable-windowsoptionalfeature -online -featureName WindowsMediaPlayer
disable-windowsoptionalfeature -online -featureName SimpleTCP
disable-windowsoptionalfeature -online -featureName SNMP
disable-windowsoptionalfeature -online -featureName TelnetClient
disable-windowsoptionalfeature -online -featureName SMB1Protocol


#Auditpolicy - doesn't work
auditpol /set /category:* /success:enable /failure:enable


#Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-MpPreference -DisableRealtimeMonitoring $false

pause
