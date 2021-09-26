#NOTE: CHECK (DEFAULT) GROUPS STILL
#Script to configure Users, create an users.txt file for local users, admins.txt file for local admins
#Disables & Configures Admin & Guest & Default Account
#Disables all unlisted users
#Enables all listed users
#Removes all users that aren't supposed to be admins
#enable change password at next logon
#disable password never expires
#lists all groups ... other than Administrators and Users

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
}

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