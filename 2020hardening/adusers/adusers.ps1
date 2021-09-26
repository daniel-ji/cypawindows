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