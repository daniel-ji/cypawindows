#enables and disables services for server and windows
#removes and adds windows features (and ie if need be)
#for both windows 10 and windows server (different options)
disable-windowsoptionalfeature -online -featureName rasrip
disable-windowsoptionalfeature -online -featureName WindowsMediaPlayer
disable-windowsoptionalfeature -online -featureName SimpleTCP
disable-windowsoptionalfeature -online -featureName SNMP
disable-windowsoptionalfeature -online -featureName TelnetClient
disable-windowsoptionalfeature -online -featureName SMB1Protocol

$isServer = Read-Host "Windows Server? [Y/n]"
if ($isServer -eq 'Y' -or $isServer -eq 'y') {
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
} elseif ($isServer -eq 'N' -or $isServer -eq 'n') {
    $stopservices = @(
        "Spooler"
        "RasAuto"
        "RasMan"
        "SessionEnv"
        "TermService"
        "UmRdpService"
        "RemoteRegistry"
        "RemoteAccess"
        "iprip"
        "SNMPTRAP"
        "SSDPSRV"
        "lmhosts"
        "TapiSrv"
        "telnet"
        "upnphost"
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
} else {
    Write-Host "Bad Input"
}

pause
