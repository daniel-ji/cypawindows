@echo off
ROBOCOPY "%WinDir%\System32\GroupPolicyUsers" "%WinDir%\System32\BACKUPGroupPolicyUsers" /S /E
ROBOCOPY "%WinDir%\System32\GroupPolicy" "%WinDir%\System32\BACKUPGroupPolicy" /S /E
RD /S /Q "%WinDir%\System32\GroupPolicyUsers"
RD /S /Q "%WinDir%\System32\GroupPolicy"
gpupdate /force

cd %~dp0
copy LGPO.exe C:\Windows\System32

lgpo.exe /g server1909r3 /v
pause