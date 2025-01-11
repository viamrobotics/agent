@echo off
:: installer for agent on windows

set root=\opt\viam
set fname=viam-agent-windows-amd64-alpha-4-6af4e0f.exe
mkdir %root%\cache
mkdir %root%\bin
curl https://storage.googleapis.com/packages.viam.com/temp/%fname% -o %root%\cache\%fname%
netsh advfirewall firewall add rule name="%fname%" dir=in action=allow program="c:\%root%\cache\%fname%" enable=yes
del %root%\bin\viam-agent.exe
mklink %root%\bin\viam-agent.exe %root%\cache\%fname%
sc create viam-agent binpath= c:%root%\bin\viam-agent.exe start= auto
sc start viam-agent
