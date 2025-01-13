@echo off
:: installer for agent on windows

set root=\opt\viam
set fname=viam-agent-windows-amd64-alpha-16-6dece14.exe
mkdir %root%\cache
mkdir %root%\bin
curl https://storage.googleapis.com/packages.viam.com/temp/%fname% -o %root%\cache\%fname%
netsh advfirewall firewall add rule name="%fname%" dir=in action=allow program="c:\%root%\cache\%fname%" enable=yes
del %root%\bin\viam-agent.exe
mklink %root%\bin\viam-agent.exe %root%\cache\%fname%
:: todo: restart on error
sc create viam-agent binpath= c:%root%\bin\viam-agent.exe start= auto
sc failure viam-agent reset= 0 actions= restart/30000/restart/30000/restart/30000
sc failureflag viam-agent 1
sc start viam-agent
