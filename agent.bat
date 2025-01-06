@echo off
:: installer for agent on windows

mkdir \opt\viam\cache
mkdir \opt\viam\bin
curl https://storage.googleapis.com/packages.viam.com/temp/viam-agent-windows-amd64-alpha-1-17bbf00.exe -o \opt\viam\cache\viam-agent-windows-amd64-alpha-1-17bbf00.exe
del \opt\viam\bin\viam-agent.exe
mklink \opt\viam\bin\viam-agent.exe \opt\viam\cache\viam-agent-windows-amd64-alpha-1-17bbf00.exe
sc create viam-agent binpath= c:\opt\viam\bin\viam-agent.exe start= auto
sc start viam-agent
