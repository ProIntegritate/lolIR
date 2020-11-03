@echo off
set th=%date%T%time%
mkdir %date%_%computername%
cd %date%_%computername%
mkdir prefetch
cls
echo --------------------------------------------------------------------------------
echo LOLIR - Living Of the Land Incident Response - run as admin for more detail.
echo Last updated 17:57 2020-11-03
echo --------------------------------------------------------------------------------
echo * Logs: Security log requires admin rights (SecurityPrivilege)
echo * Logs: System log
echo * Logs: Application log
echo * Logs: Setup log

start /b wevtutil qe security >%date%_log.security.txt 
start /b wevtutil qe system >%date%_log.system.txt 
start /b wevtutil qe application >%date%_log.application.txt 

timeout 1 >nul

start /b wevtutil epl security %date%_log.security.evtx
start /b wevtutil epl system %date%_log.system.evtx
start /b wevtutil epl application %date%_log.application.evtx

timeout 1 >nul

rem If there are any error messages saying "file cannot be written", change the timeout values to something larger.

echo * Dump registry: HKLM
start /b reg export HKLM %date%_reg_HKLM.txt >nul
echo * Dump registry: HKCU
start /b reg export HKCU %date%_reg_HKCU.txt >nul
echo * Dump registry: HKU
start /b reg export HKU %date%_reg_HKU.txt >nul

echo * Dump DNS Cache IPConf
ipconfig /displaydns >%date%_dnsCache.IPConf.txt
echo * Dump DNS Cache Powershell
powershell -c "Get-DnsClientCache | Format-List" >%date%_dnsCache.ps.txt

echo * Kerberos sessions
klist sessions >%date%_kerberos.session.tickets.txt

echo * Current processes (List)
tasklist /FO LIST > %date%_processes.short.txt
wmic process get Caption,CommandLine,ParentProcessId,ProcessId,SessionId /format:csv >%date%_processes.long.txt

echo * Network state (Admin = more detail)
Netstat -nabo >%date%_netstat.admin.txt
echo * Network state (user)
Netstat -nao >%date%_netstat.user.txt

echo * Scheduled tasks
schtasks /query /v /FO list  >%date%_schtasks.txt

echo * Services
sc query > %date%_services.sc.txt
net start > %date%_services.net.txt

echo * VSSAdmin Volumes
vssadmin list volumes > %date%_volumes.txt
echo * VSSAdmin Shadows (info only)
vssadmin list shadows >%date%_vssadmin.shadows.txt
echo * VSSAdmin Shadowstorage (info only)
vssadmin list shadowstorage >%date%_vssadmin.shadowstorage.txt

echo * Repository (objects.dat)
copy C:\Windows\System32\wbem\Repository\OBJECTS.DATA %date%_repository.objects.data >nul

echo * Prefetch
copy c:\windows\prefetch\*.pf prefetch >nul

echo * Firewall
netsh advfirewall firewall show rule name=all >%date%_firewall.txt

echo * Startup
wmic startup get * >%date%_startup.txt

echo * Temp
attrib %temp%\*.exe /s | find /i ".exe" >%date%_temp.exe.txt

echo * Hosts
copy c:\Windows\System32\drivers\etc\hosts %date%_hosts.txt

echo * Environment
set > %date%_environment.txt

echo * System info
systeminfo >%date%_systeminfo.txt

echo * Arp
arp -a > %date%_arp.txt

echo * Users
net user > %date%_net.users.txt
echo * Mapped Drives (Requires Workstation Service running)
net use > %date%_net.drives.txt
echo * Groups (Requires Workstation Service running)
net localgroup > %date%_net.localgroup.txt
echo * Shares (Requires Server Service running)
echo n | net share > %date%_net.shares.txt

cd ..
echo --------------------------------------------------------------------------------
echo Started: %th%
echo Ended:   %date%T%time%
