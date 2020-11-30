@echo off
set th=%date%T%time%
mkdir %date%_%computername%
cd %date%_%computername%
mkdir prefetch
cls
echo --------------------------------------------------------------------------------
echo LOLIR - Living Of the Land Incident Response - run as admin for more detail.
echo Last updated 17:26 2020-11-30
echo --------------------------------------------------------------------------------
echo * Logs: Security log requires admin rights (SecurityPrivilege)
echo * Logs: System log
echo * Logs: Application log
echo * Logs: Setup log

start /b wevtutil qe security >%date%_log.security.txt 
start /b wevtutil qe system >%date%_log.system.txt 
start /b wevtutil qe application >%date%_log.application.txt 
start /b wevtutil qe setup >%date%_log.setup.txt 

timeout 1 >nul

start /b wevtutil epl security %date%_log.security.evtx
start /b wevtutil epl system %date%_log.system.evtx
start /b wevtutil epl application %date%_log.application.evtx
start /b wevtutil epl setup %date%_log.setup.evtx

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

echo * Dump SecEdit (Requires admin privileges)
secedit /export /cfg %date%_SecEdit.txt

echo * Kerberos sessions
klist sessions >%date%_kerberos.session.tickets.klist.txt
powershell -c "gwmi win32_LogonSession" >%date%_kerberos.session.tickets.ps.txt

echo * Current processes (List)
tasklist /FO LIST > %date%_processes.short.txt
wmic process get Caption,CommandLine,ParentProcessId,ProcessId,SessionId /format:csv >%date%_processes.long.txt

echo * Network state (Admin = more detail)
Netstat -nabo >%date%_netstat.admin.txt
echo * Network state (user)
Netstat -nao >%date%_netstat.user.txt

echo * Scheduled tasks
schtasks /query /v /FO list  >%date%_schtasks.txt

echo * Services (Win32_Services)
sc query > %date%_services.sc.txt
net start > %date%_services.net.txt
wmic service get * /FORMAT:list >%date%_services.wmic.txt

echo * Prefetch
start /b copy c:\windows\prefetch\*.pf prefetch  >nul

echo * Repository (objects.dat)
copy C:\Windows\System32\wbem\Repository\OBJECTS.DATA %date%_repository.objects.data >nul

echo * VSSAdmin Volumes
vssadmin list volumes > %date%_volumes.txt
echo * VSSAdmin Shadows (info only)
vssadmin list shadows >%date%_vssadmin.shadows.txt
echo * VSSAdmin Shadowstorage (info only)
vssadmin list shadowstorage >%date%_vssadmin.shadowstorage.txt

echo * Firewall
netsh advfirewall firewall show rule name=all >%date%_firewall.txt

echo * Startup
wmic startup list /format:csv >%date%_startup.txt

echo * Temp
attrib %temp%\*.exe /s | find /i ".exe" >%date%_temp.exe.txt

echo * Hosts
copy c:\Windows\System32\drivers\etc\hosts %date%_hosts.txt >nul

echo * Environment
set > %date%_environment.txt

echo * System info
systeminfo >%date%_systeminfo.txt

echo * Arp
arp -a > %date%_arp.txt

echo * IPConfig
ipconfig /all > %date%_ipconfig.txt

echo * Installed software (takes a while to run)
start /b wmic product list /format:csv > %date%_wmic.installed.software.txt

echo * Users
net user > %date%_net.users.txt
wmic useraccount list /format:csv > %date%_wmic.useraccount.txt
echo * Mapped Drives (Requires Workstation Service running)
net use > %date%_net.drives.txt
echo * Shares (Requires Server Service running)
echo n | net share > %date%_net.shares.txt
echo * Groups (Requires Workstation Service running)
net localgroup > %date%_net.localgroup.txt
wmic group list /format:csv > %date%_wmic.groups.txt

echo * Disks
wmic logicaldisk list brief > %date%.wmic.logicaldisks.txt

echo * Installed patches
wmic qfe list brief > %date%.wmic.installedpatches.txt

echo * Network Interface cards
wmic nicconfig list /format:csv > %date%_wmic.niclist.txt
wmic nic list brief /format:csv> %date%_wmic.nic.list.gw-ip.txt
powershell -c "get-netadapter | format-list" > %date%_ps.niclist.txt
netsh interface show interface > %date%_netsh.niclist.txt

echo * Domain membership info
wmic ntdomain get Caption, DnsForestName, DomainControllerAddress, Status > %date%_domain.membership.txt

echo * Logins
wmic netlogin get * /format:csv > %date%_wmic.logins.txt

echo * Plug and play devices
wmic path Win32_PnPEntity get Caption, Status, Manufacturer, Service  > %date%_wmic.pnp.txt

rem ----------------------------------------
rem Slow or less useful queries:
rem ----------------------------------------

rem echo * Installed printers (Unauthorised local printers)
rem wmic printer list/format:csv > %date%_wmic.printer.txt

rem echo * Filesystem timestamps (Can take a VERY long time, uncomment to activate)
rem dir \*.* /s >%date_filesystem.txt

cd ..
echo --------------------------------------------------------------------------------
echo Started: %th%
echo Ended:   %date%T%time%
