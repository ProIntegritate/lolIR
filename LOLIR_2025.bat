@echo off

powershell -c "Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'" > timestamp.txt
set /p timestamp=<timestamp.txt
echo y | del timestamp.txt

mkdir LOLIR_%computername%_%timestamp%
cd LOLIR_%computername%_%timestamp%
mkdir prefetch
cls
color cf
echo --------------------------------------------------------------------------------
echo Started at: %timestamp%
echo LOLIR - Living Of the Land Incident Response - run as ADMIN for more detail.
echo Last updated 2025-03-19, This script now REQUIRE **at least** Windows 10.
echo --------------------------------------------------------------------------------

echo * Logs: Security log (Requires admin privileges)
start /b wevtutil qe /f:text security > %computername%_log.security.log

echo * Logs: System log
start /b wevtutil qe /f:text system > %computername%_log.system.log

echo * Logs: Application log
start /b wevtutil qe /f:text application > %computername%_log.application.log

echo * Logs: Setup log
start /b wevtutil qe /f:text setup > %computername%_log.setup.log

echo * Logs: PowerShell/Operational log
start /b wevtutil qe /f:text Microsoft-Windows-PowerShell/Operational > %computername%_powershell.operational.log

echo * Logs: Sysmon/Operational log (Requires admin privileges)
start /b wevtutil qe /f:text Microsoft-Windows-Sysmon/Operational > %computername%_sysmon.operational.log

echo * Logs: TaskScheduler/Operational log
start /b wevtutil qe /f:text Microsoft-Windows-TaskScheduler/Operational > %computername%_taskscheduler.operational.log

echo * Logs: BitsClient/Operational log 
start /b wevtutil qe /f:text Microsoft-Windows-Bits-Client/Operational > %computername%_bitsclient.operational.log

echo * Logs: TerminalServices-LocalSessionManager log 
start /b wevtutil qe /f:text Microsoft-Windows-TerminalServices-LocalSessionManager/Operational > %computername%_Term.Local.operational.log

echo * Logs: TerminalServices-RemoteConnectionManager log 
start /b wevtutil qe /f:text Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational > %computername%_Term.Remote.operational.log

echo * Logs: TerminalServices-RDPClient/Operational log 
start /b wevtutil qe /f:text Microsoft-Windows-TerminalServices-RDPClient/Operational > %computername%_Term.RDPClient.operational.log

echo * Logs: LAPS
start /b wevtutil qe /f:text Microsoft-Windows-Laps/Operational > %computername%_laps.operational.log

echo * Logs: DHCP+DHCP6
start /b wevtutil qe /f:text Microsoft-Windows-Dhcp-Client/Admin > %computername%_dhcpclient.admin.log
start /b wevtutil qe /f:text Microsoft-Windows-DHCP-Client/Operational > %computername%_dhcpclient.operational.log
start /b wevtutil qe /f:text Microsoft-Windows-DHCPv6-Client/Admin > %computername%_dhcpclient6.admin.log
start /b wevtutil qe /f:text Microsoft-Windows-DHCPv6-Client/Operational > %computername%_dhcpclient6.operational.log

echo * Logs: Defender
start /b wevtutil qe /f:text "Microsoft-Windows-Windows Defender/Operational" > %computername%_defender.operational.log

echo * Logs: AdvFirewall
start /b wevtutil qe /f:text "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" > %computername%_advfirewall.firewall.log
start /b wevtutil qe /f:text "Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" > %computername%_advfirewall.firewallverbose.log

echo * Logs: Hyper-V
start /b wevtutil qe /f:text Microsoft-Windows-Hyper-V-Hypervisor-Admin > %computername%_hyperv.admin.log
start /b wevtutil qe /f:text Microsoft-Windows-Hyper-V-Hypervisor-Operational > %computername%_hyperv.operational.log

echo * Logs: WinRM
start /b wevtutil qe /f:text Microsoft-Windows-WinRM/Operational > %computername%_winrm.operational.log

timeout 10

echo * Dumping .evtx files of the same sources (above).
start /b wevtutil epl security %computername%_log.security.evtx
start /b wevtutil epl system %computername%_log.system.evtx
start /b wevtutil epl application %computername%_log.application.evtx
start /b wevtutil epl setup %computername%_log.setup.evtx
start /b wevtutil epl Microsoft-Windows-PowerShell/Operational %computername%_log.powershell.evtx
start /b wevtutil epl Microsoft-Windows-Sysmon/Operational %computername%_log.sysmon.evtx
start /b wevtutil epl Microsoft-Windows-TaskScheduler/Operational %computername%_log.taskscheduler.evtx
start /b wevtutil epl Microsoft-Windows-Bits-Client/Operational %computername%_log.bitsclient.evtx
start /b wevtutil epl Microsoft-Windows-TerminalServices-LocalSessionManager/Operational %computername%_log.Term.Local.evtx
start /b wevtutil epl Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational %computername%_log.Term.Remote.evtx
start /b wevtutil epl Microsoft-Windows-TerminalServices-RDPClient/Operational %computername%_log.Term.RDPClient.evtx
start /b wevtutil epl Microsoft-Windows-Laps/Operational %computername%_laps.operational.evtx
start /b wevtutil epl Microsoft-Windows-Dhcp-Client/Admin %computername%_dhcpclient.admin.evtx
start /b wevtutil epl Microsoft-Windows-DHCP-Client/Operational %computername%_dhcpclient.operational.evtx
start /b wevtutil epl Microsoft-Windows-DHCPv6-Client/Admin %computername%_dhcpclient6.admin.evtx
start /b wevtutil epl Microsoft-Windows-DHCPv6-Client/Operational %computername%_dhcpclient6.operational.evtx
start /b wevtutil epl "Microsoft-Windows-Windows Defender/Operational" %computername%_defender.operational.evtx
start /b wevtutil epl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" %computername%_advfirewall.firewall.evtx
start /b wevtutil epl "Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" %computername%_advfirewall.firewallverbose.evtx
start /b wevtutil epl Microsoft-Windows-Hyper-V-Hypervisor-Admin %computername%_hyperv.admin.evtx
start /b wevtutil epl Microsoft-Windows-Hyper-V-Hypervisor-Operational %computername%_hyperv.operational.evtx
start /b wevtutil epl Microsoft-Windows-WinRM/Operational %computername%_winrm.operational.evtx

timeout 10

rem If there are any error messages saying "file cannot be written", change the timeout values to something larger.

echo * Dump registry: HKLM to text
start /b reg export HKLM %computername%_reg_HKLM.txt

echo * Dump registry: HKCU to text
start /b reg export HKCU %computername%_reg_HKCU.txt

echo * Dump registry: HKU to text
start /b reg export HKU %computername%_reg_HKU.txt

timeout 10

echo * Dump BITS jobs
bitsadmin.exe /rawreturn /list /allusers /verbose > %computername%_BITS.jobs.txt

echo * Dump DNS Cache
ipconfig /displaydns > %computername%_dnsCache.IPConf.txt

echo * IPConfig /all
ipconfig /all > %computername%_ipconfig.txt

echo * Dump DNS Cache Powershell
powershell -c "Get-DnsClientCache | Format-List" > %computername%_dnsCache.ps.txt

echo * Dump SecEdit (Requires admin privileges)
secedit /export /cfg %computername%_SecEdit.txt

echo * Kerberos sessions
klist sessions > %computername%_kerberos.session.tickets.klist.txt
klist tickets > %computername%_kerberos.tickets.txt
powershell -c "gwmi win32_LogonSession" > %computername%_kerberos.session.tickets.ps.txt

echo * NTDS.DIT (Servers only, like 2019/2022/2025).
esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d %computername%_ntds.dit

echo * Current processes (List)
tasklist /FO LIST > %computername%_processes.short.txt
powershell.exe -c "Get-CimInstance Win32_process | Export-Csv %computername%_processes.long.txt"

echo * Network state (Admin = more detail)
Netstat -nabo > %computername%_netstat.admin.txt

echo * Network state (user)
Netstat -nao > %computername%_netstat.user.txt

echo * Scheduled tasks
schtasks /query /v /FO list > %computername%_schtasks.txt

echo * Services (Win32_Services)
sc query > %computername%_services.sc.txt
net start > %computername%_services.net.txt
powershell.exe -c "Get-CimInstance Win32_service | Export-Csv %computername%_services.txt"

echo * Repository
mkdir Repository
copy C:\Windows\System32\wbem\Repository\* Repository >nul

echo * WDI
mkdir WDI
copy C:\Windows\System32\WDI\LogFiles\* WDI >nul

echo * WMI
mkdir WMI
copy C:\Windows\System32\LogFiles\WMI\* WMI >nul

echo * Setupapi
mkdir Setupapi
copy C:\Windows\INF\setupapi*.log Setupapi >nul

echo * Prefetch
mkdir Prefetch
copy c:\windows\prefetch\*.pf prefetch >nul

echo * Mountvol Drivers
mountvol > %computername%_drives.txt

echo * VSSAdmin Volumes
vssadmin list volumes > %computername%_volumes.txt

echo * VSSAdmin Shadows (info only)
vssadmin list shadows > %computername%_vssadmin.shadows.txt

echo * VSSAdmin Shadowstorage (info only)
vssadmin list shadowstorage > %computername%_vssadmin.shadowstorage.txt

echo * Firewall
netsh advfirewall firewall show rule name=all > %computername%_firewall.txt

echo * Startup
powershell.exe -c "Get-CimInstance Win32_StartupCommand | Export-Csv %computername%_startup.txt"

echo * Executables in world/user writeable, non-standard locations. (This can take a few minutes)
start /b attrib c:\ProgramData\*.exe /s | find /i ".exe" > %computername%_folder-programdata.exe.log
start /b attrib c:\users\*.exe /s | find /i ".exe" > %computername%_folder-users.exe.log

timeout 10

echo * Hosts
copy c:\Windows\System32\drivers\etc\hosts %computername%_hosts.txt

echo * Environment
set > %computername%_environment.txt

echo * System info
systeminfo >%computername%_systeminfo.txt

echo * Arp
arp -a > %computername%_arp.txt

echo * Users
net user > %computername%_net.users.txt
powershell.exe -c "Get-CimInstance Win32_useraccount | Export-Csv %computername%_useraccount.txt"

echo * Mapped Drives (Requires Workstation Service running)
net use > %computername%_net.drives.txt

echo * Shares (Requires Server Service running)
echo n | net share > %computername%_net.shares.txt

echo * Groups (Requires Workstation Service running)
net localgroup > %computername%_net.localgroup.txt
powershell.exe -c "Get-CimInstance Win32_group | Export-Csv %computername%_groups.txt"

echo * Disks
powershell.exe -c "Get-CimInstance Win32_logicaldisk | Export-Csv %computername%_logicaldisks.txt"

echo * Installed patches
powershell.exe -c "Get-CimInstance Win32_QuickFixEngineering | Export-Csv %computername%_installedpatches.txt"

echo * Network Interface cards
powershell.exe -c "Get-CimInstance Win32_NetworkAdapter | Export-Csv %computername%_nic.list.gw-ip.txt"
powershell.exe -c "Get-CimInstance Win32_NetworkAdapterConfiguration | Export-Csv %computername%_niclist.txt"
powershell -c "get-netadapter | format-list" > %computername%_ps.niclist.txt
netsh interface show interface > %computername%_netsh.niclist.txt

echo * Wifi networks
netsh wlan show profiles > %computername%_available.wifi.networks.txt

echo * Wifi Config
netsh wlan show profile Name=* Key=clear > %computername%_wifi.config.txt

echo * Domain membership info
powershell.exe -c "Get-CimInstance Win32_ntdomain | Export-Csv %computername%_domain.membership.txt"

echo * Logins
powershell.exe -c "Get-CimInstance Win32_NetworkLoginProfile | Export-Csv %computername%_netlogins.txt"

echo * Plug and play devices
powershell.exe -c "Get-CimInstance Win32_PnPEntity | Export-Csv %computername%_pnp.txt"

echo * Installed printers (Unauthorised local printers)
powershell -c "Get-Printer | Export-Csv %computername%_printer.txt"

echo * Installed software (takes a while to run)
powershell.exe -c "Get-CimInstance Win32_product | Export-Csv %computername%_installed.software.txt"

echo * User Recent files (all user folders)
for /f %%f in ('dir /B /AD %public%\..') do (
	echo %public%\..\%%f\AppData\Roaming\Microsoft\Windows\Recent\
	powershell -c "Compress-Archive -CompressionLevel Optimal -Path C:\Users\%%f\AppData\Roaming\Microsoft\Windows\Recent\ -DestinationPath %computername%_recent_%%f.zip" > nul
)

echo.

echo * Filesystem timestamps (This can take a few minutes)
dir \*.* /s > %computername%_filesystem.txt
echo * Filesystem hierarchy (This can take a few minutes)
attrib \*.* /s > %computername%_filesystem.hierarchy.txt

cd ..
echo --------------------------------------------------------------------------------
echo Ended @ %date%T%time%.
echo (For some weird reason, this console is now inoperable so just close it)
rem TODO: powershell -c "Compress-Archive -Path LOLIR_%computername%_%timestamp% -DestinationPath LOLIR_%computername%_%timestamp%.zip"
