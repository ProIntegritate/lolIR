# lolIR
**lolIR - Living Of the Land Incident Response**

QUICKSTART: Get and use the "LOLIR_2025.bat" file:
**curl -LO https://tinyurl.com/get-lolir && move get-lolir lolir.bat && lolir.bat**

SO - WHAT IS THIS? It is a live response forensics script for Windows without any dependencies or tool requirements.

It is common to use lolbins to do intrusions, so i thought, what lolbins are there to do Incident Response?
And lolIR was born. This is basically an *"i'm bored and want to do something"*-project. The goal here is not
to pull down 100's of tools and litter up the captured environment, but to - you guessed it - live of the land.

**What is being captured:**

* Logs: Security log (Requires admin privileges)
* Logs: System log
* Logs: Application log
* Logs: Setup log
* Logs: PowerShell/Operational log
* Logs: Sysmon/Operational log
* Logs: TaskScheduler/Operational log
* Logs: BitsClient/Operational log 
* Logs: TerminalServices-LocalSessionManager log 
* Logs: TerminalServices-RemoteConnectionManager log 
* Logs: TerminalServices-RDPClient/Operational log 
* Logs: LAPS
* Logs: DHCP+DHCP6
* Logs: Defender
* Logs: AdvFirewall
* Logs: Hyper-V
* Logs: WinRM
* Dump registry: HKLM to text
* Dump registry: HKCU to text
* Dump registry: HKU to text
* Dump BITS jobs
* Dump DNS Cache
* IPConfig /all
* Dump DNS Cache Powershell
* Dump SecEdit
* Kerberos sessions
* NTDS.DIT (Servers only, like 2019/2022/2025).
* Current processes (List)
* Network state
* Network state
* Scheduled tasks
* Services (Win32_Services)
* Repository
* WDI
* WMI
* Setupapi
* Prefetch
* Mountvol Drivers
* VSSAdmin Volumes
* VSSAdmin Shadows (info only)
* VSSAdmin Shadowstorage (info only)
* Firewall
* Startup
* Executables in world/user writeable, non-standard locations.
* Hosts
* Environment
* System info
* Arp
* Users
* Mapped Drives
* Shares
* Groups
* Disks
* Installed patches
* Network Interface cards
* Wifi networks
* Wifi Config
* Domain membership info
* Logins
* Plug and play devices
* Installed printers
* Installed software
* User Recent files (all user folders)
* Filesystem timestamps
* Filesystem hierarchy

Some of these are information only, i.e. no parsing is done of shadow storage but it reports if storage is still intact, and some files need to be parsed separately, like prefetch files and repository.

Runs quite fast, many thing are started in parallel so it takes from 30 to 10 seconds depending on your system performance.

For each machine it creaters a folder called %computername%_%timestamp% so if you do aquisition on multiple boxes you get a unique folder for each run. Can be started on USB, network share or whatever and yes, it does not need any other files to work, 100% Windows lolbins for DFIR.

**How to use it:**

1. Get the .bat file
2. Run it up under admin privileges.
3. Done.
