# lolIR
**lolIR - Living Of the Land Incident Response**

A live response script for Windows without any dependencies or tool requirements.

It is common to use lolbins to do intrusions, so i thought, what lolbins are there to do Incident Response?
And lolIR was born. This is basically an *"i'm bored and want to do something"*-project.

**Currently it collects the following sources:**

* Logs: Security log
* Logs: System log
* Logs: Application log
* Logs: Setup log
* Dump registry: HKLM
* Dump registry: HKCU
* Dump registry: HKU
* Dump DNS Cache IPConf
* Dump DNS Cache Powershell
* Kerberos sessions
* Current processes
* Network connections
* Scheduled tasks
* Services
* VSSAdmin Volumes
* VSSAdmin Shadows
* VSSAdmin Shadowstorage
* Repository (objects.dat)
* Prefetch files
* Firewall Configuration
* Startup
* Executables in %Temp%
* Hosts
* Environment
* System info
* Arp
* Users
* Mapped Drives
* Groups
* Shares
* SecEdit configuration

Latest version (2025) also include these source:
* WiFi config
* Log source: Bitsclient (Text and EVTX)
* Log source: TerminalServer: Remote, Local and RDPClient (Text and EVTX)
* Log source: TaskSheduler (Text and EVTX)
* User "recent" folders (zipped)

Some of these are information only, i.e. no parsing is done of shadow storage but it reports if storage is still intact, and some files need to be parsed separately, like prefetch files and repository.

Runs quite fast, many thing are started in parallel so it takes from 30 to 10 seconds depending on your system performance.

For each machine it creaters a folder called %date%-%computername% so if you do aquisition on multiple boxes you get a unique folder for each run. Can be started on USB, network share or whatever and yes, it does not need any other files to work, 100% Windows lolbins for DFIR.

**How to use it:**

1. Get the .bat file
2. Fire it up under admin privileges.
3. Done.
