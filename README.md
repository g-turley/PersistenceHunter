# PersistenceHunter

This tool is an effort to automate checking many of the common registry and filepath locations associated with Windows persistence mechanisms identified in the MITRE ATT&CK Matrix.

## Usage
```powershell
PS> Import-Module ./PersistenceHunter.ps1
```

## Covered Techniques
+ AppCert DLLs
+ AppInit DLLs
+ Application Shimming
+ Authentication Packages (LSA)
+ BITS Jobs
+ Chrome Extensions
+ Firefox Extensions
+ Image File Execution Options
+ Scheduled Tasks

## To-do 
##### Some of these won't be able to be done with PowerShell
+ Bootkits
+ Change Default File Association
+ Component Firmware
+ COM Hijacking
+ DLL Search Order Hijacking
+ External Remote Services
+ File System Permissions Weakness
+ Hidden Files and Directories
+ Hooking
+ Hypervisor
+ Logon Scripts
+ LSASS Driver
+ Modifying Existing Service
+ Netsh Helper DLL
+ New Service
+ Office Application Startup
+ Path Interception
+ Port Monitors
+ PowerShell Profile
+ Redundant Access
+ Registry Run Keys / Startup Folder
+ Screensaver
+ Security Support Provider
+ Server Software Component
+ Service Registry Permissions Weakness
+ Shortcut Modification
+ SIP and Trust Provider Hijacking
+ System Firmware
+ Time Providers
+ Valid Accounts
+ Web Shell
+ Windows Management Instrumentation Event Subscription
+ Winlogon Helper DLL
