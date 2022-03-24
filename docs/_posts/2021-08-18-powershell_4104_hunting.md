---
title: "PowerShell 4104 Hunting"
excerpt: "Command and Scripting Interpreter
, PowerShell
"
categories:
  - Endpoint
last_modified_at: 2021-08-18
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - PowerShell
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following Hunting analytic assists with identifying suspicious PowerShell execution using Script Block Logging, or EventCode 4104. This analytic is not meant to be ran hourly, but occasionally to identify malicious or suspicious PowerShell. This analytic is a combination of work completed by Alex Teixeira and Splunk Threat Research Team.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-18
- **Author**: Michael Haag, Splunk
- **ID**: d6f2b006-0041-11ec-8885-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

#### Search

```
`powershell` EventCode=4104 
| eval DoIt = if(match(Message,"(?i)(\$doit)"), "4", 0) 
| eval enccom=if(match(Message,"[A-Za-z0-9+\/]{44,}([A-Za-z0-9+\/]{4}
|[A-Za-z0-9+\/]{3}=
|[A-Za-z0-9+\/]{2}==)") OR match(Message, "(?i)[-]e(nc*o*d*e*d*c*o*m*m*a*n*d*)*\s+[^-]"),4,0) 
| eval suspcmdlet=if(match(Message, "(?i)Add-Exfiltration
|Add-Persistence
|Add-RegBackdoor
|Add-ScrnSaveBackdoor
|Check-VM
|Do-Exfiltration
|Enabled-DuplicateToken
|Exploit-Jboss
|Find-Fruit
|Find-GPOLocation
|Find-TrustedDocuments
|Get-ApplicationHost
|Get-ChromeDump
|Get-ClipboardContents
|Get-FoxDump
|Get-GPPPassword
|Get-IndexedItem
|Get-Keystrokes
|LSASecret
|Get-PassHash
|Get-RegAlwaysInstallElevated
|Get-RegAutoLogon
|Get-RickAstley
|Get-Screenshot
|Get-SecurityPackages
|Get-ServiceFilePermission
|Get-ServicePermission
|Get-ServiceUnquoted
|Get-SiteListPassword
|Get-System
|Get-TimedScreenshot
|Get-UnattendedInstallFile
|Get-Unconstrained
|Get-VaultCredential
|Get-VulnAutoRun
|Get-VulnSchTask
|Gupt-Backdoor
|HTTP-Login
|Install-SSP
|Install-ServiceBinary
|Invoke-ACLScanner
|Invoke-ADSBackdoor
|Invoke-ARPScan
|Invoke-AllChecks
|Invoke-BackdoorLNK
|Invoke-BypassUAC
|Invoke-CredentialInjection
|Invoke-DCSync
|Invoke-DllInjection
|Invoke-DowngradeAccount
|Invoke-EgressCheck
|Invoke-Inveigh
|Invoke-InveighRelay
|Invoke-Mimikittenz
|Invoke-NetRipper
|Invoke-NinjaCopy
|Invoke-PSInject
|Invoke-Paranoia
|Invoke-PortScan
|Invoke-PoshRat
|Invoke-PostExfil
|Invoke-PowerDump
|Invoke-PowerShellTCP
|Invoke-PsExec
|Invoke-PsUaCme
|Invoke-ReflectivePEInjection
|Invoke-ReverseDNSLookup
|Invoke-RunAs
|Invoke-SMBScanner
|Invoke-SSHCommand
|Invoke-Service
|Invoke-Shellcode
|Invoke-Tater
|Invoke-ThunderStruck
|Invoke-Token
|Invoke-UserHunter
|Invoke-VoiceTroll
|Invoke-WScriptBypassUAC
|Invoke-WinEnum
|MailRaider
|New-HoneyHash
|Out-Minidump
|Port-Scan
|PowerBreach
|PowerUp
|PowerView
|Remove-Update
|Set-MacAttribute
|Set-Wallpaper
|Show-TargetScreen
|Start-CaptureServer
|VolumeShadowCopyTools
|NEEEEWWW
|(Computer
|User)Property
|CachedRDPConnection
|get-net\S+
|invoke-\S+hunter
|Install-Service
|get-\S+(credent
|password)
|remoteps
|Kerberos.*(policy
|ticket)
|netfirewall
|Uninstall-Windows
|Verb\s+Runas
|AmsiBypass
|nishang
|Invoke-Interceptor
|EXEonRemote
|NetworkRelay
|PowerShelludp
|PowerShellIcmp
|CreateShortcut
|copy-vss
|invoke-dll
|invoke-mass
|out-shortcut
|Invoke-ShellCommand"),1,0) 
| eval base64 = if(match(lower(Message),"frombase64"), "4", 0) 
| eval empire=if(match(lower(Message),"system.net.webclient") AND match(lower(Message), "frombase64string") ,5,0) 
| eval mimikatz=if(match(lower(Message),"mimikatz") OR match(lower(Message), "-dumpcr") OR match(lower(Message), "SEKURLSA::Pth") OR match(lower(Message), "kerberos::ptt") OR match(lower(Message), "kerberos::golden") ,5,0) 
| eval iex = if(match(lower(Message),"iex"), "2", 0) 
| eval webclient=if(match(lower(Message),"http") OR match(lower(Message),"web(client
|request)") OR match(lower(Message),"socket") OR match(lower(Message),"download(file
|string)") OR match(lower(Message),"bitstransfer") OR match(lower(Message),"internetexplorer.application") OR match(lower(Message),"xmlhttp"),5,0) 
| eval get = if(match(lower(Message),"get-"), "1", 0) 
| eval rundll32 = if(match(lower(Message),"rundll32"), "4", 0) 
| eval suspkeywrd=if(match(Message, "(?i)(bitstransfer
|mimik
|metasp
|AssemblyBuilderAccess
|Reflection\.Assembly
|shellcode
|injection
|cnvert
|shell\.application
|start-process
|Rc4ByteStream
|System\.Security\.Cryptography
|lsass\.exe
|localadmin
|LastLoggedOn
|hijack
|BackupPrivilege
|ngrok
|comsvcs
|backdoor
|brute.?force
|Port.?Scan
|Exfiltration
|exploit
|DisableRealtimeMonitoring
|beacon)"),1,0) 
| eval syswow64 = if(match(lower(Message),"syswow64"), "3", 0) 
| eval httplocal = if(match(lower(Message),"http://127.0.0.1"), "4", 0) 
| eval reflection = if(match(lower(Message),"reflection"), "1", 0) 
| eval invokewmi=if(match(lower(Message), "(?i)(wmiobject
|WMIMethod
|RemoteWMI
|PowerShellWmi
|wmicommand)"),5,0) 
| eval downgrade=if(match(Message, "(?i)([-]ve*r*s*i*o*n*\s+2)") OR match(lower(Message),"powershell -version"),3,0) 
| eval compressed=if(match(Message, "(?i)GZipStream
|::Decompress
|IO.Compression
|write-zip
|(expand
|compress)-Archive"),5,0) 
| eval invokecmd = if(match(lower(Message),"invoke-command"), "4", 0) 
| addtotals fieldname=Score DoIt, enccom, suspcmdlet, suspkeywrd, compressed, downgrade, mimikatz, iex, empire, rundll32, webclient, syswow64, httplocal, reflection, invokewmi, invokecmd, base64, get 
| stats values(Score) by DoIt, enccom, compressed, downgrade, iex, mimikatz, rundll32, empire, webclient, syswow64, httplocal, reflection, invokewmi, invokecmd, base64, get, suspcmdlet, suspkeywrd 
| `powershell_4104_hunting_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

Note that `powershell_4104_hunting_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Message


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Known False Positives
Limited false positives. May filter as needed.

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ executing suspicious commands. |




#### Reference

* [https://github.com/inodee/threathunting-spl/blob/master/hunt-queries/powershell_qualifiers.md](https://github.com/inodee/threathunting-spl/blob/master/hunt-queries/powershell_qualifiers.md)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell)
* [https://github.com/marcurdy/dfir-toolset/blob/master/Powershell%20Blueteam.txt](https://github.com/marcurdy/dfir-toolset/blob/master/Powershell%20Blueteam.txt)
* [https://devblogs.microsoft.com/powershell/powershell-the-blue-team/](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)
* [https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
* [https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)
* [https://hurricanelabs.com/splunk-tutorials/how-to-use-powershell-transcription-logs-in-splunk/](https://hurricanelabs.com/splunk-tutorials/how-to-use-powershell-transcription-logs-in-splunk/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_4104_hunting.yml) \| *version*: **1**