---
title: "PowerShell 4104 Hunting"
excerpt: "PowerShell"
categories:
  - Endpoint
last_modified_at: 2021-08-18
toc: true
tags:
  - Hunting
  - T1059.001
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

# PowerShell 4104 Hunting

The following Hunting analytic assists with identifying suspicious PowerShell execution using Script Block Logging, or EventCode 4104. This analytic is not meant to be ran hourly, but occasionally to identify malicious or suspicious PowerShell. This analytic is a combination of work completed by Alex Teixeira and Splunk Threat Research Team.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **ATT&CK**: [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- **Last Updated**: 2021-08-18
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059.001 | PowerShell | Execution |


#### Search

```
`powershell` EventCode=4104 
| eval DoIt = if(match(Message,&#34;(?i)(\$doit)&#34;), &#34;4&#34;, 0) 
| eval enccom=if(match(Message,&#34;[A-Za-z0-9+\/]{44,}([A-Za-z0-9+\/]{4}
|[A-Za-z0-9+\/]{3}=
|[A-Za-z0-9+\/]{2}==)&#34;) OR match(Message, &#34;(?i)[-]e(nc*o*d*e*d*c*o*m*m*a*n*d*)*\s+[^-]&#34;),4,0) 
| eval suspcmdlet=if(match(Message, &#34;(?i)Add-Exfiltration
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
|Invoke-ShellCommand&#34;),1,0) 
| eval base64 = if(match(lower(Message),&#34;frombase64&#34;), &#34;4&#34;, 0) 
| eval empire=if(match(lower(Message),&#34;system.net.webclient&#34;) AND match(lower(Message), &#34;frombase64string&#34;) ,5,0) 
| eval mimikatz=if(match(lower(Message),&#34;mimikatz&#34;) OR match(lower(Message), &#34;-dumpcr&#34;) OR match(lower(Message), &#34;SEKURLSA::Pth&#34;) OR match(lower(Message), &#34;kerberos::ptt&#34;) OR match(lower(Message), &#34;kerberos::golden&#34;) ,5,0) 
| eval iex = if(match(lower(Message),&#34;iex&#34;), &#34;2&#34;, 0) 
| eval webclient=if(match(lower(Message),&#34;http&#34;) OR match(lower(Message),&#34;web(client
|request)&#34;) OR match(lower(Message),&#34;socket&#34;) OR match(lower(Message),&#34;download(file
|string)&#34;) OR match(lower(Message),&#34;bitstransfer&#34;) OR match(lower(Message),&#34;internetexplorer.application&#34;) OR match(lower(Message),&#34;xmlhttp&#34;),5,0) 
| eval get = if(match(lower(Message),&#34;get-&#34;), &#34;1&#34;, 0) 
| eval rundll32 = if(match(lower(Message),&#34;rundll32&#34;), &#34;4&#34;, 0) 
| eval suspkeywrd=if(match(Message, &#34;(?i)(bitstransfer
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
|beacon)&#34;),1,0) 
| eval syswow64 = if(match(lower(Message),&#34;syswow64&#34;), &#34;3&#34;, 0) 
| eval httplocal = if(match(lower(Message),&#34;http://127.0.0.1&#34;), &#34;4&#34;, 0) 
| eval reflection = if(match(lower(Message),&#34;reflection&#34;), &#34;1&#34;, 0) 
| eval invokewmi=if(match(lower(Message), &#34;(?i)(wmiobject
|WMIMethod
|RemoteWMI
|PowerShellWmi
|wmicommand)&#34;),5,0) 
| eval downgrade=if(match(Message, &#34;(?i)([-]ve*r*s*i*o*n*\s+2)&#34;) OR match(lower(Message),&#34;powershell -version&#34;),3,0) 
| eval compressed=if(match(Message, &#34;(?i)GZipStream
|::Decompress
|IO.Compression
|write-zip
|(expand
|compress)-Archive&#34;),5,0) 
| eval invokecmd = if(match(lower(Message),&#34;invoke-command&#34;), &#34;4&#34;, 0) 
| addtotals fieldname=Score DoIt, enccom, suspcmdlet, suspkeywrd, compressed, downgrade, mimikatz, iex, empire, rundll32, webclient, syswow64, httplocal, reflection, invokewmi, invokecmd, base64, get 
| stats values(Score) by DoIt, enccom, compressed, downgrade, iex, mimikatz, rundll32, empire, webclient, syswow64, httplocal, reflection, invokewmi, invokecmd, base64, get, suspcmdlet, suspkeywrd 
| `powershell_4104_hunting_filter`
```

#### Associated Analytic Story

* [Malicious PowerShell](_stories/malicious_powershell)


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Required field

* _time

* Message


#### Kill Chain Phase

* Exploitation


#### Known False Positives
Limited false positives. May filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



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



_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:22.143243 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```