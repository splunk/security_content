---
title: "Exchange PowerShell Module Usage"
excerpt: "Command and Scripting Interpreter, PowerShell"
categories:
  - Endpoint
last_modified_at: 2021-08-27
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the usage of Exchange PowerShell modules that were recently used for a proof of concept related to ProxyShell. Currently, there is no active data shared or data we could re-produce relate to this part of the ProxyShell chain of exploits.  \
Inherently, the usage of the modules is not malicious, but reviewing parallel processes, and user, of the session will assist with determining the intent. \
Module - New-MailboxExportRequest will begin the process of exporting contents of a primary mailbox or archive to a .pst file. \
Module - New-managementroleassignment can assign a management role to a management role group, management role assignment policy, user, or universal security group (USG).

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-27
- **Author**: Michael Haag
- **ID**: 2d10095e-05ae-11ec-8fdf-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

#### Search

```
`powershell` EventCode=4104 Message IN ("*New-MailboxExportRequest*", "*New-ManagementRoleAssignment*") 
| stats count min(_time) as firstTime max(_time) as lastTime by Path Message OpCode ComputerName User EventCode
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `exchange_powershell_module_usage_filter`
```

#### Associated Analytic Story
* [ProxyShell](/stories/proxyshell)


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Required field
* _time
* Path
* Message
* OpCode
* ComputerName
* User
* EventCode


#### Kill Chain Phase
* Reconnaissance
* Exploitation


#### Known False Positives
Administrators or power users may use this PowerShell commandlet for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Local user discovery enumeration using PowerShell on $dest$ by $user$ |




#### Reference

* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps)
* [https://blog.orange.tw/2021/08/proxyshell-a-new-attack-surface-on-ms-exchange-part-3.html](https://blog.orange.tw/2021/08/proxyshell-a-new-attack-surface-on-ms-exchange-part-3.html)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/exchange_powershell_module_usage.yml) \| *version*: **1**