---
title: "Exchange PowerShell Module Usage"
excerpt: "Command and Scripting Interpreter
, PowerShell
"
categories:
  - Endpoint
last_modified_at: 2021-08-27
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

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the usage of Exchange PowerShell modules that were recently used for a proof of concept related to ProxyShell. Currently, there is no active data shared or data we could re-produce relate to this part of the ProxyShell chain of exploits.  \
Inherently, the usage of the modules is not malicious, but reviewing parallel processes, and user, of the session will assist with determining the intent. \
Module - New-MailboxExportRequest will begin the process of exporting contents of a primary mailbox or archive to a .pst file. \
Module - New-managementroleassignment can assign a management role to a management role group, management role assignment policy, user, or universal security group (USG).

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-27
- **Author**: Michael Haag
- **ID**: 2d10095e-05ae-11ec-8fdf-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `exchange_powershell_module_usage_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Path
* Message
* OpCode
* ComputerName
* User
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Administrators or power users may use this PowerShell commandlet for troubleshooting.

#### Associated Analytic story
* [ProxyShell](/stories/proxyshell)


#### Kill Chain Phase
* Reconnaissance
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Local user discovery enumeration using PowerShell on $dest$ by $user$ |




#### Reference

* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-managementroleassignment?view=exchange-ps)
* [https://blog.orange.tw/2021/08/proxyshell-a-new-attack-surface-on-ms-exchange-part-3.html](https://blog.orange.tw/2021/08/proxyshell-a-new-attack-surface-on-ms-exchange-part-3.html)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/](https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/exchange_powershell_module_usage.yml) \| *version*: **1**