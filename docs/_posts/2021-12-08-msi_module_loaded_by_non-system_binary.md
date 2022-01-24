---
title: "MSI Module Loaded by Non-System Binary"
excerpt: "DLL Side-Loading, Hijack Execution Flow"
categories:
  - Endpoint
last_modified_at: 2021-12-08
toc: true
toc_label: ""
tags:
  - DLL Side-Loading
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Hijack Execution Flow
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic identifies `msi.dll` being loaded by a binary not located in `system32`, `syswow64`, `winsxs` or `windows` paths. This behavior is most recently related to InstallerFileTakeOver, or CVE-2021-41379, and DLL side-loading. CVE-2021-41379 requires a binary to be dropped and `msi.dll` to be loaded by it. To Successful exploitation of this issue happens in four parts \
1. Generation of an MSI that will trigger bad behavior. \
1. Preparing a directory for MSI installation. \
1. Inducing an error state. \
1. Racing to introduce a junction and a symlink to trick msiexec.exe to modify the attacker specified file. \
In addition, `msi.dll` has been abused in DLL side-loading attacks by being loaded by non-system binaries.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-12-08
- **Author**: Michael Haag, Splunk
- **ID**: ccb98a66-5851-11ec-b91c-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | DLL Side-Loading | Persistence, Privilege Escalation, Defense Evasion |

| [T1574](https://attack.mitre.org/techniques/T1574/) | Hijack Execution Flow | Persistence, Privilege Escalation, Defense Evasion |

#### Search

```
`sysmon` EventCode=7 ImageLoaded="*\\msi.dll" NOT (Image IN ("*\\System32\\*","*\\syswow64\\*","*\\windows\\*", "*\\winsxs\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded process_name Computer EventCode ProcessId 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `msi_module_loaded_by_non_system_binary_filter`
```

#### Associated Analytic Story
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Image
* ImageLoaded
* process_name
* Computer
* EventCode
* ProcessId


#### Kill Chain Phase
* Exploitation


#### Known False Positives
It is possible some Administrative utilities will load msi.dll outside of normal system paths, filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | The following module $ImageLoaded$ was loaded by $Image$ outside of the normal system paths on endpoint $Computer$, potentally related to DLL side-loading. |




#### Reference

* [https://attackerkb.com/topics/7LstI2clmF/cve-2021-41379/rapid7-analysis](https://attackerkb.com/topics/7LstI2clmF/cve-2021-41379/rapid7-analysis)
* [https://github.com/klinix5/InstallerFileTakeOver](https://github.com/klinix5/InstallerFileTakeOver)
* [https://github.com/mandiant/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/msi.dll%20Hijack%20(Methodology).ioc](https://github.com/mandiant/red_team_tool_countermeasures/blob/master/rules/PGF/supplemental/hxioc/msi.dll%20Hijack%20(Methodology).ioc)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/msi_module_loaded_by_non-system_binary.yml) \| *version*: **1**