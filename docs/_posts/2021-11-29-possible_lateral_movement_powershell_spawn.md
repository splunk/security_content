---
title: "Possible Lateral Movement PowerShell Spawn"
excerpt: "Remote Services
, Distributed Component Object Model
, Windows Remote Management
, Windows Management Instrumentation
, Scheduled Task
, Windows Service
, PowerShell
"
categories:
  - Endpoint
last_modified_at: 2021-11-29
toc: true
toc_label: ""
tags:
  - Remote Services
  - Distributed Component Object Model
  - Windows Remote Management
  - Windows Management Instrumentation
  - Scheduled Task
  - Windows Service
  - PowerShell
  - Lateral Movement
  - Lateral Movement
  - Lateral Movement
  - Execution
  - Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic assists with identifying a PowerShell process spawned as a child or grand child process of commonly abused processes during lateral movement techniques including `services.exe`, `wmiprsve.exe`, `svchost.exe`, `wsmprovhost.exe` and `mmc.exe`. Legitimate Windows features such as the Service Control Manager, Windows Management Instrumentation, Task Scheduler, Windows Remote Management and the DCOM protocol can be abused to start a process on a remote endpoint. Looking for PowerShell spawned out of this processes may reveal a lateral movement attack. Red Teams and adversaries alike may abuse these services during a breach for lateral movement and remote code execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-29
- **Author**: Mauricio Velazco, Splunk
- **ID**: cb909b3e-512b-11ec-aa31-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Distributed Component Object Model | Lateral Movement |

| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | Lateral Movement |

| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=wmiprvse.exe OR Processes.parent_process_name=services.exe OR Processes.parent_process_name=svchost.exe OR Processes.parent_process_name=wsmprovhost.exe OR Processes.parent_process_name=mmc.exe) (Processes.process_name=powershell.exe OR (Processes.process_name=cmd.exe AND Processes.process=*powershell.exe*) OR Processes.process_name=pwsh.exe OR (Processes.process_name=cmd.exe AND Processes.process=*pwsh.exe*)) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `possible_lateral_movement_powershell_spawn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `possible_lateral_movement_powershell_spawn_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints.

#### Known False Positives
Legitimate applications may spawn PowerShell as a child process of the the identified processes. Filter as needed.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)
* [Malicious PowerShell](/stories/malicious_powershell)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A PowerShell process was spawned as a child process of typically abused processes on $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1021/003](https://attack.mitre.org/techniques/T1021/003)
* [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)
* [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)
* [https://attack.mitre.org/techniques/T1053.005/](https://attack.mitre.org/techniques/T1053.005/)
* [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_powershell/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement_powershell/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/possible_lateral_movement_powershell_spawn.yml) \| *version*: **1**