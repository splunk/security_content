---
title: "Remote Process Instantiation via WinRM and PowerShell"
excerpt: "Remote Services, Windows Remote Management"
categories:
  - Endpoint
last_modified_at: 2021-11-16
toc: true
toc_label: ""
tags:
  - Remote Services
  - Lateral Movement
  - Windows Remote Management
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `powershell.exe` with arguments utilized to start a process on a remote endpoint by abusing the WinRM protocol. Specifically, this search looks for the abuse of the `Invoke-Command` commandlet. Red Teams and adversaries alike may abuse WinRM and `powershell.exe` for lateral movement and remote code execution.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-16
- **Author**: Mauricio Velazco, Splunk
- **ID**: ba24cda8-4716-11ec-8009-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_powershell` (Processes.process="*Invoke-Command*" AND Processes.process="*-ComputerName*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `remote_process_instantiation_via_winrm_and_powershell_filter`
```

#### Associated Analytic Story
* [Lateral Movement](/stories/lateral_movement)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints.

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


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Administrators may leverage WinRM and `Invoke-Command` to start a process on remote systems for system administration or automation use cases. However, this activity is usually limited to a small set of hosts or users.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A process was started on a remote endpoint from $dest by abusing WinRM using PowerShell.exe |




#### Reference

* [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)
* [https://pentestlab.blog/2018/05/15/lateral-movement-winrm/](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remote_process_instantiation_via_winrm_and_powershell.yml) \| *version*: **1**