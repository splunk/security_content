---
title: "Scheduled Task Creation on Remote Endpoint using At"
excerpt: "Scheduled Task/Job, At (Windows)"
categories:
  - Endpoint
last_modified_at: 2021-11-11
toc: true
toc_label: ""
tags:
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - At (Windows)
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `at.exe` with command-line arguments utilized to create a Scheduled Task on a remote endpoint. Red Teams and adversaries alike may abuse the Task Scheduler for lateral movement and remote code execution. The `at.exe` binary internally leverages the AT protocol which was deprecated starting with Windows 8 and Windows Server 2012 but may still work on previous versions of Windows. Furthermore, attackers may enable this protocol on demand by changing a sytem registry key.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-11
- **Author**: Mauricio Velazco, Splunk
- **ID**: 4be54858-432f-11ec-8209-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1053.002](https://attack.mitre.org/techniques/T1053/002/) | At (Windows) | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=at.exe OR Processes.original_file_name=at.exe) (Processes.process=*\\\\*) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `scheduled_task_creation_on_remote_endpoint_using_at_filter`
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
Administrators may create scheduled tasks on remote systems, but this activity is usually limited to a small set of hosts or users.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | A Windows Scheduled Task was created on a remote endpoint from $dest |




#### Reference

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/at](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/at)
* [https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-scheduledjob?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-scheduledjob?redirectedfrom=MSDN)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/lateral_movement/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.002/lateral_movement/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/scheduled_task_creation_on_remote_endpoint_using_at.yml) \| *version*: **1**