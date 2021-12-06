---
title: "Scheduled Task Initiation on Remote Endpoint"
excerpt: "Scheduled Task/Job, Scheduled Task"
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
  - Scheduled Task
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

This analytic looks for the execution of `schtasks.exe` with command-line arguments utilized to start a Scheduled Task on a remote endpoint. Red Teams and adversaries alike may abuse the Task Scheduler for lateral movement and remote code execution.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-11
- **Author**: Mauricio Velazco, Splunk
- **ID**: 95cf4608-4302-11ec-8194-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=schtasks.exe OR Processes.original_file_name=schtasks.exe) (Processes.process=*/s* AND Processes.process=*/run*) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `scheduled_task_initiation_on_remote_endpoint_filter`
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
Administrators may start scheduled tasks on remote systems, but this activity is usually limited to a small set of hosts or users.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | A Windows Scheduled Task was ran on a remote endpoint from $dest |




#### Reference

* [https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/scheduled_task_initiation_on_remote_endpoint.yml) \| *version*: **1**