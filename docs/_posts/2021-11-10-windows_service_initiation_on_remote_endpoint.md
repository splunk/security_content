---
title: "Windows Service Initiation on Remote Endpoint"
excerpt: "Create or Modify System Process
, Windows Service
"
categories:
  - Endpoint
last_modified_at: 2021-11-10
toc: true
toc_label: ""
tags:
  - Create or Modify System Process
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `sc.exe` with command-line arguments utilized to start a Windows Service on a remote endpoint. Red Teams and adversaries alike may abuse the Service Control Manager for lateral movement and remote code execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-10
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3f519894-4276-11ec-ab02-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=sc.exe OR Processes.original_file_name=sc.exe) (Processes.process=*\\\\* AND Processes.process=*start*) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `windows_service_initiation_on_remote_endpoint_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `windows_service_initiation_on_remote_endpoint_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Administrators may start Windows Services on remote systems, but this activity is usually limited to a small set of hosts or users.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | A Windows Service was started on a remote endpoint from $dest |




#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/services/controlling-a-service-using-sc](https://docs.microsoft.com/en-us/windows/win32/services/controlling-a-service-using-sc)
* [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/lateral_movement/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_service_initiation_on_remote_endpoint.yml) \| *version*: **1**