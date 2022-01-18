---
title: "Suspicious Scheduled Task from Public Directory"
excerpt: "Scheduled Task, Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2021-03-01
toc: true
toc_label: ""
tags:
  - Scheduled Task
  - Execution
  - Persistence
  - Privilege Escalation
  - Scheduled Task/Job
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

The following detection identifies Scheduled Tasks registering (creating a new task) a binary or script to run from a public directory which includes users\public, \programdata\ and \windows\temp. Upon triage, review the binary or script in the command line for legitimacy, whether an approved binary/script or not. In addition, capture the binary or script in question and analyze for further behaviors. Identify the source and contain the endpoint.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-01
- **Author**: Michael Haag, Splunk
- **ID**: 7feb7972-7ac3-11eb-bac8-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe (Processes.process=*\\users\\public\\* OR Processes.process=*\\programdata\\* OR Processes.process=*windows\\temp*)  Processes.process=*/create* by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `suspicious_scheduled_task_from_public_directory_filter`
```

#### Associated Analytic Story
* [Ransomware](/stories/ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation
* Privilege Escalation


#### Known False Positives
Limited false positives may be present. Filter as needed by parent process or command line argument.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 70 | 50 | Suspicious scheduled task registered on $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtasks/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/schtasks/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_scheduled_task_from_public_directory.yml) \| *version*: **1**