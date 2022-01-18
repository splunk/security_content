---
title: "Scheduled Task Deleted Or Created via CMD"
excerpt: "Scheduled Task, Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2020-12-17
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

This search looks for flags passed to schtasks.exe on the command-line that indicate a task was created via command like. This has been associated with the Dragonfly threat actor, and the SUNBURST attack against Solarwinds.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-12-17
- **Author**: Bhavin Patel, Splunk
- **ID**: d5af132c-7c17-439c-9d31-13d55340f36c


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process) as process values(Processes.parent_process) as parent_process min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe (Processes.process=*delete* OR Processes.process=*create*) by Processes.user Processes.process_name Processes.parent_process_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `scheduled_task_deleted_or_created_via_cmd_filter` 
```

#### Associated Analytic Story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [NOBELIUM Group](/stories/nobelium_group)


#### How To Implement
You must be ingesting endpoint data that tracks process activity, including parent-child relationships from your endpoints to populate the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model.

#### Required field
* _time
* Processes.process
* Processes.parent_process
* Processes.process_name
* Processes.user
* Processes.parent_process_name
* Processes.dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Tasks should not be manually created via CLI, this is rarely done by admins as well


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A schedule task process $process_name$ with create or delete commandline $process$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/scheduled_task_deleted_or_created_via_cmd.yml) \| *version*: **5**