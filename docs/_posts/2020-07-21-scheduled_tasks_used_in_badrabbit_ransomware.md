---
title: "Scheduled tasks used in BadRabbit ransomware"
excerpt: "Scheduled Task
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Scheduled Task
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for flags passed to schtasks.exe on the command-line that indicate that task names related to the execution of Bad Rabbit ransomware were created or deleted. Deprecated because we already have a similar detection

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 1297fb80-f42a-4b4a-9c8b-78c066437cf6


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process  from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe (Processes.process= "*create*"  OR Processes.process= "*delete*") by Processes.parent_process Processes.process_name Processes.user 
| `drop_dm_object_name("Processes")` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| search (process=*rhaegal* OR process=*drogon* OR *viserion_*) 
| `scheduled_tasks_used_in_badrabbit_ransomware_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `scheduled_tasks_used_in_badrabbit_ransomware_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Processes node. You must also be ingesting logs with both the process name and command line from your endpoints. The command-line arguments are mapped to the "process" field in the Endpoint data model.

#### Known False Positives
No known false positives

#### Associated Analytic story
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/scheduled_tasks_used_in_badrabbit_ransomware.yml) \| *version*: **3**