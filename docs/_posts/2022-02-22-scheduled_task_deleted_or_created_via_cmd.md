---
title: "Scheduled Task Deleted Or Created via CMD"
excerpt: "Scheduled Task
, Scheduled Task/Job
"
categories:
  - Endpoint
last_modified_at: 2022-02-22
toc: true
toc_label: ""
tags:
  - Scheduled Task
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
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

The following analytic identifies the creation or deletion of a scheduled task using schtasks.exe with flags - create or delete being passed on the command-line. This has been associated with the Dragonfly threat actor, and the SUNBURST attack against Solarwinds. This analytic replaces "Scheduled Task used in BadRabbit Ransomware".

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-02-22
- **Author**: Bhavin Patel, Splunk
- **ID**: d5af132c-7c17-439c-9d31-13d55340f36c


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `scheduled_task_deleted_or_created_via_cmd_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process
* Processes.process_name
* Processes.user
* Processes.parent_process_name
* Processes.dest


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
It is possible scripts or administrators may trigger this analytic. Filter as needed based on parent process, application.

#### Associated Analytic story
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [NOBELIUM Group](/stories/nobelium_group)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A schedule task process $process_name$ with create or delete commandline $process$ in host $dest$ |




#### Reference

* [https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/](https://thedfirreport.com/2022/02/21/qbot-and-zerologon-lead-to-full-domain-compromise/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/scheduled_task_deleted_or_created_via_cmd.yml) \| *version*: **6**