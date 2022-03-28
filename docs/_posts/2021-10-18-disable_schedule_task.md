---
title: "Disable Schedule Task"
excerpt: "Disable or Modify Tools
, Impair Defenses
"
categories:
  - Endpoint
last_modified_at: 2021-10-18
toc: true
toc_label: ""
tags:
  - Disable or Modify Tools
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious commandline to disable existing schedule task. This technique is used by adversaries or commodity malware like IceID to disable security application (AV products) in the targetted host to evade detections. This TTP is a good pivot to check further why and what other process run before and after this detection. check which process execute the commandline and what task is disabled. parent child process is quite valuable in this scenario too.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-18
- **Author**: Teoderick Contreras, Splunk
- **ID**: db596056-3019-11ec-a9ff-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Disable or Modify Tools | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process=*/change*  Processes.process=*/disable* by Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.dest 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `disable_schedule_task_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `disable_schedule_task_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.user
* Processes.process_name
* Processes.parent_process_name
* Processes.dest


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
admin may disable problematic schedule task

#### Associated Analytic story
* [IcedID](/stories/icedid)
* [Living Off The Land](/stories/living_off_the_land)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | schtask process with commandline $process$ to disable schedule task in $dest$ |




#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_schtask/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_schtask/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_schedule_task.yml) \| *version*: **1**