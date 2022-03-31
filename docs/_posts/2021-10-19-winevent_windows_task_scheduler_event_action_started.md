---
title: "WinEvent Windows Task Scheduler Event Action Started"
excerpt: "Scheduled Task
"
categories:
  - Endpoint
last_modified_at: 2021-10-19
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

The following hunting analytic assists with identifying suspicious tasks that have been registered and ran in Windows using EventID 200 (action run) and 201 (action completed). It is recommended to filter based on ActionName by specifying specific paths not used in your environment. After some basic tuning, this may be effective in capturing evasive ways to register tasks on Windows. Review parallel events related to tasks being scheduled. EventID 106 will generate when a new task is generated, however, that does not mean it ran. Capture any files on disk and analyze.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-19
- **Author**: Michael Haag, Splunk
- **ID**: b3632472-310b-11ec-9aab-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`wineventlog_task_scheduler` EventCode IN ("200","201") 
| rename ComputerName as dest 
| stats count min(_time) as firstTime max(_time) as lastTime by Message dest EventCode category 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `winevent_windows_task_scheduler_event_action_started_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_task_scheduler](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_task_scheduler.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **winevent_windows_task_scheduler_event_action_started_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* TaskName
* ActionName
* EventID
* dest
* ProcessID


#### How To Implement
Task Scheduler logs are required to be collected. Enable logging with inputs.conf by adding a stanza for [WinEventLog://Microsoft-Windows-TaskScheduler/Operational] and renderXml=false. Note, not translating it in XML may require a proper extraction of specific items in the Message.

#### Known False Positives
False positives will be present. Filter based on ActionName paths or specify keywords of interest.

#### Associated Analytic story
* [IcedID](/stories/icedid)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | A Scheduled Task was scheduled and ran on $dest$. |


#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md)
* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/windows_taskschedule/windows-taskschedule.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/windows_taskschedule/windows-taskschedule.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/winevent_windows_task_scheduler_event_action_started.yml) \| *version*: **1**