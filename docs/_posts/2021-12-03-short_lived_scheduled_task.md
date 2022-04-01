---
title: "Short Lived Scheduled Task"
excerpt: "Scheduled Task
"
categories:
  - Endpoint
last_modified_at: 2021-12-03
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
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Windows Security EventCode 4698, `A scheduled task was created` and Windows Security EventCode 4699, `A scheduled task was deleted` to identify scheduled tasks created and deleted in less than 30 seconds. This behavior may represent a lateral movement attack abusing the Task Scheduler to obtain code execution. Red Teams and adversaries alike may abuse the Task Scheduler for lateral movement and remote code execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-12-03
- **Author**: Mauricio Velazco, Splunk
- **ID**: 6fa31414-546e-11ec-adfa-acde48001122


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
 `wineventlog_security` EventCode=4698 OR EventCode=4699 
| xmlkv Message 
| transaction Task_Name  startswith=(EventCode=4698) endswith=(EventCode=4699) 
| eval short_lived=case((duration<30),"TRUE") 
| search  short_lived = TRUE 
| table _time, ComputerName, Account_Name, Command, Task_Name, short_lived 
| `short_lived_scheduled_task_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **short_lived_scheduled_task_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* ComputerName
* Account_Name
* Task_Name
* Description
* Command


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4698 EventCode enabled. The Windows TA is also required.

#### Known False Positives
Although uncommon, legitimate applications may create and delete a Scheduled Task within 30 seconds. Filter as needed.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | A windows scheduled task was created and deleted in 30 seconds on $ComputerName$ |


#### Reference

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
* [https://docs.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler](https://docs.microsoft.com/en-us/windows/win32/taskschd/about-the-task-scheduler)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/short_lived_scheduled_task.yml) \| *version*: **1**