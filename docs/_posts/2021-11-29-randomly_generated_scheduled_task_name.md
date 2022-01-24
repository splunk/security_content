---
title: "Randomly Generated Scheduled Task Name"
excerpt: "Scheduled Task/Job, Scheduled Task"
categories:
  - Endpoint
last_modified_at: 2021-11-29
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
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic leverages Event ID 4698, `A scheduled task was created`, to identify the creation of a Scheduled Task with a suspicious, high entropy, Task Name. To achieve this, this analytic also leverages the `ut_shannon` function from the URL ToolBox Splunk application. Red teams and adversaries alike may abuse the Task Scheduler to create and start a remote Scheduled Task and obtain remote code execution. To achieve this goal, tools like Impacket or Crapmapexec, typically create a Scheduled Task with a random task name on the victim host. This hunting analytic may help defenders identify Scheduled Tasks created as part of a lateral movement attack. The entropy threshold `ut_shannon &gt; 3` should be customized by users. The Command field can be used to determine if the task has malicious intent or not.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-11-29
- **Author**: Mauricio Velazco, Splunk
- **ID**: 9d22a780-5165-11ec-ad4f-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

#### Search

```
 `wineventlog_security` EventCode=4698 
| xmlkv Message 
| lookup ut_shannon_lookup word as Task_Name 
| where ut_shannon > 3 
| table  _time, dest, Task_Name, ut_shannon, Command, Author, Enabled, Hidden 
| `randomly_generated_scheduled_task_name_filter`
```

#### Associated Analytic Story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4698 EventCode enabled. The Windows TA as well as the URL ToolBox application are also required.

#### Required field
* _time
* dest
* Task_Name
* Description
* Command


#### Kill Chain Phase
* Privilege Escalation
* Lateral Movement
* Persistence


#### Known False Positives
Legitimate applications may use random Scheduled Task names.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A windows scheduled task with a suspicious task name was created on $dest$ |




#### Reference

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
* [https://splunkbase.splunk.com/app/2734/](https://splunkbase.splunk.com/app/2734/)
* [https://en.wikipedia.org/wiki/Entropy_(information_theory)](https://en.wikipedia.org/wiki/Entropy_(information_theory))



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/randomly_generated_scheduled_task_name.yml) \| *version*: **1**